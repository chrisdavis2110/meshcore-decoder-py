"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Main packet decoder - orchestrates all payload decoders
"""

from typing import Optional, Dict, Any, List, Tuple
from ..types.packet import DecodedPacket, PacketStructure, PacketSegment, PayloadSegment, HeaderBreakdown
from ..types.enums import RouteType, PayloadType, PayloadVersion
from ..utils.hex import hex_to_bytes, byte_to_hex, bytes_to_hex, number_to_hex
from ..utils.enum_names import get_route_type_name, get_payload_type_name
from ..types.crypto import DecryptionOptions, ValidationResult, CryptoKeyStore
from ..crypto.key_manager import MeshCoreKeyStore

from .payload_decoders.ack import AckPayloadDecoder
from .payload_decoders.trace import TracePayloadDecoder
from .payload_decoders.path import PathPayloadDecoder
from .payload_decoders.advert import AdvertPayloadDecoder
from .payload_decoders.group_text import GroupTextPayloadDecoder
from .payload_decoders.request import RequestPayloadDecoder
from .payload_decoders.response import ResponsePayloadDecoder
from .payload_decoders.anon_request import AnonRequestPayloadDecoder
from .payload_decoders.text_message import TextMessagePayloadDecoder


class MeshCorePacketDecoder:
    """Main packet decoder for MeshCore packets"""

    @staticmethod
    def decode(hex_data: str, options: Optional[DecryptionOptions] = None) -> DecodedPacket:
        """Decode a raw packet from hex string"""
        result = MeshCorePacketDecoder._parse_internal(hex_data, False, options)
        return result['packet']

    @staticmethod
    async def decode_with_verification(hex_data: str, options: Optional[DecryptionOptions] = None) -> DecodedPacket:
        """Decode a raw packet from hex string with signature verification for advertisements"""
        result = await MeshCorePacketDecoder._parse_internal_async(hex_data, False, options)
        return result['packet']

    @staticmethod
    def analyze_structure(hex_data: str, options: Optional[DecryptionOptions] = None) -> PacketStructure:
        """Analyze packet structure for detailed breakdown"""
        result = MeshCorePacketDecoder._parse_internal(hex_data, True, options)
        return result['structure']

    @staticmethod
    async def analyze_structure_with_verification(hex_data: str, options: Optional[DecryptionOptions] = None) -> PacketStructure:
        """Analyze packet structure with signature verification for advertisements"""
        result = await MeshCorePacketDecoder._parse_internal_async(hex_data, True, options)
        return result['structure']

    @staticmethod
    def _parse_internal(hex_data: str, include_structure: bool, options: Optional[DecryptionOptions]) -> Dict[str, Any]:
        """Internal unified parsing method"""
        bytes_data = hex_to_bytes(hex_data)
        segments: List[PacketSegment] = []

        if len(bytes_data) < 2:
            error_packet = DecodedPacket(
                message_hash='',
                route_type=RouteType.Flood,
                payload_type=PayloadType.RawCustom,
                payload_version=PayloadVersion.Version1,
                path_length=0,
                path=None,
                payload={'raw': '', 'decoded': None},
                total_bytes=len(bytes_data),
                is_valid=False,
                errors=['Packet too short (minimum 2 bytes required)']
            )

            error_structure = PacketStructure(
                segments=[],
                total_bytes=len(bytes_data),
                raw_hex=hex_data.upper(),
                message_hash='',
                payload={
                    'segments': [],
                    'hex': '',
                    'start_byte': 0,
                    'type': 'Unknown'
                }
            )

            return {'packet': error_packet, 'structure': error_structure}

        try:
            offset = 0

            # Parse header
            header = bytes_data[0]
            route_type = RouteType(header & 0x03)
            payload_type = PayloadType((header >> 2) & 0x0F)
            payload_version = PayloadVersion((header >> 6) & 0x03)

            if include_structure:
                segments.append(PacketSegment(
                    name='Header',
                    description='Header byte breakdown',
                    start_byte=0,
                    end_byte=0,
                    value=f'0x{header:02x}',
                    header_breakdown={
                        'full_binary': f'{header:08b}',
                        'fields': [
                            {
                                'bits': '0-1',
                                'field': 'Route Type',
                                'value': get_route_type_name(route_type),
                                'binary': f'{header & 0x03:02b}'
                            },
                            {
                                'bits': '2-5',
                                'field': 'Payload Type',
                                'value': get_payload_type_name(payload_type),
                                'binary': f'{(header >> 2) & 0x0F:04b}'
                            },
                            {
                                'bits': '6-7',
                                'field': 'Version',
                                'value': str(payload_version.value),
                                'binary': f'{(header >> 6) & 0x03:02b}'
                            }
                        ]
                    }
                ))
            offset = 1

            # Handle transport codes
            transport_codes: Optional[Tuple[int, int]] = None
            if route_type in (RouteType.TransportFlood, RouteType.TransportDirect):
                if len(bytes_data) < offset + 4:
                    raise ValueError('Packet too short for transport codes')
                code1 = bytes_data[offset] | (bytes_data[offset + 1] << 8)
                code2 = bytes_data[offset + 2] | (bytes_data[offset + 3] << 8)
                transport_codes = (code1, code2)

                if include_structure:
                    transport_code = (bytes_data[offset] |
                                       (bytes_data[offset + 1] << 8) |
                                       (bytes_data[offset + 2] << 16) |
                                       (bytes_data[offset + 3] << 24))
                    segments.append(PacketSegment(
                        name='Transport Code',
                        description='Used for Direct/Response routing',
                        start_byte=offset,
                        end_byte=offset + 3,
                        value=f'0x{transport_code:08x}'
                    ))
                offset += 4

            # Parse path
            if len(bytes_data) < offset + 1:
                raise ValueError('Packet too short for path length')
            path_length = bytes_data[offset]

            if include_structure:
                if route_type in (RouteType.Direct, RouteType.TransportDirect):
                    path_length_description = f'For "Direct" packets, this contains routing instructions. {path_length} bytes of routing instructions (decreases as packet travels)'
                elif route_type in (RouteType.Flood, RouteType.TransportFlood):
                    path_length_description = f'{path_length} bytes showing route taken (increases as packet floods)'
                else:
                    path_length_description = f'Path contains {path_length} bytes'

                segments.append(PacketSegment(
                    name='Path Length',
                    description=path_length_description,
                    start_byte=offset,
                    end_byte=offset,
                    value=f'0x{path_length:02x}'
                ))
            offset += 1

            if len(bytes_data) < offset + path_length:
                raise ValueError('Packet too short for path data')

            # Convert path data to hex strings
            path_bytes = bytes_data[offset:offset + path_length]
            path: Optional[List[str]] = [byte_to_hex(b) for b in path_bytes] if path_length > 0 else None

            if include_structure and path_length > 0:
                if payload_type == PayloadType.Trace:
                    # TRACE packets have SNR values in path
                    snr_values = []
                    for i in range(path_length):
                        snr_raw = bytes_data[offset + i]
                        snr_signed = snr_raw - 256 if snr_raw > 127 else snr_raw
                        snr_db = snr_signed / 4.0
                        snr_values.append(f'{snr_db:.2f}dB (0x{snr_raw:02x})')
                    segments.append(PacketSegment(
                        name='Path SNR Data',
                        description=f'SNR values collected during trace: {", ".join(snr_values)}',
                        start_byte=offset,
                        end_byte=offset + path_length - 1,
                        value=bytes_to_hex(bytes_data[offset:offset + path_length])
                    ))
                else:
                    if route_type in (RouteType.Direct, RouteType.TransportDirect):
                        path_description = 'Routing instructions (bytes are stripped at each hop as packet travels to destination)'
                    elif route_type in (RouteType.Flood, RouteType.TransportFlood):
                        path_description = 'Historical route taken (bytes are added as packet floods through network)'
                    else:
                        path_description = 'Routing path information'

                    segments.append(PacketSegment(
                        name='Path Data',
                        description=path_description,
                        start_byte=offset,
                        end_byte=offset + path_length - 1,
                        value=bytes_to_hex(bytes_data[offset:offset + path_length])
                    ))
            offset += path_length

            # Extract payload
            payload_bytes = bytes_data[offset:]
            payload_hex = bytes_to_hex(payload_bytes)

            if include_structure and len(bytes_data) > offset:
                segments.append(PacketSegment(
                    name='Payload',
                    description=f'{get_payload_type_name(payload_type)} payload data',
                    start_byte=offset,
                    end_byte=len(bytes_data) - 1,
                    value=bytes_to_hex(bytes_data[offset:])
                ))

            # Decode payload based on type
            decoded_payload = None
            payload_segments: List[PayloadSegment] = []

            if payload_type == PayloadType.Advert:
                result = AdvertPayloadDecoder.decode(payload_bytes, {'include_segments': include_structure, 'segment_offset': 0})
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.Trace:
                result = TracePayloadDecoder.decode(payload_bytes, path, {'include_segments': include_structure, 'segment_offset': 0})
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.GroupText:
                decoder_options = options.__dict__ if options else {}
                decoder_options['include_segments'] = include_structure
                decoder_options['segment_offset'] = 0
                result = GroupTextPayloadDecoder.decode(payload_bytes, options)
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.Request:
                result = RequestPayloadDecoder.decode(payload_bytes, {'include_segments': include_structure, 'segment_offset': 0})
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.Response:
                # Pass DecryptionOptions if available, similar to GroupText
                decoder_options = options if options else DecryptionOptions()
                # Add segment info to options object
                decoder_options.include_segments = include_structure
                decoder_options.segment_offset = 0
                result = ResponsePayloadDecoder.decode(payload_bytes, decoder_options)
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.AnonRequest:
                result = AnonRequestPayloadDecoder.decode(payload_bytes, {'include_segments': include_structure, 'segment_offset': 0})
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.Ack:
                result = AckPayloadDecoder.decode(payload_bytes, {'include_segments': include_structure, 'segment_offset': 0})
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.Path:
                decoded_payload = PathPayloadDecoder.decode(payload_bytes)
            elif payload_type == PayloadType.TextMessage:
                # Pass DecryptionOptions if available, similar to Response
                decoder_options = options if options else DecryptionOptions()
                decoded_payload = TextMessagePayloadDecoder.decode(payload_bytes, decoder_options)

            # If no segments were generated and we need structure, show basic payload info
            if include_structure and len(payload_segments) == 0 and len(bytes_data) > offset:
                payload_segments.append(PayloadSegment(
                    name=f'{get_payload_type_name(payload_type)} Payload',
                    description=f'Raw {get_payload_type_name(payload_type)} payload data ({len(payload_bytes)} bytes)',
                    start_byte=0,
                    end_byte=len(payload_bytes) - 1,
                    value=bytes_to_hex(payload_bytes)
                ))

            # Calculate message hash
            message_hash = MeshCorePacketDecoder._calculate_message_hash(bytes_data, route_type, payload_type, payload_version)

            packet = DecodedPacket(
                message_hash=message_hash,
                route_type=route_type,
                payload_type=payload_type,
                payload_version=payload_version,
                transport_codes=transport_codes,
                path_length=path_length,
                path=path,
                payload={'raw': payload_hex, 'decoded': decoded_payload},
                total_bytes=len(bytes_data),
                is_valid=True
            )

            structure = PacketStructure(
                segments=segments,
                total_bytes=len(bytes_data),
                raw_hex=hex_data.upper(),
                message_hash=message_hash,
                payload={
                    'segments': payload_segments,
                    'hex': payload_hex,
                    'start_byte': offset,
                    'type': get_payload_type_name(payload_type)
                }
            )

            return {'packet': packet, 'structure': structure}

        except Exception as error:
            error_packet = DecodedPacket(
                message_hash='',
                route_type=RouteType.Flood,
                payload_type=PayloadType.RawCustom,
                payload_version=PayloadVersion.Version1,
                path_length=0,
                path=None,
                payload={'raw': '', 'decoded': None},
                total_bytes=len(bytes_data),
                is_valid=False,
                errors=[str(error)]
            )

            error_structure = PacketStructure(
                segments=[],
                total_bytes=len(bytes_data),
                raw_hex=hex_data.upper(),
                message_hash='',
                payload={
                    'segments': [],
                    'hex': '',
                    'start_byte': 0,
                    'type': 'Unknown'
                }
            )

            return {'packet': error_packet, 'structure': error_structure}

    @staticmethod
    async def _parse_internal_async(hex_data: str, include_structure: bool, options: Optional[DecryptionOptions]) -> Dict[str, Any]:
        """Internal unified parsing method with signature verification for advertisements"""
        # First do the regular parsing
        result = MeshCorePacketDecoder._parse_internal(hex_data, include_structure, options)

        # If it's an advertisement, verify the signature
        if result['packet'].payload_type == PayloadType.Advert and result['packet'].payload['decoded']:
            try:
                advert_payload = result['packet'].payload['decoded']
                bytes_data = hex_to_bytes(hex_data)

                # Calculate payload start offset
                offset = 1  # Skip header

                # Skip transport codes if present
                route_type = result['packet'].route_type
                if route_type in (RouteType.TransportFlood, RouteType.TransportDirect):
                    offset += 4

                # Skip path data
                if len(bytes_data) > offset:
                    path_length = bytes_data[offset]
                    offset += 1 + path_length

                # Get the payload bytes
                payload_bytes = bytes_data[offset:]

                # Decode with verification
                verified_advert = await AdvertPayloadDecoder.decode_with_verification(
                    payload_bytes,
                    {'include_segments': include_structure, 'segment_offset': 0}
                )

                if verified_advert:
                    # Update the payload with verification results
                    result['packet'].payload['decoded'] = verified_advert

                    # If the advertisement signature is invalid, mark the whole packet as invalid
                    if not verified_advert.is_valid:
                        result['packet'].is_valid = False
                        result['packet'].errors = verified_advert.errors or ['Invalid advertisement signature']

                    # Update structure segments if needed
                    if include_structure and hasattr(verified_advert, 'segments') and verified_advert.segments:
                        result['structure'].payload['segments'] = verified_advert.segments
            except Exception as error:
                print(f'Signature verification failed: {error}')

        return result

    @staticmethod
    def validate(hex_data: str) -> ValidationResult:
        """Validate packet format without full decoding"""
        bytes_data = hex_to_bytes(hex_data)
        errors: List[str] = []

        if len(bytes_data) < 2:
            errors.append('Packet too short (minimum 2 bytes required)')
            return ValidationResult(is_valid=False, errors=errors)

        try:
            offset = 1  # Skip header

            # Check transport codes
            header = bytes_data[0]
            route_type = RouteType(header & 0x03)
            if route_type in (RouteType.TransportFlood, RouteType.TransportDirect):
                if len(bytes_data) < offset + 4:
                    errors.append('Packet too short for transport codes')
                offset += 4

            # Check path length
            if len(bytes_data) < offset + 1:
                errors.append('Packet too short for path length')
            else:
                path_length = bytes_data[offset]
                offset += 1

                if len(bytes_data) < offset + path_length:
                    errors.append('Packet too short for path data')
                offset += path_length

            # Check if we have payload data
            if offset >= len(bytes_data):
                errors.append('No payload data found')

        except Exception as error:
            errors.append(str(error))

        return ValidationResult(is_valid=len(errors) == 0, errors=errors if errors else None)

    @staticmethod
    def _calculate_message_hash(bytes_data: bytes, route_type: RouteType, payload_type: PayloadType, payload_version: PayloadVersion) -> str:
        """Calculate message hash for a packet"""
        # For TRACE packets, use the trace tag as hash
        if payload_type == PayloadType.Trace and len(bytes_data) >= 13:
            offset = 1

            # Skip transport codes if present
            if route_type in (RouteType.TransportFlood, RouteType.TransportDirect):
                offset += 4

            # Skip path data
            if len(bytes_data) > offset:
                path_len = bytes_data[offset]
                offset += 1 + path_len

            # Extract trace tag
            if len(bytes_data) >= offset + 4:
                trace_tag = (bytes_data[offset] |
                           (bytes_data[offset + 1] << 8) |
                           (bytes_data[offset + 2] << 16) |
                           (bytes_data[offset + 3] << 24))
                return number_to_hex(trace_tag, 8)

        # For other packets, create hash from constant parts
        constant_header = (payload_type.value << 2) | (payload_version.value << 6)
        offset = 1

        # Skip transport codes if present
        if route_type in (RouteType.TransportFlood, RouteType.TransportDirect):
            offset += 4

        # Skip path data
        if len(bytes_data) > offset:
            path_len = bytes_data[offset]
            offset += 1 + path_len

        payload_data = bytes_data[offset:]
        hash_input = [constant_header] + list(payload_data)

        # Generate hash
        hash_value = 0
        for byte in hash_input:
            hash_value = ((hash_value << 5) - hash_value + byte) & 0xffffffff

        return number_to_hex(hash_value, 8)

    @staticmethod
    def create_key_store(initial_keys: Optional[Dict[str, Any]] = None) -> CryptoKeyStore:
        """Create a key store for decryption"""
        return MeshCoreKeyStore(initial_keys)

    @staticmethod
    def decode_to_json(hex_data: str, options: Optional[DecryptionOptions] = None) -> str:
        """
        Decode packet and return as JSON string

        Returns:
            JSON string representation of the decoded packet
        """
        import json
        packet = MeshCorePacketDecoder.decode(hex_data, options)
        return json.dumps(packet.to_dict(), indent=2)
