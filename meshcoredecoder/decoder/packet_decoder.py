"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Main packet decoder - orchestrates all payload decoders.
Packet layout: docs/packet_format.md. Payload formats: docs/payloads.md.
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
from .payload_decoders.group_data import GroupDataPayloadDecoder
from .payload_decoders.request import RequestPayloadDecoder
from .payload_decoders.response import ResponsePayloadDecoder
from .payload_decoders.anon_request import AnonRequestPayloadDecoder
from .payload_decoders.text_message import TextMessagePayloadDecoder
from .payload_decoders.control import ControlPayloadDecoder


class MeshCorePacketDecoder:
    """Main packet decoder for MeshCore packets"""

    @staticmethod
    def decode(hex_data: str, options: Optional[DecryptionOptions] = None) -> DecodedPacket:
        """Decode a raw packet from hex string"""
        result = MeshCorePacketDecoder._parse_internal(hex_data, False, options)
        return result['packet']

    @staticmethod
    def decode_with_verification(hex_data: str, options: Optional[DecryptionOptions] = None) -> DecodedPacket:
        """Decode a raw packet from hex string with signature verification for advertisements"""
        result = MeshCorePacketDecoder._parse_internal_with_verification(hex_data, False, options)
        return result['packet']

    @staticmethod
    def analyze_structure(hex_data: str, options: Optional[DecryptionOptions] = None) -> PacketStructure:
        """Analyze packet structure for detailed breakdown"""
        result = MeshCorePacketDecoder._parse_internal(hex_data, True, options)
        return result['structure']

    @staticmethod
    def analyze_structure_with_verification(hex_data: str, options: Optional[DecryptionOptions] = None) -> PacketStructure:
        """Analyze packet structure with signature verification for advertisements"""
        result = MeshCorePacketDecoder._parse_internal_with_verification(hex_data, True, options)
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
                    transport_code_1 = bytes_data[offset] | (bytes_data[offset + 1] << 8)
                    transport_code_2 = bytes_data[offset + 2] | (bytes_data[offset + 3] << 8)
                    segments.append(PacketSegment(
                        name='Transport Codes',
                        description='2× uint16: transport_code_1 (region scope), transport_code_2 (reserved). See packet_format.md.',
                        start_byte=offset,
                        end_byte=offset + 3,
                        value=f'0x{transport_code_1:04x} 0x{transport_code_2:04x}'
                    ))
                offset += 4

            # Parse path (multi-byte path encoding per meshcore-decoder PR #8 / Packet.h)
            # Bits 7:6 = hash size selector: (path_len_byte >> 6) + 1 = 1, 2, or 3 bytes per hop
            # Bits 5:0 = hop count (0-63). path_byte_length = hop_count * hash_size
            if len(bytes_data) < offset + 1:
                raise ValueError('Packet too short for path length')
            path_length_byte = bytes_data[offset]
            path_hash_size, path_hop_count, path_byte_length = MeshCorePacketDecoder._decode_path_len_byte(path_length_byte)

            payload_start = offset + 1
            remaining_after_path = len(bytes_data) - payload_start

            # Use legacy (raw path byte count) only when:
            # - Reserved hash size (bits 7:6 = 11), or
            # - Path would extend past packet (path_byte_length > remaining_after_path).
            # Do NOT use min_payload to trigger legacy; valid new-encoding packets can have small payloads.
            use_legacy = False
            if path_hash_size == 4:
                use_legacy = True
            elif path_byte_length > remaining_after_path:
                use_legacy = True

            if use_legacy:
                # Legacy: path_length byte = raw path byte count (1 byte per hop). Cap at packet and MAX_PATH_SIZE (64).
                path_byte_length = min(path_length_byte, remaining_after_path, 64)
                path_hop_count = path_byte_length
                path_hash_size = 1

            if include_structure:
                hash_desc = f' × {path_hash_size}-byte hashes' if path_hash_size > 1 else ''
                if path_hop_count == 0:
                    path_length_description = f'No path data{hash_desc}' if path_hash_size > 1 else 'No path data'
                elif route_type in (RouteType.Direct, RouteType.TransportDirect):
                    path_length_description = f'{path_hop_count} hop(s){hash_desc} of routing instructions (decreases as packet travels)'
                elif route_type in (RouteType.Flood, RouteType.TransportFlood):
                    path_length_description = f'{path_hop_count} hop(s){hash_desc} showing route taken (increases as packet floods)'
                else:
                    path_length_description = f'Path: {path_hop_count} hop(s){hash_desc}'

                segments.append(PacketSegment(
                    name='Path Length',
                    description=path_length_description,
                    start_byte=offset,
                    end_byte=offset,
                    value=f'0x{path_length_byte:02x}'
                ))
            offset += 1

            if len(bytes_data) < offset + path_byte_length:
                raise ValueError('Packet too short for path data')

            # Convert path data to list of hex strings (one per hop, hash_size bytes each)
            path: Optional[List[str]] = None
            if path_hop_count > 0 and path_byte_length > 0:
                path = []
                for i in range(path_hop_count):
                    hop_start = offset + i * path_hash_size
                    hop_bytes = bytes_data[hop_start:hop_start + path_hash_size]
                    path.append(bytes_to_hex(hop_bytes))

            if include_structure and path_byte_length > 0:
                if payload_type == PayloadType.Trace:
                    # TRACE packets: path holds SNR values (single-byte entries)
                    snr_values = []
                    for i in range(path_byte_length):
                        snr_raw = bytes_data[offset + i]
                        snr_signed = snr_raw - 256 if snr_raw > 127 else snr_raw
                        snr_db = snr_signed / 4.0
                        snr_values.append(f'{snr_db:.2f}dB (0x{snr_raw:02x})')
                    segments.append(PacketSegment(
                        name='Path SNR Data',
                        description=f'SNR values collected during trace: {", ".join(snr_values)}',
                        start_byte=offset,
                        end_byte=offset + path_byte_length - 1,
                        value=bytes_to_hex(bytes_data[offset:offset + path_byte_length])
                    ))
                else:
                    path_description = f'Routing path ({path_hash_size}-byte hash per hop)' if path_hash_size > 1 else 'Routing path information'
                    if route_type in (RouteType.Direct, RouteType.TransportDirect):
                        path_description = f'Routing instructions ({path_hash_size}-byte hashes stripped at each hop)'
                    elif route_type in (RouteType.Flood, RouteType.TransportFlood):
                        path_description = f'Historical route taken ({path_hash_size}-byte hashes per hop)'

                    segments.append(PacketSegment(
                        name='Path Data',
                        description=path_description,
                        start_byte=offset,
                        end_byte=offset + path_byte_length - 1,
                        value=bytes_to_hex(bytes_data[offset:offset + path_byte_length])
                    ))
            offset += path_byte_length

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
            elif payload_type == PayloadType.GroupData:
                decoder_options = options.__dict__ if options else {}
                decoder_options['include_segments'] = include_structure
                decoder_options['segment_offset'] = 0
                result = GroupDataPayloadDecoder.decode(payload_bytes, options)
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.Request:
                decoder_options = options.__dict__ if options else {}
                decoder_options['include_segments'] = include_structure
                decoder_options['segment_offset'] = 0
                result = RequestPayloadDecoder.decode(payload_bytes, options if options else decoder_options)
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.Response:
                decoder_options = options.__dict__ if options else {}
                decoder_options['include_segments'] = include_structure
                decoder_options['segment_offset'] = 0
                result = ResponsePayloadDecoder.decode(payload_bytes, options if options else decoder_options)
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.AnonRequest:
                decoder_options = options.__dict__ if options else {}
                decoder_options['include_segments'] = include_structure
                decoder_options['segment_offset'] = 0
                result = AnonRequestPayloadDecoder.decode(payload_bytes, options if options else decoder_options)
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.Ack:
                result = AckPayloadDecoder.decode(payload_bytes, {'include_segments': include_structure, 'segment_offset': 0})
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type == PayloadType.Path:
                decoder_options = options.__dict__ if options else {}
                decoder_options['include_segments'] = include_structure
                decoder_options['segment_offset'] = 0
                decoded_payload = PathPayloadDecoder.decode(payload_bytes, options if options else decoder_options)
            elif payload_type == PayloadType.TextMessage:
                decoder_options = options.__dict__ if options else {}
                decoder_options['include_segments'] = include_structure
                decoder_options['segment_offset'] = 0
                decoded_payload = TextMessagePayloadDecoder.decode(payload_bytes, options if options else decoder_options)
            elif payload_type == PayloadType.Control:
                result = ControlPayloadDecoder.decode(payload_bytes, {'include_segments': include_structure, 'segment_offset': 0})
                decoded_payload = result
                if result and hasattr(result, 'segments') and result.segments:
                    payload_segments.extend(result.segments)
            elif payload_type in (PayloadType.Reserved0C, PayloadType.Reserved0D, PayloadType.Reserved0E):
                # Reserved payload types: show raw only
                decoded_payload = None

            # If no segments were generated and we need structure, show basic payload info
            if include_structure and len(payload_segments) == 0 and len(bytes_data) > offset:
                payload_segments.append(PayloadSegment(
                    name=f'{get_payload_type_name(payload_type)} Payload',
                    description=f'Raw {get_payload_type_name(payload_type)} payload data ({len(payload_bytes)} bytes)',
                    start_byte=0,
                    end_byte=len(payload_bytes) - 1,
                    value=bytes_to_hex(payload_bytes)
                ))

            # Calculate message hash (use same path_byte_length we used for decoding)
            message_hash = MeshCorePacketDecoder._calculate_message_hash(
                bytes_data, route_type, payload_type, payload_version, path_byte_length_override=path_byte_length
            )

            packet = DecodedPacket(
                message_hash=message_hash,
                route_type=route_type,
                payload_type=payload_type,
                payload_version=payload_version,
                transport_codes=transport_codes,
                path_length=path_hop_count,
                path=path,
                payload={'raw': payload_hex, 'decoded': decoded_payload},
                total_bytes=len(bytes_data),
                is_valid=True,
                path_byte_length=path_byte_length,
                path_hash_size=path_hash_size if path_hash_size != 1 else None,
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
    def _parse_internal_with_verification(hex_data: str, include_structure: bool, options: Optional[DecryptionOptions]) -> Dict[str, Any]:
        """Internal unified parsing method with signature verification for advertisements"""
        # First do the regular parsing
        result = MeshCorePacketDecoder._parse_internal(hex_data, include_structure, options)

        # If it's an advertisement, verify the signature
        if result['packet'].payload_type == PayloadType.Advert and result['packet'].payload['decoded']:
            try:
                advert_payload = result['packet'].payload['decoded']
                bytes_data = hex_to_bytes(hex_data)

                # Calculate payload start offset (use same path_length as decoded packet, which may use fallback)
                offset = 1  # Skip header

                # Skip transport codes if present
                route_type = result['packet'].route_type
                if route_type in (RouteType.TransportFlood, RouteType.TransportDirect):
                    offset += 4

                # Skip path data: use the packet's path_byte_length (total path bytes after path_len byte)
                path_byte_length = getattr(result['packet'], 'path_byte_length', result['packet'].path_length) or 0
                offset += 1 + path_byte_length

                # Get the payload bytes
                payload_bytes = bytes_data[offset:]

                # Decode with verification
                verified_advert = AdvertPayloadDecoder.decode_with_verification(
                    payload_bytes,
                    {'include_segments': include_structure, 'segment_offset': 0}
                )

                if verified_advert:
                    # Update the payload with verification results
                    result['packet'].payload['decoded'] = verified_advert
                    # Do not mark the whole packet invalid when only the advert signature fails;
                    # packet stays valid so decoded advert and signature_valid/errors are visible.

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

            # Check path (multi-byte encoding)
            if len(bytes_data) < offset + 1:
                errors.append('Packet too short for path length')
            else:
                path_len_byte = bytes_data[offset]
                offset += 1
                hash_size, hop_count, byte_length = MeshCorePacketDecoder._decode_path_len_byte(path_len_byte)
                if hash_size == 4:
                    errors.append('Invalid path length byte: reserved hash size (bits 7:6 = 11)')
                if len(bytes_data) < offset + byte_length:
                    errors.append('Packet too short for path data')
                offset += byte_length

            # Check if we have payload data
            if offset >= len(bytes_data):
                errors.append('No payload data found')

        except Exception as error:
            errors.append(str(error))

        return ValidationResult(is_valid=len(errors) == 0, errors=errors if errors else None)

    @staticmethod
    def _decode_path_len_byte(path_len_byte: int) -> tuple:
        """
        Decode path length byte per meshcore-decoder PR #8 / Packet.h.
        Bits 7:6 = hash size selector: (path_len_byte >> 6) + 1 = 1, 2, or 3 bytes per hop.
        Bits 5:0 = hop count (0-63).
        Returns (hash_size, hop_count, byte_length). hash_size 4 = reserved.
        """
        hash_size = (path_len_byte >> 6) + 1  # 1, 2, or 3; 4 if bits 7:6 = 11 (reserved)
        hop_count = path_len_byte & 63
        byte_length = hop_count * hash_size
        return (hash_size, hop_count, byte_length)

    @staticmethod
    def _min_payload_for_type(payload_type: PayloadType) -> int:
        """Minimum payload size in bytes for the payload type (for path-length fallback)."""
        mins = {
            PayloadType.Advert: 101,      # public_key(32) + timestamp(4) + signature(64) + flags(1)
            PayloadType.AnonRequest: 35,  # dest(1) + pubkey(32) + MAC(2)
            PayloadType.Trace: 9,
            PayloadType.Ack: 4,
            PayloadType.Control: 1,
            PayloadType.Request: 4,
            PayloadType.Response: 4,
            PayloadType.TextMessage: 4,
            PayloadType.Path: 4,
            PayloadType.GroupText: 3,
            PayloadType.GroupData: 3,
        }
        return mins.get(payload_type, 0)

    @staticmethod
    def _calculate_message_hash(
        bytes_data: bytes,
        route_type: RouteType,
        payload_type: PayloadType,
        payload_version: PayloadVersion,
        path_byte_length_override: Optional[int] = None,
    ) -> str:
        """Calculate message hash for a packet"""
        def skip_path(off: int) -> int:
            if path_byte_length_override is not None:
                return off + 1 + path_byte_length_override
            if len(bytes_data) <= off:
                return off
            _, _, path_byte_len = MeshCorePacketDecoder._decode_path_len_byte(bytes_data[off])
            return off + 1 + path_byte_len

        # For TRACE packets, use the trace tag as hash
        if payload_type == PayloadType.Trace and len(bytes_data) >= 13:
            offset = 1
            if route_type in (RouteType.TransportFlood, RouteType.TransportDirect):
                offset += 4
            offset = skip_path(offset)

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
        if route_type in (RouteType.TransportFlood, RouteType.TransportDirect):
            offset += 4
        offset = skip_path(offset)

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
