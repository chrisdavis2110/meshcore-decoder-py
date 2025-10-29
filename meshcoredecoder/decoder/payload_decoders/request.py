"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Request payload decoder
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import RequestPayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion, RequestType
from ...utils.hex import bytes_to_hex


class RequestPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[RequestPayload]:
        """Decode a Request payload"""
        if options is None:
            options = {}

        try:
            # Based on MeshCore payloads.md - Request payload structure:
            # - destination hash (1 byte)
            # - source hash (1 byte)
            # - cipher MAC (2 bytes)
            # - ciphertext (rest of payload) - contains encrypted timestamp, request type, and request data

            if len(payload) < 4:
                result = RequestPayload(
                    payload_type=PayloadType.Request,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['Request payload too short (minimum 4 bytes: dest hash + source hash + MAC)'],
                    timestamp=0,
                    request_type=RequestType.GetStats,
                    request_data='',
                    destination_hash='',
                    source_hash='',
                    cipher_mac='',
                    ciphertext=''
                )

                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid Request Data',
                        description='Request payload too short (minimum 4 bytes required: 1 for dest hash + 1 for source hash + 2 for MAC)',
                        start_byte=options.get('segment_offset', 0),
                        end_byte=(options.get('segment_offset', 0) + len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)
            offset = 0

            # Parse destination hash (1 byte)
            destination_hash = bytes_to_hex(payload[offset:offset + 1])

            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Destination Hash',
                    description=f'First byte of destination node public key: 0x{destination_hash}',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset,
                    value=destination_hash
                ))
            offset += 1

            # Parse source hash (1 byte)
            source_hash = bytes_to_hex(payload[offset:offset + 1])

            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Source Hash',
                    description=f'First byte of source node public key: 0x{source_hash}',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset,
                    value=source_hash
                ))
            offset += 1

            # Parse cipher MAC (2 bytes)
            cipher_mac = bytes_to_hex(payload[offset:offset + 2])

            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Cipher MAC',
                    description='MAC for encrypted data verification (2 bytes)',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset + 1,
                    value=cipher_mac
                ))
            offset += 2

            # Parse ciphertext (remaining bytes)
            ciphertext = bytes_to_hex(payload[offset:])

            if options.get('include_segments') and len(payload) > offset:
                segments.append(PayloadSegment(
                    name='Ciphertext',
                    description=f'Encrypted message data ({len(payload) - offset} bytes). Contains encrypted plaintext with timestamp, request type, and request data',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + len(payload) - 1,
                    value=ciphertext
                ))

            result = RequestPayload(
                payload_type=PayloadType.Request,
                version=PayloadVersion.Version1,
                is_valid=True,
                timestamp=0,  # Will be decrypted if key is available
                request_type=RequestType.GetStats,  # Default value, will be overridden if decrypted
                request_data='',
                destination_hash=destination_hash,
                source_hash=source_hash,
                cipher_mac=cipher_mac,
                ciphertext=ciphertext
            )

            if options.get('include_segments'):
                result.segments = segments

            return result
        except Exception as error:
            return RequestPayload(
                payload_type=PayloadType.Request,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                timestamp=0,
                request_type=RequestType.GetStats,
                request_data='',
                destination_hash='',
                source_hash='',
                cipher_mac='',
                ciphertext=''
            )
