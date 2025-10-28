"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Response payload decoder
"""

from typing import Optional, Dict, Any, List
from src.types.payloads import ResponsePayload
from src.types.packet import PayloadSegment
from src.types.enums import PayloadType, PayloadVersion
from src.utils.hex import byte_to_hex, bytes_to_hex


class ResponsePayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[ResponsePayload]:
        """Decode a Response payload"""
        if options is None:
            options = {}

        try:
            # Based on MeshCore payloads.md - Response payload structure:
            # - destination_hash (1 byte)
            # - source_hash (1 byte)
            # - cipher_mac (2 bytes)
            # - ciphertext (rest of payload)

            if len(payload) < 4:
                result = ResponsePayload(
                    payload_type=PayloadType.Response,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['Response payload too short (minimum 4 bytes: dest + source + MAC)'],
                    destination_hash='',
                    source_hash='',
                    cipher_mac='',
                    ciphertext='',
                    ciphertext_length=0
                )

                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid Response Data',
                        description='Response payload too short (minimum 4 bytes required)',
                        start_byte=options.get('segment_offset', 0),
                        end_byte=(options.get('segment_offset', 0) + len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)
            offset = 0

            # Destination Hash (1 byte)
            destination_hash = byte_to_hex(payload[offset])
            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Destination Hash',
                    description='First byte of destination node public key',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset,
                    value=destination_hash
                ))
            offset += 1

            # Source hash (1 byte)
            source_hash = byte_to_hex(payload[offset])
            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Source Hash',
                    description='First byte of source node public key',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset,
                    value=source_hash
                ))
            offset += 1

            # Cipher MAC (2 bytes)
            cipher_mac = bytes_to_hex(payload[offset:offset + 2])
            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Cipher MAC',
                    description='MAC for encrypted data in next field',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset + 1,
                    value=cipher_mac
                ))
            offset += 2

            # Ciphertext (remaining bytes)
            ciphertext = bytes_to_hex(payload[offset:])
            if options.get('include_segments') and len(payload) > offset:
                segments.append(PayloadSegment(
                    name='Ciphertext',
                    description='Encrypted response data (tag + content)',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + len(payload) - 1,
                    value=ciphertext
                ))

            result = ResponsePayload(
                payload_type=PayloadType.Response,
                version=PayloadVersion.Version1,
                is_valid=True,
                destination_hash=destination_hash,
                source_hash=source_hash,
                cipher_mac=cipher_mac,
                ciphertext=ciphertext,
                ciphertext_length=len(payload) - 4
            )

            if options.get('include_segments'):
                result.segments = segments

            return result
        except Exception as error:
            return ResponsePayload(
                payload_type=PayloadType.Response,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                destination_hash='',
                source_hash='',
                cipher_mac='',
                ciphertext='',
                ciphertext_length=0
            )
