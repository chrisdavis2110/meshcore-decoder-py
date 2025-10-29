"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

AnonRequest payload decoder
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import AnonRequestPayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...utils.hex import byte_to_hex, bytes_to_hex


class AnonRequestPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[AnonRequestPayload]:
        """Decode an AnonRequest payload"""
        if options is None:
            options = {}

        try:
            # Based on MeshCore payloads.md - AnonRequest payload structure:
            # - destination_hash (1 byte)
            # - sender_public_key (32 bytes)
            # - cipher_mac (2 bytes)
            # - ciphertext (rest of payload)

            if len(payload) < 35:
                result = AnonRequestPayload(
                    payload_type=PayloadType.AnonRequest,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['AnonRequest payload too short (minimum 35 bytes: dest + public key + MAC)'],
                    destination_hash='',
                    sender_public_key='',
                    cipher_mac='',
                    ciphertext='',
                    ciphertext_length=0
                )

                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid AnonRequest Data',
                        description='AnonRequest payload too short (minimum 35 bytes required: 1 for dest hash + 32 for public key + 2 for MAC)',
                        start_byte=options.get('segment_offset', 0),
                        end_byte=(options.get('segment_offset', 0) + len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)
            offset = 0

            # Parse destination hash (1 byte)
            destination_hash = byte_to_hex(payload[0])

            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Destination Hash',
                    description=f'First byte of destination node public key: 0x{destination_hash}',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset,
                    value=destination_hash
                ))
            offset += 1

            # Parse sender public key (32 bytes)
            sender_public_key = bytes_to_hex(payload[1:33])

            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Sender Public Key',
                    description='Ed25519 public key of the sender (32 bytes)',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset + 31,
                    value=sender_public_key
                ))
            offset += 32

            # Parse cipher MAC (2 bytes)
            cipher_mac = bytes_to_hex(payload[33:35])

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
            ciphertext = bytes_to_hex(payload[35:])

            if options.get('include_segments') and len(payload) > 35:
                segments.append(PayloadSegment(
                    name='Ciphertext',
                    description=f'Encrypted message data ({len(payload) - 35} bytes). Contains encrypted plaintext with timestamp, sync timestamp (room server only), and password',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + len(payload) - 1,
                    value=ciphertext
                ))

            result = AnonRequestPayload(
                payload_type=PayloadType.AnonRequest,
                version=PayloadVersion.Version1,
                is_valid=True,
                destination_hash=destination_hash,
                sender_public_key=sender_public_key,
                cipher_mac=cipher_mac,
                ciphertext=ciphertext,
                ciphertext_length=len(payload) - 35
            )

            if options.get('include_segments'):
                result.segments = segments

            return result
        except Exception as error:
            return AnonRequestPayload(
                payload_type=PayloadType.AnonRequest,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                destination_hash='',
                sender_public_key='',
                cipher_mac='',
                ciphertext='',
                ciphertext_length=0
            )
