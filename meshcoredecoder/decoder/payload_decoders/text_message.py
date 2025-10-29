"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

TextMessage payload decoder
"""

from typing import Optional, Dict, Any
from ...types.payloads import TextMessagePayload
from ...types.enums import PayloadType, PayloadVersion
from ...utils.hex import byte_to_hex, bytes_to_hex


class TextMessagePayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[TextMessagePayload]:
        """Decode a TextMessage payload"""
        if options is None:
            options = {}

        try:
            # Based on MeshCore payloads.md - TextMessage payload structure:
            # - destination_hash (1 byte)
            # - source_hash (1 byte)
            # - cipher_mac (2 bytes)
            # - ciphertext (rest of payload)

            if len(payload) < 4:
                return TextMessagePayload(
                    payload_type=PayloadType.TextMessage,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['TextMessage payload too short (minimum 4 bytes: dest + source + MAC)'],
                    destination_hash='',
                    source_hash='',
                    cipher_mac='',
                    ciphertext='',
                    ciphertext_length=0
                )

            destination_hash = byte_to_hex(payload[0])
            source_hash = byte_to_hex(payload[1])
            cipher_mac = bytes_to_hex(payload[2:4])
            ciphertext = bytes_to_hex(payload[4:])

            return TextMessagePayload(
                payload_type=PayloadType.TextMessage,
                version=PayloadVersion.Version1,
                is_valid=True,
                destination_hash=destination_hash,
                source_hash=source_hash,
                cipher_mac=cipher_mac,
                ciphertext=ciphertext,
                ciphertext_length=len(payload) - 4
            )
        except Exception as error:
            return TextMessagePayload(
                payload_type=PayloadType.TextMessage,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                destination_hash='',
                source_hash='',
                cipher_mac='',
                ciphertext='',
                ciphertext_length=0
            )
