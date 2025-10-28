"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

GroupText payload decoder with decryption support
"""

from typing import Optional, Dict, Any, List
from src.types.payloads import GroupTextPayload
from src.types.packet import PayloadSegment
from src.types.enums import PayloadType, PayloadVersion
from src.types.crypto import DecryptionOptions, CryptoKeyStore
from src.crypto.channel_crypto import ChannelCrypto
from src.utils.hex import byte_to_hex, bytes_to_hex


class GroupTextPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[DecryptionOptions] = None
    ) -> Optional[GroupTextPayload]:
        """Decode a GroupText payload with optional decryption"""
        if options is None:
            options = DecryptionOptions()

        try:
            if len(payload) < 3:
                result = GroupTextPayload(
                    payload_type=PayloadType.GroupText,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['GroupText payload too short (need at least channel_hash(1) + MAC(2))'],
                    channel_hash='',
                    cipher_mac='',
                    ciphertext='',
                    ciphertext_length=0
                )

                if options and hasattr(options, 'include_segments') and options.include_segments:
                    result.segments = [PayloadSegment(
                        name='Invalid GroupText Data',
                        description='GroupText payload too short (minimum 3 bytes required)',
                        start_byte=options.get('segment_offset', 0) if isinstance(options, dict) else 0,
                        end_byte=(options.get('segment_offset', 0) if isinstance(options, dict) else 0) + len(payload) - 1,
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0) if isinstance(options, dict) else 0
            offset = 0

            # Channel hash (1 byte) - first byte of SHA256 of channel's shared key
            channel_hash = byte_to_hex(payload[offset])
            if isinstance(options, dict) and options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Channel Hash',
                    description='First byte of SHA256 of channel\'s shared key',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset,
                    value=channel_hash
                ))
            offset += 1

            # MAC (2 bytes) - message authentication code
            cipher_mac = bytes_to_hex(payload[offset:offset + 2])
            if isinstance(options, dict) and options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Cipher MAC',
                    description='MAC for encrypted data',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset + 1,
                    value=cipher_mac
                ))
            offset += 2

            # Ciphertext (remaining bytes) - encrypted message
            ciphertext = bytes_to_hex(payload[offset:])
            if isinstance(options, dict) and options.get('include_segments') and len(payload) > offset:
                segments.append(PayloadSegment(
                    name='Ciphertext',
                    description='Encrypted message content (timestamp + flags + message)',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + len(payload) - 1,
                    value=ciphertext
                ))

            group_text = GroupTextPayload(
                payload_type=PayloadType.GroupText,
                version=PayloadVersion.Version1,
                is_valid=True,
                channel_hash=channel_hash,
                cipher_mac=cipher_mac,
                ciphertext=ciphertext,
                ciphertext_length=len(payload) - 3
            )

            # Attempt decryption if key store is provided
            if options.key_store and options.key_store.has_channel_key(channel_hash):
                # Try all possible keys for this hash (handles collisions)
                channel_keys = options.key_store.get_channel_keys(channel_hash)

                for channel_key in channel_keys:
                    decryption_result = ChannelCrypto.decrypt_group_text_message(
                        ciphertext,
                        cipher_mac,
                        channel_key
                    )

                    if decryption_result.success and decryption_result.data:
                        group_text.decrypted = decryption_result.data
                        break  # Stop trying keys once we find one that works

            if isinstance(options, dict) and options.get('include_segments'):
                group_text.segments = segments

            return group_text
        except Exception as error:
            return GroupTextPayload(
                payload_type=PayloadType.GroupText,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                channel_hash='',
                cipher_mac='',
                ciphertext='',
                ciphertext_length=0
            )
