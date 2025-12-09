"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

GroupData payload decoder with decryption support
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import GroupDataPayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...types.crypto import DecryptionOptions
from ...utils.hex import byte_to_hex, bytes_to_hex
from ...crypto.channel_crypto import ChannelCrypto


class GroupDataPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[DecryptionOptions] = None
    ) -> Optional[GroupDataPayload]:
        """Decode a GroupData payload with optional decryption"""
        if options is None:
            options = DecryptionOptions()

        try:
            segment_offset = 0
            if isinstance(options, dict):
                segment_offset = options.get('segment_offset', 0)

            if len(payload) < 3:
                result = GroupDataPayload(
                    payload_type=PayloadType.GroupData,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['GroupData payload too short (need at least channel_hash(1) + MAC(2))'],
                    channel_hash='',
                    cipher_mac='',
                    ciphertext='',
                    ciphertext_length=0
                )

                if isinstance(options, dict) and options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid GroupData Data',
                        description='GroupData payload too short (minimum 3 bytes required)',
                        start_byte=segment_offset,
                        end_byte=segment_offset + len(payload) - 1,
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
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

            # Ciphertext (remaining bytes) - encrypted datagram data
            ciphertext = bytes_to_hex(payload[offset:])
            if isinstance(options, dict) and options.get('include_segments') and len(payload) > offset:
                segments.append(PayloadSegment(
                    name='Ciphertext',
                    description='Encrypted datagram content (timestamp + flags + data blob)',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + len(payload) - 1,
                    value=ciphertext
                ))

            group_data = GroupDataPayload(
                payload_type=PayloadType.GroupData,
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
                    decryption_result = ChannelCrypto.decrypt_group_data_payload(
                        ciphertext,
                        cipher_mac,
                        channel_key
                    )

                    if decryption_result.success and decryption_result.data:
                        group_data.decrypted = decryption_result.data
                        break  # Stop trying keys once we find one that works

            if isinstance(options, dict) and options.get('include_segments'):
                group_data.segments = segments

            return group_data
        except Exception as error:
            return GroupDataPayload(
                payload_type=PayloadType.GroupData,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                channel_hash='',
                cipher_mac='',
                ciphertext='',
                ciphertext_length=0
            )
