"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

AnonRequest payload decoder with decryption support
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import AnonRequestPayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...types.crypto import DecryptionOptions
from ...utils.hex import byte_to_hex, bytes_to_hex, hex_to_bytes
from ...crypto.channel_crypto import ChannelCrypto


class AnonRequestPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[AnonRequestPayload]:
        """Decode an AnonRequest payload with optional decryption"""
        if options is None:
            options = {}

        # Handle DecryptionOptions object
        decryption_options = None
        if isinstance(options, DecryptionOptions):
            decryption_options = options
            options = {'include_segments': False}
        elif isinstance(options, dict) and 'key_store' in options:
            # Convert dict to DecryptionOptions if it has key_store
            decryption_options = DecryptionOptions(
                key_store=options.get('key_store'),
                attempt_decryption=options.get('attempt_decryption', True),
                include_raw_ciphertext=options.get('include_raw_ciphertext', True)
            )

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

            # Attempt decryption if key store is provided
            # For anonymous requests, we use the sender's public key from the packet
            if decryption_options and decryption_options.key_store and decryption_options.attempt_decryption:
                key_store = decryption_options.key_store
                node_keys = key_store.node_keys if hasattr(key_store, 'node_keys') else {}

                # Find our node key that matches destination hash
                destination_hash_byte = hex_to_bytes(destination_hash)[0]
                my_node_key = None

                for my_pub_key_hex, my_priv_key_hex in node_keys.items():
                    my_pub_key_bytes = hex_to_bytes(my_pub_key_hex)
                    if len(my_pub_key_bytes) >= 1 and my_pub_key_bytes[0] == destination_hash_byte:
                        my_node_key = (my_pub_key_hex, my_priv_key_hex)
                        break

                # Calculate shared secret using sender's public key from packet
                if my_node_key:
                    my_pub_key_hex, my_priv_key_hex = my_node_key
                    shared_secret = ChannelCrypto.calculate_shared_secret(
                        sender_public_key,
                        my_priv_key_hex
                    )

                    if shared_secret:
                        decryption_result = ChannelCrypto.decrypt_anon_request_payload(
                            ciphertext,
                            cipher_mac,
                            shared_secret
                        )

                        if decryption_result.success and decryption_result.data:
                            result.decrypted = decryption_result.data

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
