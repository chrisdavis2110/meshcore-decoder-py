"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

TextMessage payload decoder with decryption support
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import TextMessagePayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...types.crypto import DecryptionOptions
from ...utils.hex import byte_to_hex, bytes_to_hex, hex_to_bytes
from ...crypto.channel_crypto import ChannelCrypto


class TextMessagePayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[TextMessagePayload]:
        """Decode a TextMessage payload with optional decryption"""
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
            # Based on MeshCore packet_breakdown_guide.md - TextMessage payload structure:
            # - destination_hash (1 byte)
            # - source_hash (1 byte)
            # - cipher_mac (2 bytes)
            # - ciphertext (rest of payload)

            if len(payload) < 4:
                result = TextMessagePayload(
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

                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid TextMessage Data',
                        description='TextMessage payload too short (minimum 4 bytes required)',
                        start_byte=options.get('segment_offset', 0),
                        end_byte=(options.get('segment_offset', 0) + len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)
            offset = 0

            # Parse destination hash (1 byte)
            destination_hash = byte_to_hex(payload[offset])
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
            source_hash = byte_to_hex(payload[offset])
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
                    description=f'Encrypted message data ({len(payload) - offset} bytes). Contains encrypted plaintext with timestamp, flags, and message',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + len(payload) - 1,
                    value=ciphertext
                ))

            result = TextMessagePayload(
                payload_type=PayloadType.TextMessage,
                version=PayloadVersion.Version1,
                is_valid=True,
                destination_hash=destination_hash,
                source_hash=source_hash,
                cipher_mac=cipher_mac,
                ciphertext=ciphertext,
                ciphertext_length=len(payload) - 4
            )

            # Attempt decryption if key store is provided
            if decryption_options and decryption_options.key_store and decryption_options.attempt_decryption:
                key_store = decryption_options.key_store

                # Try to decrypt using shared secrets or calculate from node keys
                shared_secrets = key_store.shared_secrets if hasattr(key_store, 'shared_secrets') else {}
                node_keys = key_store.node_keys if hasattr(key_store, 'node_keys') else {}

                # Try all shared secrets first (most efficient)
                for peer_pub_key, shared_secret_hex in shared_secrets.items():
                    shared_secret = hex_to_bytes(shared_secret_hex)
                    decryption_result = ChannelCrypto.decrypt_text_message_payload(
                        ciphertext,
                        cipher_mac,
                        shared_secret
                    )

                    if decryption_result.success and decryption_result.data:
                        result.decrypted = decryption_result.data
                        break  # Stop trying once we find a working key

                # If shared secrets didn't work, try calculating from node keys
                if not result.decrypted and node_keys:
                    destination_hash_byte = hex_to_bytes(destination_hash)[0]

                    # Find our node key that matches destination hash
                    my_node_key = None
                    for my_pub_key_hex, my_priv_key_hex in node_keys.items():
                        my_pub_key_bytes = hex_to_bytes(my_pub_key_hex)
                        if len(my_pub_key_bytes) >= 1 and my_pub_key_bytes[0] == destination_hash_byte:
                            my_node_key = (my_pub_key_hex, my_priv_key_hex)
                            break

                    # If we found our node key, try to find peer public keys that match source hash
                    if my_node_key and hasattr(key_store, 'get_peers_by_hash'):
                        my_pub_key_hex, my_priv_key_hex = my_node_key
                        peer_pub_keys = key_store.get_peers_by_hash(source_hash)

                        for peer_pub_key_hex in peer_pub_keys:
                            # Calculate shared secret using ECDH
                            shared_secret = ChannelCrypto.calculate_shared_secret(
                                peer_pub_key_hex,
                                my_priv_key_hex
                            )

                            if shared_secret:
                                # Try to decrypt with this shared secret
                                decryption_result = ChannelCrypto.decrypt_text_message_payload(
                                    ciphertext,
                                    cipher_mac,
                                    shared_secret
                                )

                                if decryption_result.success and decryption_result.data:
                                    result.decrypted = decryption_result.data
                                    break

                        # If no peer keys matched by hash, try all peer keys anyway
                        if not result.decrypted and hasattr(key_store, 'peer_public_keys') and key_store.peer_public_keys:
                            for peer_pub_key_hex in key_store.peer_public_keys:
                                shared_secret = ChannelCrypto.calculate_shared_secret(
                                    peer_pub_key_hex,
                                    my_priv_key_hex
                                )
                                if shared_secret:
                                    decryption_result = ChannelCrypto.decrypt_text_message_payload(
                                        ciphertext,
                                        cipher_mac,
                                        shared_secret
                                    )
                                    if decryption_result.success and decryption_result.data:
                                        result.decrypted = decryption_result.data
                                        break
                                if result.decrypted:
                                    break

            if options.get('include_segments'):
                result.segments = segments

            return result
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
