"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Path payload decoder with decryption support
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import PathPayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...types.crypto import DecryptionOptions
from ...utils.hex import byte_to_hex, bytes_to_hex, hex_to_bytes
from ...crypto.channel_crypto import ChannelCrypto


class PathPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[PathPayload]:
        """Decode a Path payload with optional decryption"""
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
            # Based on MeshCore packet_breakdown_guide.md - Path payload structure:
            # Encrypted format:
            # - destination_hash (1 byte)
            # - source_hash (1 byte)
            # - cipher_mac (2 bytes)
            # - ciphertext (rest of payload) - contains: path_len(1) + path(path_len) + extra_type(1) + extra(variable)

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)
            offset = 0

            if len(payload) < 4:
                result = PathPayload(
                    payload_type=PayloadType.Path,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['Path payload too short (minimum 4 bytes: dest + source + MAC)'],
                    path_length=0,
                    path_hashes=[],
                    extra_type=0,
                    extra_data=''
                )

                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid Path Data',
                        description='Path payload too short (minimum 4 bytes required)',
                        start_byte=segment_offset,
                        end_byte=segment_offset + len(payload) - 1,
                        value=bytes_to_hex(payload)
                    )]

                return result

            # Parse encrypted portion
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

            ciphertext = bytes_to_hex(payload[offset:])
            if options.get('include_segments') and len(payload) > offset:
                segments.append(PayloadSegment(
                    name='Ciphertext',
                    description=f'Encrypted path data ({len(payload) - offset} bytes). Contains encrypted plaintext with path_len, path, extra_type, and extra',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + len(payload) - 1,
                    value=ciphertext
                ))

            result = PathPayload(
                payload_type=PayloadType.Path,
                version=PayloadVersion.Version1,
                is_valid=True,
                path_length=0,
                path_hashes=[],
                extra_type=0,
                extra_data='',
                destination_hash=destination_hash,
                source_hash=source_hash,
                cipher_mac=cipher_mac,
                ciphertext=ciphertext
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
                    decryption_result = ChannelCrypto.decrypt_path_payload(
                        ciphertext,
                        cipher_mac,
                        shared_secret
                    )

                    if decryption_result.success and decryption_result.data:
                        # Parse decrypted path structure
                        path_len = decryption_result.data['path_len']
                        path_bytes = decryption_result.data['path']
                        extra_type = decryption_result.data['extra_type']
                        extra_bytes = decryption_result.data['extra']

                        # Convert path bytes to hex strings
                        path_hashes = [byte_to_hex(b) for b in path_bytes]
                        extra_data = bytes_to_hex(extra_bytes)

                        result.path_length = path_len
                        result.path_hashes = path_hashes
                        result.extra_type = extra_type
                        result.extra_data = extra_data
                        result.decrypted = {
                            'path_len': path_len,
                            'path_hashes': path_hashes,
                            'extra_type': extra_type,
                            'extra_data': extra_data
                        }
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
                                decryption_result = ChannelCrypto.decrypt_path_payload(
                                    ciphertext,
                                    cipher_mac,
                                    shared_secret
                                )

                                if decryption_result.success and decryption_result.data:
                                    # Parse decrypted path structure
                                    path_len = decryption_result.data['path_len']
                                    path_bytes = decryption_result.data['path']
                                    extra_type = decryption_result.data['extra_type']
                                    extra_bytes = decryption_result.data['extra']

                                    # Convert path bytes to hex strings
                                    path_hashes = [byte_to_hex(b) for b in path_bytes]
                                    extra_data = bytes_to_hex(extra_bytes)

                                    result.path_length = path_len
                                    result.path_hashes = path_hashes
                                    result.extra_type = extra_type
                                    result.extra_data = extra_data
                                    result.decrypted = {
                                        'path_len': path_len,
                                        'path_hashes': path_hashes,
                                        'extra_type': extra_type,
                                        'extra_data': extra_data
                                    }
                                    break

                        # If no peer keys matched by hash, try all peer keys anyway
                        if not result.decrypted and hasattr(key_store, 'peer_public_keys') and key_store.peer_public_keys:
                            for peer_pub_key_hex in key_store.peer_public_keys:
                                shared_secret = ChannelCrypto.calculate_shared_secret(
                                    peer_pub_key_hex,
                                    my_priv_key_hex
                                )
                                if shared_secret:
                                    decryption_result = ChannelCrypto.decrypt_path_payload(
                                        ciphertext,
                                        cipher_mac,
                                        shared_secret
                                    )
                                    if decryption_result.success and decryption_result.data:
                                        # Parse decrypted path structure
                                        path_len = decryption_result.data['path_len']
                                        path_bytes = decryption_result.data['path']
                                        extra_type = decryption_result.data['extra_type']
                                        extra_bytes = decryption_result.data['extra']

                                        # Convert path bytes to hex strings
                                        path_hashes = [byte_to_hex(b) for b in path_bytes]
                                        extra_data = bytes_to_hex(extra_bytes)

                                        result.path_length = path_len
                                        result.path_hashes = path_hashes
                                        result.extra_type = extra_type
                                        result.extra_data = extra_data
                                        result.decrypted = {
                                            'path_len': path_len,
                                            'path_hashes': path_hashes,
                                            'extra_type': extra_type,
                                            'extra_data': extra_data
                                        }
                                        break
                                if result.decrypted:
                                    break

            # If decryption failed, we can't parse the path structure
            # But we still return the encrypted payload info
            if not result.decrypted:
                result.errors = ['Path payload is encrypted and decryption failed or no key provided']

            if options.get('include_segments'):
                result.segments = segments

            return result
        except Exception as error:
            return PathPayload(
                payload_type=PayloadType.Path,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                path_length=0,
                path_hashes=[],
                extra_type=0,
                extra_data=''
            )
