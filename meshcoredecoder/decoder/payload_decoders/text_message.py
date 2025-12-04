"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

TextMessage payload decoder
"""

from typing import Optional, Dict, Any
from ...types.payloads import TextMessagePayload
from ...types.enums import PayloadType, PayloadVersion
from ...types.crypto import DecryptionOptions
from ...utils.hex import byte_to_hex, bytes_to_hex
from ...crypto.channel_crypto import ChannelCrypto


class TextMessagePayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[DecryptionOptions] = None
    ) -> Optional[TextMessagePayload]:
        """
        Decode a TextMessage payload
        TextMessage uses the same encryption as Response: Ed25519 key exchange
        """
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
            ciphertext_bytes = payload[4:]

            # Attempt decryption if key store is provided
            decrypted_data: Optional[Dict[str, Any]] = None

            # Check if we should attempt decryption
            if not options:
                decrypted_data = {'error': 'No decryption options provided. Use --node-key PUBKEY:PRIVKEY to provide decryption keys.'}
            elif not options.attempt_decryption:
                decrypted_data = {'error': 'Decryption disabled in options'}
            elif not options.key_store:
                decrypted_data = {'error': 'No key store provided. Use --node-key PUBKEY:PRIVKEY to provide decryption keys.'}
            elif len(ciphertext_bytes) == 0:
                decrypted_data = {'error': 'No ciphertext to decrypt'}
            elif options.attempt_decryption and options.key_store and len(ciphertext_bytes) > 0:
                # TextMessage uses the same Ed25519 key exchange as Response
                # Sender encrypts with: ed25519_key_exchange(sender_privkey, receiver_pubkey)
                # Receiver decrypts with: ed25519_key_exchange(receiver_privkey, sender_pubkey)

                decryption_success = False
                matching_keys_tried = []
                decryption_errors = []

                # Find sender's public key (matches source_hash) and our private key
                sender_pubkey = None
                our_privkey = None
                our_pubkey = None

                # First, find the sender's public key (matches source_hash) and our private key
                for stored_pubkey, stored_privkey in options.key_store.node_keys.items():
                    pubkey_bytes = bytes.fromhex(stored_pubkey)
                    if len(pubkey_bytes) > 0:
                        pubkey_first_byte = byte_to_hex(pubkey_bytes[0])

                        # Check if this public key matches the sender (source_hash)
                        if pubkey_first_byte == source_hash:
                            sender_pubkey = stored_pubkey
                            our_privkey = stored_privkey
                        # Also check if this is our public key (matches destination_hash)
                        elif pubkey_first_byte == destination_hash:
                            our_pubkey = stored_pubkey
                            # Use this private key as our private key if we don't have one yet
                            if not our_privkey:
                                our_privkey = stored_privkey

                # Try key exchange with sender's public key + our private key
                if sender_pubkey and our_privkey:
                    matching_keys_tried.append({
                        'pubkey_first_byte': byte_to_hex(bytes.fromhex(sender_pubkey)[0]),
                        'matched_hash': 'source',
                        'pubkey': sender_pubkey[:16] + '...' if len(sender_pubkey) > 16 else sender_pubkey,
                        'note': 'Using sender public key + our private key for key exchange'
                    })

                    decryption_result = ChannelCrypto.decrypt_node_message(
                        ciphertext,
                        cipher_mac,
                        our_privkey,  # Our private key (receiver)
                        node_public_key=our_pubkey,  # Our public key (for reference, not used in key exchange)
                        other_public_key=sender_pubkey  # Sender's public key (for key exchange)
                    )

                    if decryption_result.success and decryption_result.data:
                        decrypted_bytes = decryption_result.data
                        decryption_success = True

                        # Parse decrypted TextMessage content
                        # Format: timestamp (4 bytes, little-endian) + flags (1 byte) + message (variable)
                        if len(decrypted_bytes) >= 5:
                            # Parse timestamp
                            timestamp = (
                                decrypted_bytes[0] |
                                (decrypted_bytes[1] << 8) |
                                (decrypted_bytes[2] << 16) |
                                (decrypted_bytes[3] << 24)
                            )

                            # Parse flags
                            flags = decrypted_bytes[4]

                            # Parse message (remaining bytes, UTF-8)
                            message_bytes = decrypted_bytes[5:]
                            try:
                                message = message_bytes.decode('utf-8')
                            except UnicodeDecodeError:
                                message = message_bytes.hex()

                            decrypted_data = {
                                'timestamp': timestamp,
                                'flags': flags,
                                'message': message,
                                'raw': bytes_to_hex(decrypted_bytes)
                            }
                        else:
                            # Decryption succeeded but data is too short
                            decrypted_data = {
                                'raw': bytes_to_hex(decrypted_bytes),
                                'error': 'Decrypted data too short (less than 5 bytes)'
                            }
                    else:
                        if decryption_result.error:
                            decryption_errors.append(f"Key exchange (our_priv + sender_pub): {decryption_result.error}")

                # Try all keys as fallback
                if not decryption_success:
                    for stored_pubkey, stored_privkey in options.key_store.node_keys.items():
                        # Skip if we already tried this combination
                        if sender_pubkey and stored_pubkey == sender_pubkey:
                            continue

                        pubkey_bytes = bytes.fromhex(stored_pubkey)
                        if len(pubkey_bytes) > 0:
                            pubkey_first_byte = byte_to_hex(pubkey_bytes[0])

                            matching_keys_tried.append({
                                'pubkey_first_byte': pubkey_first_byte,
                                'matched_hash': 'trying_all_keys',
                                'pubkey': stored_pubkey[:16] + '...' if len(stored_pubkey) > 16 else stored_pubkey,
                                'note': f'Trying key exchange with {stored_pubkey[:8]}... as other party'
                            })

                            decryption_result = ChannelCrypto.decrypt_node_message(
                                ciphertext,
                                cipher_mac,
                                our_privkey if our_privkey else stored_privkey,
                                node_public_key=None,
                                other_public_key=stored_pubkey
                            )

                            if decryption_result.success and decryption_result.data:
                                decrypted_bytes = decryption_result.data
                                decryption_success = True

                                # Parse decrypted content
                                if len(decrypted_bytes) >= 5:
                                    timestamp = (
                                        decrypted_bytes[0] |
                                        (decrypted_bytes[1] << 8) |
                                        (decrypted_bytes[2] << 16) |
                                        (decrypted_bytes[3] << 24)
                                    )
                                    flags = decrypted_bytes[4]
                                    message_bytes = decrypted_bytes[5:]
                                    try:
                                        message = message_bytes.decode('utf-8')
                                    except UnicodeDecodeError:
                                        message = message_bytes.hex()

                                    decrypted_data = {
                                        'timestamp': timestamp,
                                        'flags': flags,
                                        'message': message,
                                        'raw': bytes_to_hex(decrypted_bytes)
                                    }
                                break

                if not decryption_success:
                    # Build detailed error message
                    error_msg = 'Decryption failed'
                    if len(matching_keys_tried) == 0:
                        error_msg += f': No node key found matching source hash ({source_hash}) or destination hash ({destination_hash})'
                        error_msg += f'. Available keys: {len(options.key_store.node_keys)} key(s) provided'
                        if len(options.key_store.node_keys) > 0:
                            available_hashes = []
                            for pk in options.key_store.node_keys.keys():
                                try:
                                    pk_bytes = bytes.fromhex(pk)
                                    if len(pk_bytes) > 0:
                                        available_hashes.append(byte_to_hex(pk_bytes[0]))
                                except:
                                    pass
                            if available_hashes:
                                error_msg += f'. Available key hashes: {", ".join(set(available_hashes))}'
                    else:
                        error_msg += f': {len(matching_keys_tried)} matching key(s) tried but decryption failed'
                        if decryption_errors:
                            error_msg += f'. Errors: {"; ".join(decryption_errors)}'
                        error_msg += '. Tried all key derivation methods (byte ranges, hashes, public key, combined methods). '
                        error_msg += 'Possible causes: 1) MeshCore uses a different key derivation method than implemented, 2) Encryption key is stored separately (not derived from Ed25519 keys), 3) Key format mismatch.'

                    decrypted_data = {'error': error_msg}

            # Ensure decrypted_data is always set (fallback)
            if decrypted_data is None:
                decrypted_data = {'error': 'Decryption was attempted but no result was set. This is a bug.'}

            return TextMessagePayload(
                payload_type=PayloadType.TextMessage,
                version=PayloadVersion.Version1,
                is_valid=True,
                destination_hash=destination_hash,
                source_hash=source_hash,
                cipher_mac=cipher_mac,
                ciphertext=ciphertext,
                ciphertext_length=len(payload) - 4,
                decrypted=decrypted_data
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
