"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Response payload decoder
"""

from typing import Optional, Dict, Any, List, Union
from ...types.payloads import ResponsePayload, NeighborEntry
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...types.crypto import DecryptionOptions
from ...crypto.channel_crypto import ChannelCrypto
from ...utils.hex import byte_to_hex, bytes_to_hex


class ResponsePayloadDecoder:
    @staticmethod
    def _parse_neighbors(decrypted_bytes: bytes, content_offset: int) -> tuple[list, Optional[int]]:
        """
        Parse neighbor entries from decrypted bytes.

        Format (as per MeshCore):
        Byte 0-3:   sender_timestamp (uint32_t, little-endian)
        Byte 4-5:   neighbours_count (uint16_t, little-endian) - total available
        Byte 6-7:   results_count (uint16_t, little-endian) - in this packet
        Byte 8+:    Array of neighbor entries, each entry:
                    - pubkey_prefix (variable length, 1-32 bytes)
                    - heard_seconds_ago (uint32_t, little-endian, 4 bytes)
                    - snr (int8_t, 1 byte)

        Returns tuple of (list of NeighborEntry objects, total_count if available).
        """
        neighbors = []
        remaining_bytes = len(decrypted_bytes) - content_offset
        total_count = None
        actual_count = None

        if remaining_bytes < 8:
            return neighbors, total_count

        # Parse header: sender_timestamp (4) + neighbours_count (2) + results_count (2)
        if content_offset + 8 > len(decrypted_bytes):
            return neighbors, total_count

        sender_timestamp = (
            decrypted_bytes[content_offset] |
            (decrypted_bytes[content_offset + 1] << 8) |
            (decrypted_bytes[content_offset + 2] << 16) |
            (decrypted_bytes[content_offset + 3] << 24)
        )

        total_count = (
            decrypted_bytes[content_offset + 4] |
            (decrypted_bytes[content_offset + 5] << 8)
        )

        actual_count = (
            decrypted_bytes[content_offset + 6] |
            (decrypted_bytes[content_offset + 7] << 8)
        )

        # Parse neighbor entries starting at byte 8 (content_offset + 8)
        entry_offset = content_offset + 8

        # Parse variable-length neighbor entries
        # Each entry: pubkey_prefix (1-32 bytes) + heard_seconds_ago (4 bytes) + snr (1 byte)
        # Entry size = pubkey_prefix_length + 4 + 1 bytes
        # Detect pubkey_prefix_length by checking entry size
        # If entries are at 9-byte intervals, pubkey_prefix_length = 4
        # If entries are at 6-byte intervals, pubkey_prefix_length = 1

        # Try to detect pubkey_prefix_length from first entry
        remaining_after_header = len(decrypted_bytes) - entry_offset
        if remaining_after_header >= 9 and actual_count > 0:
            # Check if entries are at 9-byte intervals (pubkey_prefix_length = 4)
            first_hash_pos = entry_offset
            second_hash_pos = entry_offset + 9
            if (second_hash_pos < len(decrypted_bytes) and
                decrypted_bytes[first_hash_pos] != 0x00 and decrypted_bytes[first_hash_pos] != 0xFF and
                decrypted_bytes[second_hash_pos] != 0x00 and decrypted_bytes[second_hash_pos] != 0xFF):
                pubkey_prefix_length = 4  # 4-byte prefix format
            else:
                pubkey_prefix_length = 1  # 1-byte hash format
        else:
            pubkey_prefix_length = 1  # Default to 1-byte

        entry_size = pubkey_prefix_length + 4 + 1  # pubkey_prefix + heard_seconds_ago + snr

        for i in range(actual_count):
            if entry_offset + entry_size > len(decrypted_bytes):
                break

            # pubkey_prefix (variable length, typically 1 or 4 bytes)
            pubkey_prefix = decrypted_bytes[entry_offset:entry_offset + pubkey_prefix_length]

            # For display, use first byte as node_id (hash)
            node_hash = pubkey_prefix[0]

            # Skip 0x00 and 0xFF (not valid repeaters)
            if node_hash == 0x00 or node_hash == 0xFF:
                # Skip this entry
                entry_offset += entry_size
                continue

            # Store pubkey_prefix as node_id (hex string)
            node_id = bytes_to_hex(pubkey_prefix) if pubkey_prefix_length > 1 else byte_to_hex(node_hash)
            entry_offset += pubkey_prefix_length

            # heard_seconds_ago (4 bytes, little-endian) - seconds since neighbor was last heard
            heard_seconds_ago = (
                decrypted_bytes[entry_offset] |
                (decrypted_bytes[entry_offset + 1] << 8) |
                (decrypted_bytes[entry_offset + 2] << 16) |
                (decrypted_bytes[entry_offset + 3] << 24)
            )
            entry_offset += 4

            # snr (1 byte, signed int8) - stored directly, not multiplied by 4
            snr_raw = decrypted_bytes[entry_offset]
            snr_signed = snr_raw - 256 if snr_raw > 127 else snr_raw
            snr_db = float(snr_signed)  # Use directly, not divided by 4.0
            entry_offset += 1

            # Calculate timestamps: heard_timestamp = sender_timestamp - heard_seconds_ago
            heard_timestamp = sender_timestamp - heard_seconds_ago if sender_timestamp >= heard_seconds_ago else 0
            # For advert_timestamp, we use heard_timestamp (same value)
            advert_timestamp = heard_timestamp

            neighbors.append(NeighborEntry(
                node_id=node_id,
                advert_timestamp=advert_timestamp,
                heard_timestamp=heard_timestamp,
                snr=snr_db
            ))

        return neighbors, total_count

    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[DecryptionOptions] = None
    ) -> Optional[ResponsePayload]:
        """Decode a Response payload with optional decryption"""
        if options is None:
            options = DecryptionOptions()

        # Extract segment info from options dict if it was passed that way
        include_segments = getattr(options, 'include_segments', False)
        segment_offset = getattr(options, 'segment_offset', 0)

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

                if include_segments:
                    result.segments = [PayloadSegment(
                        name='Invalid Response Data',
                        description='Response payload too short (minimum 4 bytes required)',
                        start_byte=segment_offset,
                        end_byte=(segment_offset + len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
            offset = 0

            # Destination Hash (1 byte)
            destination_hash = byte_to_hex(payload[offset])
            if include_segments:
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
            if include_segments:
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
            if include_segments:
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
            ciphertext_bytes = payload[offset:]

            if include_segments and len(payload) > offset:
                segments.append(PayloadSegment(
                    name='Ciphertext',
                    description='Encrypted response data (tag + content)',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + len(payload) - 1,
                    value=ciphertext
                ))

            # Attempt decryption if key store is provided
            decrypted_data: Optional[Dict[str, Any]] = None
            tag: Optional[int] = None
            neighbors: List[NeighborEntry] = []

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
                # Try to find a node key that matches the source hash
                # For Response payloads: source_hash is the node that sent the response (the responder)
                # The response is encrypted with the responder's private key, so we need the private key
                # of the node whose public key's first byte matches source_hash
                decryption_success = False
                matching_keys_tried = []
                decryption_errors = []

                # For Response decryption using Ed25519 key exchange:
                # According to MeshCore: Response is encrypted by sender using:
                #   shared_secret = ed25519_key_exchange(sender_privkey, receiver_pubkey)
                # So to decrypt, we (receiver) need:
                #   shared_secret = ed25519_key_exchange(our_privkey, sender_pubkey)
                #
                # BUT: The sender encrypts with: sender_privkey + receiver_pubkey
                # So we decrypt with: our_privkey + sender_pubkey (which should give same shared secret)
                #
                # The key store format is: SENDER_PUBKEY:OUR_PRIVKEY
                # We need to find the sender's public key (matches source_hash) and use our private key with it

                # Find all keys and try different combinations
                sender_pubkey = None
                our_privkey = None
                our_pubkey = None  # Our public key (might match destination_hash)

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

                # According to MeshCore: Response encryption uses:
                #   shared_secret = ed25519_key_exchange(sender_privkey, receiver_pubkey)
                # So to decrypt, we need: our_privkey + sender_pubkey
                # BUT: The sender might have used receiver_pubkey (our public key, matching destination_hash)
                # So we should try BOTH:
                #   1. our_privkey + sender_pubkey (standard key exchange)
                #   2. our_privkey + our_pubkey (if sender used our public key - but this won't work for key exchange)

                # Actually, wait - for key exchange to work, we need:
                #   sender: ed25519_key_exchange(sender_privkey, receiver_pubkey)
                #   receiver: ed25519_key_exchange(receiver_privkey, sender_pubkey)
                # These should produce the same shared secret

                # So we need: our_privkey + sender_pubkey
                # But maybe the issue is we're providing the wrong "our_privkey"?
                # Or maybe MeshCore's ed25519_key_exchange does something different?

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
                        # Parse decrypted content immediately
                        # Format: tag (4 bytes, little-endian) + content
                        if len(decrypted_bytes) >= 4:
                            # Parse tag
                            tag = (
                                decrypted_bytes[0] |
                                (decrypted_bytes[1] << 8) |
                                (decrypted_bytes[2] << 16) |
                                (decrypted_bytes[3] << 24)
                            )

                            # Try to parse neighbor table (GetStats response)
                            neighbors, total_count = ResponsePayloadDecoder._parse_neighbors(decrypted_bytes, 0)

                            decrypted_data = {
                                'tag': tag,
                                'raw': bytes_to_hex(decrypted_bytes),
                                'neighborCount': len(neighbors)
                            }
                            if total_count is not None:
                                decrypted_data['totalNeighborCount'] = total_count
                        else:
                            # Decryption succeeded but data is too short
                            decrypted_data = {
                                'raw': bytes_to_hex(decrypted_bytes),
                                'error': 'Decrypted data too short (less than 4 bytes)'
                            }
                    else:
                        if decryption_result.error:
                            decryption_errors.append(f"Key exchange (our_priv + sender_pub): {decryption_result.error}")

                # Try all keys as fallback - maybe the key mapping is different
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

                            # Try: stored_privkey (as our key) + stored_pubkey (as sender's key)
                            # Or: our_privkey + stored_pubkey
                            decryption_result = ChannelCrypto.decrypt_node_message(
                                ciphertext,
                                cipher_mac,
                                our_privkey if our_privkey else stored_privkey,  # Use our private key if we have it
                                node_public_key=None,
                                other_public_key=stored_pubkey  # Try this public key
                            )

                            if decryption_result.success and decryption_result.data:
                                decrypted_bytes = decryption_result.data
                                decryption_success = True
                                break
                            else:
                                if decryption_result.error and "succeeded but MAC" not in decryption_result.error:
                                    # Only log if it's not a MAC failure (MAC failure means key exchange worked)
                                    pass

                # Fallback: try old method if key exchange didn't work
                if not decryption_success:
                    for node_pubkey, node_privkey in options.key_store.node_keys.items():
                        pubkey_bytes = bytes.fromhex(node_pubkey)
                        if len(pubkey_bytes) > 0:
                            pubkey_first_byte = byte_to_hex(pubkey_bytes[0])
                            should_try = (pubkey_first_byte == source_hash or
                                         pubkey_first_byte == destination_hash or
                                         len(options.key_store.node_keys) == 1)

                            if should_try and not any(m['pubkey'] == node_pubkey[:16] + '...' for m in matching_keys_tried):
                                # Try old fallback methods
                                decryption_result = ChannelCrypto.decrypt_node_message(
                                    ciphertext,
                                    cipher_mac,
                                    node_privkey,
                                    node_public_key=node_pubkey,
                                    other_public_key=None  # No key exchange, use fallback methods
                                )

                                if decryption_result.success and decryption_result.data:
                                    decrypted_bytes = decryption_result.data
                                    decryption_success = True
                                    break

                                if decryption_result.error:
                                    decryption_errors.append(f"Key matching {pubkey_first_byte}: {decryption_result.error}")

                            if decryption_result.success and decryption_result.data:
                                decrypted_bytes = decryption_result.data
                                decryption_success = True

                                # Parse decrypted content
                                # Format: tag (4 bytes, little-endian) + content
                                if len(decrypted_bytes) >= 4:
                                    # Parse tag
                                    tag = (
                                        decrypted_bytes[0] |
                                        (decrypted_bytes[1] << 8) |
                                        (decrypted_bytes[2] << 16) |
                                        (decrypted_bytes[3] << 24)
                                    )

                                    # Try to parse neighbor table (GetStats response)
                                    neighbors, total_count = ResponsePayloadDecoder._parse_neighbors(decrypted_bytes, 0)

                                    decrypted_data = {
                                        'tag': tag,
                                        'raw': bytes_to_hex(decrypted_bytes),
                                        'neighborCount': len(neighbors)
                                    }
                                    if total_count is not None:
                                        decrypted_data['totalNeighborCount'] = total_count

                                break
                            else:
                                # Key matched hash but decryption failed
                                if decryption_result.error:
                                    decryption_errors.append(f"Key matching {pubkey_first_byte} ({'source' if pubkey_first_byte == source_hash else 'destination'} hash): {decryption_result.error}")

                # If hash-based matching failed, try all keys as fallback
                # (in case of hash collisions or key format issues)
                if not decryption_success and len(matching_keys_tried) > 0:
                    # We already tried matching keys, now try all remaining keys
                    for node_pubkey, node_privkey in options.key_store.node_keys.items():
                        pubkey_bytes = bytes.fromhex(node_pubkey)
                        if len(pubkey_bytes) > 0:
                            pubkey_first_byte = byte_to_hex(pubkey_bytes[0])
                            # Skip keys we already tried
                            if pubkey_first_byte != source_hash and pubkey_first_byte != destination_hash:
                                decryption_result = ChannelCrypto.decrypt_node_message(
                                    ciphertext,
                                    cipher_mac,
                                    node_privkey
                                )

                                if decryption_result.success and decryption_result.data:
                                    decrypted_bytes = decryption_result.data
                                    decryption_success = True

                                    # Parse decrypted content
                                    if len(decrypted_bytes) >= 4:
                                        tag = (
                                            decrypted_bytes[0] |
                                            (decrypted_bytes[1] << 8) |
                                            (decrypted_bytes[2] << 16) |
                                            (decrypted_bytes[3] << 24)
                                        )

                                        # Try to parse neighbor table
                                        neighbors, total_count = ResponsePayloadDecoder._parse_neighbors(decrypted_bytes, 0)

                                        decrypted_data = {
                                            'tag': tag,
                                            'raw': bytes_to_hex(decrypted_bytes),
                                            'neighborCount': len(neighbors),
                                            'note': f'Decrypted with key hash {pubkey_first_byte} (did not match source/dest hash)'
                                        }
                                        if total_count is not None:
                                            decrypted_data['totalNeighborCount'] = total_count

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
                        error_msg += 'Possible causes: 1) MeshCore uses a different key derivation method than implemented, 2) Encryption key is stored separately (not derived from Ed25519 keys), 3) Key format mismatch. '
                        error_msg += 'Please check MeshCore source code (Mesh.cpp) for the exact encryption key derivation algorithm used for Response payloads.'

                    decrypted_data = {'error': error_msg}

            # Ensure decrypted_data is always set (fallback)
            if decrypted_data is None:
                decrypted_data = {'error': 'Decryption was attempted but no result was set. This is a bug.'}

            result = ResponsePayload(
                payload_type=PayloadType.Response,
                version=PayloadVersion.Version1,
                is_valid=True,
                destination_hash=destination_hash,
                source_hash=source_hash,
                cipher_mac=cipher_mac,
                ciphertext=ciphertext,
                ciphertext_length=len(payload) - 4,
                decrypted=decrypted_data,
                tag=tag,
                neighbors=neighbors
            )

            if include_segments:
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
