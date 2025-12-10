"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Response payload decoder with decryption support
"""

from typing import Optional, Dict, Any, List, Union
from ...types.payloads import ResponsePayload, NeighborEntry
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...types.crypto import DecryptionOptions
from ...utils.hex import byte_to_hex, bytes_to_hex, hex_to_bytes
from ...crypto.channel_crypto import ChannelCrypto


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
            # Use decryption_options if available, otherwise check if options is a DecryptionOptions object
            effective_options = decryption_options if decryption_options else (options if isinstance(options, DecryptionOptions) else None)

            if not effective_options:
                decrypted_data = {'error': 'No decryption options provided. Use --node-key PUBKEY:PRIVKEY to provide decryption keys.'}
            elif not effective_options.attempt_decryption:
                decrypted_data = {'error': 'Decryption disabled in options'}
            elif not effective_options.key_store:
                decrypted_data = {'error': 'No key store provided. Use --node-key PUBKEY:PRIVKEY to provide decryption keys.'}
            elif len(ciphertext_bytes) == 0:
                decrypted_data = {'error': 'No ciphertext to decrypt'}
            elif effective_options.attempt_decryption and effective_options.key_store and len(ciphertext_bytes) > 0:
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
                for stored_pubkey, stored_privkey in effective_options.key_store.node_keys.items():
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

                            # Extract content (bytes 4+)
                            content_bytes = decrypted_bytes[4:] if len(decrypted_bytes) > 4 else b''

                            # Parse response content to determine type
                            parsed_content = ResponsePayloadDecoder._parse_response_content(tag, content_bytes)

                            # Try to parse neighbor table (for GetNeighbours responses)
                            neighbors, total_count = ResponsePayloadDecoder._parse_neighbors(decrypted_bytes, 0)

                            # Build decrypted_data with parsed content
                            decrypted_data = {
                                'tag': tag,
                                'raw': bytes_to_hex(decrypted_bytes),
                                'content': parsed_content
                            }
                            if len(neighbors) > 0:
                                decrypted_data['neighborCount'] = len(neighbors)
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
                    for stored_pubkey, stored_privkey in effective_options.key_store.node_keys.items():
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
                                # Parse the decrypted content
                                if len(decrypted_bytes) >= 4:
                                    tag = (
                                        decrypted_bytes[0] |
                                        (decrypted_bytes[1] << 8) |
                                        (decrypted_bytes[2] << 16) |
                                        (decrypted_bytes[3] << 24)
                                    )
                                    content_bytes = decrypted_bytes[4:] if len(decrypted_bytes) > 4 else b''
                                    parsed_content = ResponsePayloadDecoder._parse_response_content(tag, content_bytes)
                                    neighbors, total_count = ResponsePayloadDecoder._parse_neighbors(decrypted_bytes, 0)

                                    decrypted_data = {
                                        'tag': tag,
                                        'raw': bytes_to_hex(decrypted_bytes),
                                        'content': parsed_content
                                    }
                                    if len(neighbors) > 0:
                                        decrypted_data['neighborCount'] = len(neighbors)
                                    if total_count is not None:
                                        decrypted_data['totalNeighborCount'] = total_count
                                break
                            else:
                                if decryption_result.error and "succeeded but MAC" not in decryption_result.error:
                                    # Only log if it's not a MAC failure (MAC failure means key exchange worked)
                                    pass

                # Fallback: try old method if key exchange didn't work
                if not decryption_success:
                    for node_pubkey, node_privkey in effective_options.key_store.node_keys.items():
                        pubkey_bytes = bytes.fromhex(node_pubkey)
                        if len(pubkey_bytes) > 0:
                            pubkey_first_byte = byte_to_hex(pubkey_bytes[0])
                            should_try = (pubkey_first_byte == source_hash or
                                         pubkey_first_byte == destination_hash or
                                         len(effective_options.key_store.node_keys) == 1)

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

                                    # Extract content (bytes 4+)
                                    content_bytes = decrypted_bytes[4:] if len(decrypted_bytes) > 4 else b''

                                    # Parse response content to determine type
                                    parsed_content = ResponsePayloadDecoder._parse_response_content(tag, content_bytes)

                                    # Try to parse neighbor table
                                    neighbors, total_count = ResponsePayloadDecoder._parse_neighbors(decrypted_bytes, 0)

                                    decrypted_data = {
                                        'tag': tag,
                                        'raw': bytes_to_hex(decrypted_bytes),
                                        'content': parsed_content
                                    }
                                    if len(neighbors) > 0:
                                        decrypted_data['neighborCount'] = len(neighbors)
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
                    for node_pubkey, node_privkey in effective_options.key_store.node_keys.items():
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

                                        # Extract content (bytes 4+)
                                        content_bytes = decrypted_bytes[4:] if len(decrypted_bytes) > 4 else b''

                                        # Parse response content to determine type
                                        parsed_content = ResponsePayloadDecoder._parse_response_content(tag, content_bytes)

                                        # Try to parse neighbor table
                                        neighbors, total_count = ResponsePayloadDecoder._parse_neighbors(decrypted_bytes, 0)

                                        decrypted_data = {
                                            'tag': tag,
                                            'raw': bytes_to_hex(decrypted_bytes),
                                            'content': parsed_content,
                                            'note': f'Decrypted with key hash {pubkey_first_byte} (did not match source/dest hash)'
                                        }
                                        if len(neighbors) > 0:
                                            decrypted_data['neighborCount'] = len(neighbors)
                                        if total_count is not None:
                                            decrypted_data['totalNeighborCount'] = total_count

                                    break

                if not decryption_success:
                    # Build detailed error message
                    error_msg = 'Decryption failed'
                    if len(matching_keys_tried) == 0:
                        error_msg += f': No node key found matching source hash ({source_hash}) or destination hash ({destination_hash})'
                        error_msg += f'. Available keys: {len(effective_options.key_store.node_keys)} key(s) provided'
                        if len(effective_options.key_store.node_keys) > 0:
                            available_hashes = []
                            for pk in effective_options.key_store.node_keys.keys():
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

            # Extract tag from decrypted_data if available
            result_tag = tag
            if decrypted_data and 'tag' in decrypted_data:
                result_tag = decrypted_data['tag']

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
                tag=result_tag,
                neighbors=neighbors
            )

            # Attempt decryption if key store is provided (second path - try if first path failed or didn't run)
            # Check if first path succeeded by looking for valid content (not error and not unknown type)
            first_path_succeeded = (
                result.decrypted and
                'content' in result.decrypted and
                result.decrypted.get('content', {}).get('type') != 'unknown' and
                'error' not in result.decrypted
            )

            if not first_path_succeeded and decryption_options and decryption_options.key_store and decryption_options.attempt_decryption:
                key_store = decryption_options.key_store

                # Try to decrypt using shared secrets or calculate from node keys
                shared_secrets = key_store.shared_secrets if hasattr(key_store, 'shared_secrets') else {}
                node_keys = key_store.node_keys if hasattr(key_store, 'node_keys') else {}

                # Try all shared secrets first (most efficient)
                for peer_pub_key, shared_secret_hex in shared_secrets.items():
                    shared_secret = hex_to_bytes(shared_secret_hex)
                    decryption_result = ChannelCrypto.decrypt_response_payload(
                        ciphertext,
                        cipher_mac,
                        shared_secret
                    )

                    if decryption_result.success and decryption_result.data:
                        # Parse response content based on the guide
                        parsed_content = ResponsePayloadDecoder._parse_response_content(
                            decryption_result.data['tag'],
                            decryption_result.data['content']
                        )
                        result.decrypted = {
                            'tag': decryption_result.data['tag'],
                            'content': parsed_content
                        }
                        result.tag = decryption_result.data['tag']
                        break  # Stop trying once we find a working key

                # If shared secrets didn't work, try calculating from node keys
                if (not result.decrypted or
                    (result.decrypted.get('content', {}).get('type') == 'unknown') or
                    'error' in result.decrypted) and node_keys:
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
                                decryption_result = ChannelCrypto.decrypt_response_payload(
                                    ciphertext,
                                    cipher_mac,
                                    shared_secret
                                )

                                if decryption_result.success and decryption_result.data:
                                    # Parse response content
                                    parsed_content = ResponsePayloadDecoder._parse_response_content(
                                        decryption_result.data['tag'],
                                        decryption_result.data['content']
                                    )
                                    result.decrypted = {
                                        'tag': decryption_result.data['tag'],
                                        'content': parsed_content
                                    }
                                    break

                        # If no peer keys matched by hash, try all peer keys anyway
                        if ((not result.decrypted or
                             (result.decrypted.get('content', {}).get('type') == 'unknown') or
                             'error' in result.decrypted) and
                            hasattr(key_store, 'peer_public_keys') and key_store.peer_public_keys):
                            for peer_pub_key_hex in key_store.peer_public_keys:
                                shared_secret = ChannelCrypto.calculate_shared_secret(
                                    peer_pub_key_hex,
                                    my_priv_key_hex
                                )
                                if shared_secret:
                                    decryption_result = ChannelCrypto.decrypt_response_payload(
                                        ciphertext,
                                        cipher_mac,
                                        shared_secret
                                    )
                                    if decryption_result.success and decryption_result.data:
                                        parsed_content = ResponsePayloadDecoder._parse_response_content(
                                            decryption_result.data['tag'],
                                            decryption_result.data['content']
                                        )
                                        result.decrypted = {
                                            'tag': decryption_result.data['tag'],
                                            'content': parsed_content
                                        }
                                        result.tag = decryption_result.data['tag']
                                        break
                                if result.decrypted and result.decrypted.get('content', {}).get('type') != 'unknown':
                                    break

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

    @staticmethod
    def _parse_response_content(tag: int, content: bytes) -> Dict[str, Any]:
        """
        Parse response content based on request type
        According to packet_breakdown_guide.md, response content varies by request type

        Note: The tag is extracted from bytes 0-3 of the decrypted data (usually sender_timestamp).
        The content parameter is bytes 4+ of the decrypted data.

        For GET_NEIGHBOURS: content = neighbours_count(2) + results_count(2) + results_buffer(M)
        For other types: content may start with tag again, then the actual response data.
        """
        parsed = {
            'tag': tag,
            'raw': bytes_to_hex(content)
        }

        if len(content) < 2:
            parsed['error'] = 'Content too short'
            return parsed

        # Telemetry check: LPP format - small size, starts with channel byte (1-255)
        # Note: Telemetry can be any length, including multiples of 7, so we don't check % 7
        # Key indicators: small size (< 40 bytes), starts with valid channel byte (1-255)
        # We check this early to avoid false matches with access list (which uses multiples of 7)
        content_len = len(content)
        if content_len >= 3 and content_len < 40 and content[0] > 0 and content[0] <= 255:
            # Additional check: if it's a multiple of 7, verify it's not access list by checking structure
            # Access list entries are 7 bytes each with specific patterns
            # Telemetry LPP format: [channel][type][data]... where channel is 1-255
            # If content_len % 7 == 0, we need to distinguish from access list
            # Access list typically has entries starting with known pubkey prefixes
            # Telemetry has channel bytes at offsets 0, then after each LPP entry
            if content_len % 7 == 0:
                # Could be access list - check if it matches access list pattern
                # Access list: entries of 7 bytes, first byte often matches known prefixes (2e, f6, 05, 02, 96, c1, 35)
                # Telemetry: channel bytes are 1-255, but not necessarily matching those specific values
                # For now, if it's a multiple of 7 and small, check if first byte looks like a channel (1-255)
                # and doesn't match common access list prefixes
                expected_access_list_prefixes = [0x2e, 0xf6, 0x05, 0x02, 0x96, 0xc1, 0x35]
                first_byte = content[0]
                # If first byte matches access list pattern at multiple offsets, it's likely access list
                matches_access_list_pattern = sum(1 for i in range(min(7, content_len // 7))
                                                  if i < len(expected_access_list_prefixes) and
                                                  content[i * 7] == expected_access_list_prefixes[i]) >= 3
                if not matches_access_list_pattern:
                    # Doesn't match access list pattern, likely telemetry
                    parsed['type'] = 'telemetry'
                    parsed['tag'] = tag
                    parsed['telemetry_data'] = bytes_to_hex(content)
                    return parsed
            else:
                # Not a multiple of 7, definitely not access list, likely telemetry
                parsed['type'] = 'telemetry'
                parsed['tag'] = tag
                parsed['telemetry_data'] = bytes_to_hex(content)
                return parsed

        # Try to parse as Login Response (from ANON_REQ login)
        # Structure: timestamp(4) + response_code(1) + legacy_keepalive(1) + is_admin(1) + permissions(1) + random_blob(4) + firmware_version(1) = 13 bytes
        # The tag from decryption is the timestamp, so content should be 9 bytes: response_code + legacy_keepalive + is_admin + permissions + random_blob + firmware_version
        # OR: if tag is repeated, content is 13 bytes (with timestamp)
        # OR: if structure is slightly different, content might be 12 bytes (timestamp in content, but firmware_version missing or padding)
        # Try: 9 bytes (tag is timestamp), 12 bytes (timestamp in content, no firmware_version), or 13 bytes (full structure)
        # Also try: content might have padding, so check if first 9 bytes match the structure
        if len(content) >= 9:
            # Try parsing as 9-byte structure (tag is timestamp)
            # Check if first byte is reasonable response_code (0x00 = success, or small non-zero = failure)
            response_code_candidate = content[0]
            legacy_keepalive_candidate = content[1]
            is_admin_candidate = content[2]
            permissions_candidate = content[3]

            # Heuristic: if response_code is 0x00 or small value, and is_admin is 0 or 1, it's likely a login response
            if (response_code_candidate <= 0x7F and
                (is_admin_candidate == 0 or is_admin_candidate == 1) and
                len(content) <= 13):  # Allow up to 13 bytes (with possible padding)
                # Parse as 9-byte structure (tag is timestamp)
                timestamp = tag  # Use tag as timestamp
                response_code = response_code_candidate
                legacy_keepalive = legacy_keepalive_candidate
                is_admin = is_admin_candidate
                permissions = permissions_candidate
                random_blob = (
                    content[4] |
                    (content[5] << 8) |
                    (content[6] << 16) |
                    (content[7] << 24)
                )
                firmware_version = content[8] if len(content) > 8 else 0

                parsed['type'] = 'login_response'
                parsed['timestamp'] = timestamp
                parsed['response_code'] = response_code
                parsed['legacy_keepalive'] = legacy_keepalive
                parsed['is_admin'] = is_admin
                parsed['permissions'] = permissions
                parsed['random_blob'] = bytes_to_hex(content[4:8])
                parsed['firmware_version'] = firmware_version
                if len(content) > 9:
                    parsed['note'] = f'Extra {len(content) - 9} bytes after structure (padding?)'
                return parsed

        if len(content) == 9:
            # Tag is not repeated - tag is the timestamp, content starts with response_code
            timestamp = tag  # Use tag as timestamp
            response_code = content[0]
            legacy_keepalive = content[1]
            is_admin = content[2]
            permissions = content[3]
            random_blob = (
                content[4] |
                (content[5] << 8) |
                (content[6] << 16) |
                (content[7] << 24)
            )
            firmware_version = content[8]

            parsed['type'] = 'login_response'
            parsed['timestamp'] = timestamp
            parsed['response_code'] = response_code
            parsed['legacy_keepalive'] = legacy_keepalive
            parsed['is_admin'] = is_admin
            parsed['permissions'] = permissions
            parsed['random_blob'] = bytes_to_hex(content[4:8])
            parsed['firmware_version'] = firmware_version
            return parsed
        elif len(content) == 12:
            # 12 bytes: timestamp(4) + response_code(1) + legacy_keepalive(1) + is_admin(1) + permissions(1) + random_blob(4) (firmware_version missing or included in random_blob)
            timestamp = (
                content[0] |
                (content[1] << 8) |
                (content[2] << 16) |
                (content[3] << 24)
            )
            response_code = content[4]
            legacy_keepalive = content[5]
            is_admin = content[6]
            permissions = content[7]
            random_blob = (
                content[8] |
                (content[9] << 8) |
                (content[10] << 16) |
                (content[11] << 24)
            )
            firmware_version = 0  # Not present in 12-byte version

            parsed['type'] = 'login_response'
            parsed['timestamp'] = timestamp
            parsed['response_code'] = response_code
            parsed['legacy_keepalive'] = legacy_keepalive
            parsed['is_admin'] = is_admin
            parsed['permissions'] = permissions
            parsed['random_blob'] = bytes_to_hex(content[8:12])
            parsed['firmware_version'] = firmware_version
            parsed['note'] = 'Firmware version not present (12-byte structure)'
            return parsed
        elif len(content) == 13:
            timestamp = (
                content[0] |
                (content[1] << 8) |
                (content[2] << 16) |
                (content[3] << 24)
            )
            response_code = content[4]
            legacy_keepalive = content[5]
            is_admin = content[6]
            permissions = content[7]
            random_blob = (
                content[8] |
                (content[9] << 8) |
                (content[10] << 16) |
                (content[11] << 24)
            )
            firmware_version = content[12]

            # Heuristic: check for reasonable values
            # response_code: 0x00 = success, non-zero = failure (but could be any value)
            # legacy_keepalive: should be 0, but might not be
            # is_admin: should be 0 or 1, but might be other values
            # permissions: should have lower 2 bits as role (0x01, 0x02, 0x03), but might be other values
            # If it's exactly 13 bytes, it's likely a login response
            parsed['type'] = 'login_response'
            parsed['timestamp'] = timestamp
            parsed['response_code'] = response_code
            parsed['legacy_keepalive'] = legacy_keepalive
            parsed['is_admin'] = is_admin
            parsed['permissions'] = permissions
            parsed['random_blob'] = bytes_to_hex(content[8:12])
            parsed['firmware_version'] = firmware_version
            return parsed

        # First, check if tag is repeated in content (indicates min_max_avg, access_list, or stats)
        # This should be checked BEFORE trying to parse as neighbours, since neighbours doesn't repeat the tag
        tag_in_content = None
        if len(content) >= 4:
            tag_in_content = (
                content[0] |
                (content[1] << 8) |
                (content[2] << 16) |
                (content[3] << 24)
            )

        # Telemetry parsing is now done at the very beginning (line 270) to avoid false matches

        # Try to parse as GET_NEIGHBOURS response (most structured)
        # Note: The tag is already the sender_timestamp from bytes 0-3 of decrypted data
        # Content starts at bytes 4+ which is: neighbours_count(2) + results_count(2) + results_buffer(M)
        # Structure: neighbours_count(2) + results_count(2) + results_buffer(M)
        # However, sometimes results_count might be stored as a single byte if < 256
        # IMPORTANT: Only try neighbours parsing if tag is NOT repeated in content
        # (Telemetry, stats, etc. repeat the tag, but neighbours does not)
        if len(content) >= 4 and (tag_in_content is None or tag_in_content != tag):
            neighbours_count = content[0] | (content[1] << 8)
            results_count_uint16 = content[2] | (content[3] << 8)
            results_count_uint8 = content[2]  # Try as single byte

            # Choose the most reasonable interpretation
            # If uint16_t gives unreasonably high value (> 255), try uint8_t
            # Also check if results_buffer has enough data for the claimed count
            results_buffer_size = len(content) - 4
            results_count = results_count_uint16

            # If results_count seems too high or doesn't match available data, try single byte
            if results_count_uint16 > 255:
                # Check if uint8_t makes more sense
                # Minimum entry size is 6 bytes (1 byte pubkey + 4 bytes heard + 1 byte snr)
                min_entry_size = 6
                max_entries_uint8 = results_buffer_size // min_entry_size
                max_entries_uint16 = results_buffer_size // min_entry_size

                if results_count_uint8 <= max_entries_uint8 and results_count_uint8 > 0:
                    # uint8_t interpretation makes more sense
                    results_count = results_count_uint8
                    results_buffer_start = 3  # results_buffer starts at byte 3 (after neighbours_count + results_count byte)
                else:
                    results_buffer_start = 4  # Standard: results_buffer starts at byte 4
            else:
                results_buffer_start = 4  # Standard: results_buffer starts at byte 4

            # Verify this looks like a neighbours response
            # results_count is uint16_t (0-65535) or uint8_t (0-255)
            # For GET_NEIGHBOURS, we expect reasonable values
            # Note: neighbours_count can be 0 if no neighbors available
            # If neighbours_count is 0, results_count should also be 0
            # Also, results_count should not exceed neighbours_count
            # Stricter validation: neighbours_count should be reasonable (< 1000 typically)
            # This helps avoid false matches with telemetry/stats data
            if (0 <= results_count <= 1000 and 0 <= neighbours_count <= 1000 and
                ((neighbours_count == 0 and results_count == 0) or
                 (neighbours_count > 0 and results_count > 0 and results_count <= neighbours_count))):
                # Parse neighbor entries from results_buffer
                # Each entry: pubkey_prefix[K] + heard_seconds_ago(4) + snr(1)
                # K is variable (pubkey_prefix_length from request), try common values: 4, 6, 8, 32, 1, 2
                # Try longer lengths first as they're more common
                neighbors = []
                pubkey_lengths_to_try = [4, 6, 8, 32, 1, 2]  # Try longer lengths first (more common)

                for pubkey_len in pubkey_lengths_to_try:
                    neighbors = []
                    offset = results_buffer_start
                    entry_size = pubkey_len + 4 + 1  # pubkey_prefix + heard_seconds_ago + snr

                    while offset + entry_size <= len(content) and len(neighbors) < results_count:
                        pubkey_prefix = bytes_to_hex(content[offset:offset + pubkey_len])
                        heard_seconds_ago = (
                            content[offset + pubkey_len] |
                            (content[offset + pubkey_len + 1] << 8) |
                            (content[offset + pubkey_len + 2] << 16) |
                            (content[offset + pubkey_len + 3] << 24)
                        )
                        snr_raw = content[offset + pubkey_len + 4]
                        snr = snr_raw - 256 if snr_raw > 127 else snr_raw

                        # Validate that values are reasonable
                        # heard_seconds_ago should be reasonable (not more than a few years = ~100 million seconds)
                        # SNR should be in reasonable range (int8_t: -128 to 127, but typically -60 to 60 for radio)
                        is_reasonable = (
                            heard_seconds_ago < 100000000 and  # Less than ~3 years
                            -60 <= snr <= 60  # Reasonable SNR range (slightly wider to catch edge cases)
                        )

                        neighbors.append({
                            'pubkey_prefix': pubkey_prefix,
                            'pubkey_prefix_length': pubkey_len,
                            'heard_seconds_ago': heard_seconds_ago,
                            'snr': snr
                        })
                        offset += entry_size

                    # If we successfully parsed all expected neighbors with reasonable values, use this length
                    if len(neighbors) == results_count:
                        # Check if all values are reasonable
                        all_reasonable = all(
                            n['heard_seconds_ago'] < 100000000 and -60 <= n['snr'] <= 60
                            for n in neighbors
                        )
                        if all_reasonable:
                            # Only classify as neighbours if we successfully parsed reasonable entries
                            parsed['type'] = 'neighbours'
                            parsed['sender_timestamp'] = tag  # Tag is the sender_timestamp
                            parsed['neighbours_count'] = neighbours_count
                            parsed['results_count'] = results_count
                            parsed['neighbors'] = neighbors
                            parsed['pubkey_prefix_length'] = pubkey_len
                            return parsed
                        # If values aren't reasonable, continue trying other lengths
                    elif len(neighbors) > 0 and offset <= len(content):
                        # Partial match - check if values are reasonable
                        all_reasonable = all(
                            n['heard_seconds_ago'] < 100000000 and -60 <= n['snr'] <= 60
                            for n in neighbors
                        )
                        if all_reasonable:
                            # Only classify as neighbours if we successfully parsed reasonable entries
                            parsed['type'] = 'neighbours'
                            parsed['sender_timestamp'] = tag  # Tag is the sender_timestamp
                            parsed['neighbours_count'] = neighbours_count
                            parsed['results_count'] = results_count
                            parsed['neighbors'] = neighbors
                            parsed['pubkey_prefix_length'] = pubkey_len
                            return parsed

                # If no length worked perfectly, use the first one that gave results (but only if values are reasonable)
                if neighbors:
                    all_reasonable = all(
                        n['heard_seconds_ago'] < 100000000 and -60 <= n['snr'] <= 60
                        for n in neighbors
                    )
                    if all_reasonable:
                        parsed['type'] = 'neighbours'
                        parsed['sender_timestamp'] = tag
                        parsed['neighbours_count'] = neighbours_count
                        parsed['results_count'] = results_count
                        parsed['neighbors'] = neighbors
                        parsed['pubkey_prefix_length'] = 'unknown (tried 1, 2, 4, 6, 8, 32)'
                        return parsed

                # If we couldn't parse any reasonable neighbors, don't classify as neighbours
                # Fall through to try other response types

        # Telemetry parsing is now done earlier (before neighbours check)

        # Try to parse as GET_AVG_MIN_MAX response
        # Structure: tag(4) + timestamp(4) + data(M)
        if len(content) >= 8:
            tag_in_content = (
                content[0] |
                (content[1] << 8) |
                (content[2] << 16) |
                (content[3] << 24)
            )
            current_timestamp = (
                content[4] |
                (content[5] << 8) |
                (content[6] << 16) |
                (content[7] << 24)
            )
            # Verify this looks like timestamps (reasonable values)
            if tag_in_content == tag and 1000000000 < current_timestamp < 4294967295:
                parsed['type'] = 'min_max_avg'
                parsed['tag'] = tag_in_content
                parsed['current_timestamp'] = current_timestamp
                parsed['data'] = bytes_to_hex(content[8:])
                return parsed

        # Try to parse as GET_STATS response (check AFTER telemetry)
        # Structure: tag(4) + stats(M) OR just stats(M) if tag is not repeated
        # Stats data is typically 52 bytes (ServerStats or RepeaterStats)
        # IMPORTANT: Skip if content length is a multiple of 7 (Access List uses multiples of 7)
        if len(content) >= 4:
            tag_in_content = (
                content[0] |
                (content[1] << 8) |
                (content[2] << 16) |
                (content[3] << 24)
            )
            # If tag matches and remaining bytes are NOT a multiple of 7, it's likely stats
            if tag_in_content == tag:
                remaining = len(content) - 4
                # Stats is typically 40-60 bytes, and NOT a multiple of 7 (Access List uses multiples of 7)
                if 40 <= remaining <= 60 and remaining % 7 != 0:
                    parsed['type'] = 'stats'
                    parsed['tag'] = tag_in_content
                    parsed['stats_data'] = bytes_to_hex(content[4:])
                    return parsed
            # If tag doesn't match, check if content length matches stats structure
            # Stats is typically 40-60 bytes and NOT a multiple of 7 (Access List uses multiples of 7)
            elif 40 <= len(content) <= 60 and len(content) % 7 != 0:
                # This is likely stats data (tag not repeated)
                parsed['type'] = 'stats'
                parsed['tag'] = tag  # Use the tag from decryption
                parsed['stats_data'] = bytes_to_hex(content)  # All content is stats data
                parsed['note'] = 'Stats data (tag not repeated in content)'
                return parsed

        # Default: just return raw data
        parsed['type'] = 'unknown'
        parsed['note'] = 'Could not determine response type - content structure unknown'
        return parsed
