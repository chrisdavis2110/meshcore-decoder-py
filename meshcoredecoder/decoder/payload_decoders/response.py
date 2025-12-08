"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Response payload decoder with decryption support
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import ResponsePayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...types.crypto import DecryptionOptions
from ...utils.hex import byte_to_hex, bytes_to_hex, hex_to_bytes
from ...crypto.channel_crypto import ChannelCrypto


class ResponsePayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[ResponsePayload]:
        """Decode a Response payload with optional decryption"""
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

                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid Response Data',
                        description='Response payload too short (minimum 4 bytes required)',
                        start_byte=options.get('segment_offset', 0),
                        end_byte=(options.get('segment_offset', 0) + len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)
            offset = 0

            # Destination Hash (1 byte)
            destination_hash = byte_to_hex(payload[offset])
            if options.get('include_segments'):
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
            if options.get('include_segments'):
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
            if options.get('include_segments'):
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
            if options.get('include_segments') and len(payload) > offset:
                segments.append(PayloadSegment(
                    name='Ciphertext',
                    description='Encrypted response data (tag + content)',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + len(payload) - 1,
                    value=ciphertext
                ))

            result = ResponsePayload(
                payload_type=PayloadType.Response,
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
                        if not result.decrypted and hasattr(key_store, 'peer_public_keys') and key_store.peer_public_keys:
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
                                        break
                                if result.decrypted:
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
