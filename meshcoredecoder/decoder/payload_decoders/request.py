"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Request payload decoder
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import RequestPayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion, RequestType
from ...types.crypto import DecryptionOptions
from ...utils.hex import bytes_to_hex, hex_to_bytes
from ...crypto.channel_crypto import ChannelCrypto


class RequestPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[RequestPayload]:
        """Decode a Request payload"""
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
            # Based on MeshCore payloads.md - Request payload structure:
            # - destination hash (1 byte)
            # - source hash (1 byte)
            # - cipher MAC (2 bytes)
            # - ciphertext (rest of payload) - contains encrypted timestamp, request type, and request data

            if len(payload) < 4:
                result = RequestPayload(
                    payload_type=PayloadType.Request,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['Request payload too short (minimum 4 bytes: dest hash + source hash + MAC)'],
                    timestamp=0,
                    request_type=RequestType.GetStats,
                    request_data='',
                    destination_hash='',
                    source_hash='',
                    cipher_mac='',
                    ciphertext=''
                )

                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid Request Data',
                        description='Request payload too short (minimum 4 bytes required: 1 for dest hash + 1 for source hash + 2 for MAC)',
                        start_byte=options.get('segment_offset', 0),
                        end_byte=(options.get('segment_offset', 0) + len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)
            offset = 0

            # Parse destination hash (1 byte)
            destination_hash = bytes_to_hex(payload[offset:offset + 1])

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
            source_hash = bytes_to_hex(payload[offset:offset + 1])

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
                    description=f'Encrypted message data ({len(payload) - offset} bytes). Contains encrypted plaintext with timestamp, request type, and request data',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + len(payload) - 1,
                    value=ciphertext
                ))

            result = RequestPayload(
                payload_type=PayloadType.Request,
                version=PayloadVersion.Version1,
                is_valid=True,
                timestamp=0,  # Will be decrypted if key is available
                request_type=RequestType.GetStats,  # Default value, will be overridden if decrypted
                request_data='',
                destination_hash=destination_hash,
                source_hash=source_hash,
                cipher_mac=cipher_mac,
                ciphertext=ciphertext
            )

            # Attempt decryption if key store is provided
            if decryption_options and decryption_options.key_store and decryption_options.attempt_decryption:
                # Try to decrypt using shared secrets or calculate from node keys
                key_store = decryption_options.key_store

                # First, try pre-stored shared secrets
                shared_secrets = key_store.shared_secrets if hasattr(key_store, 'shared_secrets') else {}

                # Also try to calculate shared secrets from node keys if we have them
                # Note: This requires knowing the peer's public key, which we don't have from just the hash
                # So we'll try all node keys we have
                node_keys = key_store.node_keys if hasattr(key_store, 'node_keys') else {}

                # Try all shared secrets first (most efficient)
                for peer_pub_key, shared_secret_hex in shared_secrets.items():
                    shared_secret = hex_to_bytes(shared_secret_hex)
                    decryption_result = ChannelCrypto.decrypt_request_payload(
                        ciphertext,
                        cipher_mac,
                        shared_secret
                    )

                    if decryption_result.success and decryption_result.data:
                        RequestPayloadDecoder._apply_decrypted_data(result, decryption_result.data)
                        break  # Stop trying once we find a working key

                # If shared secrets didn't work, try calculating from node keys
                # We need to match the source hash to a peer public key and calculate shared secret
                if not result.decrypted and node_keys:
                    # First, verify we have a node key that matches the destination hash
                    # (we're the recipient, so our public key should match destination_hash)
                    my_node_key = None
                    destination_hash_byte = hex_to_bytes(destination_hash)[0]

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
                                decryption_result = ChannelCrypto.decrypt_request_payload(
                                    ciphertext,
                                    cipher_mac,
                                    shared_secret
                                )

                                if decryption_result.success and decryption_result.data:
                                    RequestPayloadDecoder._apply_decrypted_data(result, decryption_result.data)
                                    break

                        # If no peer keys matched by hash, try all peer keys anyway
                        # (in case of hash collision or if hash matching failed)
                        if not result.decrypted and hasattr(key_store, 'peer_public_keys') and key_store.peer_public_keys:
                            for peer_pub_key_hex in key_store.peer_public_keys:
                                shared_secret = ChannelCrypto.calculate_shared_secret(
                                    peer_pub_key_hex,
                                    my_priv_key_hex
                                )
                                if shared_secret:
                                    decryption_result = ChannelCrypto.decrypt_request_payload(
                                        ciphertext,
                                        cipher_mac,
                                        shared_secret
                                    )
                                    if decryption_result.success and decryption_result.data:
                                        RequestPayloadDecoder._apply_decrypted_data(result, decryption_result.data)
                                        break
                                if result.decrypted:
                                    break

                    # Also try if we have node keys but didn't match destination hash
                    # (maybe the user provided the wrong node key, but we should still try)
                    if not result.decrypted and node_keys and hasattr(key_store, 'peer_public_keys') and key_store.peer_public_keys:
                        # Try all combinations of node keys and peer keys
                        for my_pub_key_hex, my_priv_key_hex in node_keys.items():
                            for peer_pub_key_hex in key_store.peer_public_keys:
                                shared_secret = ChannelCrypto.calculate_shared_secret(
                                    peer_pub_key_hex,
                                    my_priv_key_hex
                                )
                                if shared_secret:
                                    decryption_result = ChannelCrypto.decrypt_request_payload(
                                        ciphertext,
                                        cipher_mac,
                                        shared_secret
                                    )
                                    if decryption_result.success and decryption_result.data:
                                        RequestPayloadDecoder._apply_decrypted_data(result, decryption_result.data)
                                        break
                            if result.decrypted:
                                break

            if options.get('include_segments'):
                result.segments = segments

            return result
        except Exception as error:
            return RequestPayload(
                payload_type=PayloadType.Request,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                timestamp=0,
                request_type=RequestType.GetStats,
                request_data='',
                destination_hash='',
                source_hash='',
                cipher_mac='',
                ciphertext=''
            )

    @staticmethod
    def _parse_request_data(request_type: RequestType, request_data: bytes) -> Dict[str, Any]:
        """Parse request data based on request type"""
        parsed = {}

        try:
            if request_type == RequestType.GetStats:
                # 0x01 - Get Stats: No specific request data structure
                parsed['description'] = 'No additional request data'
                parsed['raw'] = bytes_to_hex(request_data) if len(request_data) > 0 else ''

            elif request_type == RequestType.GetTelemetryData:
                # 0x03 - Get Telemetry Data
                if len(request_data) >= 1:
                    permission_mask = request_data[0]
                    parsed['permission_mask'] = permission_mask
                    parsed['permission_mask_hex'] = f'0x{permission_mask:02x}'
                    parsed['description'] = f'Permission mask (inverse): 0x{permission_mask:02x}'
                else:
                    parsed['error'] = 'Request data too short (expected 1 byte)'

            elif request_type == RequestType.GetMinMaxAvgData:
                # 0x04 - Get Min/Max/Avg Data
                if len(request_data) >= 10:
                    start_secs_ago = (
                        request_data[0] |
                        (request_data[1] << 8) |
                        (request_data[2] << 16) |
                        (request_data[3] << 24)
                    )
                    end_secs_ago = (
                        request_data[4] |
                        (request_data[5] << 8) |
                        (request_data[6] << 16) |
                        (request_data[7] << 24)
                    )
                    res1 = request_data[8]
                    res2 = request_data[9]

                    parsed['start_secs_ago'] = start_secs_ago
                    parsed['end_secs_ago'] = end_secs_ago
                    parsed['res1'] = res1
                    parsed['res2'] = res2
                    parsed['description'] = f'Time span: {start_secs_ago}s ago to {end_secs_ago}s ago'
                else:
                    parsed['error'] = f'Request data too short (expected 10 bytes, got {len(request_data)})'

            elif request_type == RequestType.GetAccessList:
                # 0x05 - Get Access List
                if len(request_data) >= 2:
                    res1 = request_data[0]
                    res2 = request_data[1]
                    parsed['res1'] = res1
                    parsed['res2'] = res2
                    parsed['description'] = 'Reserved fields for future use'
                else:
                    parsed['error'] = f'Request data too short (expected 2 bytes, got {len(request_data)})'

            elif request_type == RequestType.GetNeighbours:
                # 0x06 - Get Neighbours
                if len(request_data) >= 10:
                    request_version = request_data[0]
                    count = request_data[1]
                    offset = (
                        request_data[2] |
                        (request_data[3] << 8)
                    )
                    order_by = request_data[4]
                    pubkey_prefix_length = request_data[5]
                    random_blob = bytes_to_hex(request_data[6:10])

                    parsed['request_version'] = request_version
                    parsed['count'] = count
                    parsed['offset'] = offset
                    parsed['order_by'] = order_by
                    parsed['order_by_name'] = RequestPayloadDecoder._get_order_by_name(order_by)
                    parsed['pubkey_prefix_length'] = pubkey_prefix_length
                    parsed['random_blob'] = random_blob
                    parsed['description'] = f'Fetch {count} neighbors starting at offset {offset}, ordered by {parsed["order_by_name"]}'
                else:
                    parsed['error'] = f'Request data too short (expected at least 10 bytes, got {len(request_data)})'

            else:
                # Unknown or Keepalive (deprecated)
                parsed['raw'] = bytes_to_hex(request_data)
                parsed['description'] = f'Unknown request type data ({len(request_data)} bytes)'

        except Exception as e:
            parsed['error'] = f'Error parsing request data: {str(e)}'
            parsed['raw'] = bytes_to_hex(request_data)

        return parsed

    @staticmethod
    def _get_order_by_name(order_by: int) -> str:
        """Get human-readable name for order_by value"""
        order_names = {
            0: 'newest',
            1: 'oldest',
            2: 'strongest',
            3: 'weakest'
        }
        return order_names.get(order_by, f'unknown({order_by})')

    @staticmethod
    def _apply_decrypted_data(result: RequestPayload, decrypted_data: Dict[str, Any]) -> None:
        """Apply decrypted data to the result payload"""
        timestamp = decrypted_data['timestamp']
        request_type_val = decrypted_data['request_type']
        request_data_bytes = decrypted_data['request_data']

        # Update result with decrypted values
        result.timestamp = timestamp

        # Map request type
        try:
            result.request_type = RequestType(request_type_val)
        except ValueError:
            result.request_type = RequestType.GetStats  # Default

        # Parse request data based on type
        parsed_request_data = RequestPayloadDecoder._parse_request_data(
            result.request_type,
            request_data_bytes
        )

        result.decrypted = {
            'timestamp': timestamp,
            'request_type': result.request_type.value,
            'request_type_name': result.request_type.name,
            'request_data': parsed_request_data
        }
