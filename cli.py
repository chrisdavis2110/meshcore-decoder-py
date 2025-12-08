#!/usr/bin/env python3
"""
MeshCore Decoder CLI
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Complete CLI implementation for decoding MeshCore packets
"""

import sys
import json
import asyncio
from typing import List, Optional
from meshcoredecoder import MeshCoreDecoder
from meshcoredecoder.crypto import MeshCoreKeyStore
from meshcoredecoder.types.crypto import DecryptionOptions
from meshcoredecoder.utils.enum_names import get_route_type_name, get_payload_type_name, get_device_role_name
from meshcoredecoder.utils.hex import bytes_to_hex
from meshcoredecoder.types.enums import PayloadType


def print_formatted_packet(packet, keys: Optional[List[str]] = None):
    """Print formatted packet information"""
    print('\n=== MeshCore Packet Analysis ===\n')

    if not packet.is_valid:
        print('❌ Invalid Packet')
        if packet.errors:
            for error in packet.errors:
                print(f'   {error}')
    else:
        print('✅ Valid Packet')

    print(f'{bold("Message Hash:")} {packet.message_hash}')
    print(f'{bold("Route Type:")} {get_route_type_name(packet.route_type)}')
    print(f'{bold("Payload Type:")} {get_payload_type_name(packet.payload_type)}')
    print(f'{bold("Total Bytes:")} {packet.total_bytes}')

    if packet.path and len(packet.path) > 0:
        print(f'{bold("Path:")} {" → ".join(packet.path)}')

    # Show payload details
    if packet.payload['decoded']:
        print(f'\n{bold("=== Payload Details ===")}')
        show_payload_details(packet.payload['decoded'])

    if not packet.is_valid:
        sys.exit(1)


def show_payload_details(payload):
    """Show details for specific payload types"""
    from datetime import datetime

    payload_type = payload.type

    if payload_type == PayloadType.Advert:
        advert = payload
        print(f'{bold("Public Key:")} {advert.public_key}')
        print(f'{bold("Device Role:")} {get_device_role_name(advert.app_data["device_role"])}')

        if advert.app_data.get('name'):
            print(f'{bold("Device Name:")} {advert.app_data["name"]}')

        if advert.app_data.get('location'):
            loc = advert.app_data['location']
            print(f'{bold("Location:")} {loc["latitude"]}, {loc["longitude"]}')

        if advert.app_data.get('battery_voltage') is not None:
            print(f'{bold("Battery Voltage:")} {advert.app_data["battery_voltage"]} V')

        print(f'{bold("Timestamp:")} {datetime.fromtimestamp(advert.timestamp).isoformat()}')

        # Show signature verification status
        if advert.signature_valid is not None:
            if advert.signature_valid:
                print(f'{bold("Signature:")} ✅ Valid Ed25519 signature')
            else:
                print(f'{bold("Signature:")} ❌ Invalid Ed25519 signature')
                if advert.signature_error:
                    print(f'{bold("Error:")} {advert.signature_error}')
        else:
            print(f'{bold("Signature:")} ⚠️ Not verified (use --verify flag)')

    elif payload_type == PayloadType.GroupText:
        group_text = payload
        print(f'{bold("Channel Hash:")} {group_text.channel_hash} (0x{group_text.channel_hash})')
        print(f'{bold("Cipher MAC:")} {group_text.cipher_mac}')
        print(f'{bold("Ciphertext Length:")} {group_text.ciphertext_length} bytes')

        if group_text.decrypted:
            print(f'\n{bold("🔓 Decrypted Message:")}')
            decrypted = group_text.decrypted
            print(f'{bold("Timestamp:")} {datetime.fromtimestamp(decrypted.get("timestamp", 0)).isoformat()}')

            flags = decrypted.get('flags', 0)
            txt_type = (flags >> 2) & 0x3F
            attempt = flags & 0x03
            print(f'{bold("Text Type:")} {txt_type} (attempt: {attempt})')

            if decrypted.get('sender'):
                print(f'{bold("Sender:")} {decrypted["sender"]}')
            if decrypted.get('message'):
                print(f'{bold("Message:")} {decrypted["message"]}')
        else:
            print('\n🔒 Encrypted (channel shared key required)')
            print(f'{bold("Ciphertext:")} {group_text.ciphertext[:64]}...')
            print(f'{bold("Note:")} To decrypt, provide channel shared key for hash 0x{group_text.channel_hash}')

    elif payload_type == PayloadType.Request:
        request = payload
        print(f'{bold("Destination Hash:")} {request.destination_hash}')
        print(f'{bold("Source Hash:")} {request.source_hash}')

        if request.decrypted:
            print(f'{bold("🔓 Decrypted Request:")}')
            decrypted = request.decrypted
            print(f'{bold("Timestamp:")} {datetime.fromtimestamp(decrypted["timestamp"]).isoformat()}')

            # Show request type prominently
            if decrypted.get('request_type_name'):
                request_type_name = decrypted["request_type_name"]
                request_type_val = decrypted["request_type"]
                print(f'\n{bold("📋 Request Type:")} {bold(request_type_name)} (0x{request_type_val:02x})')

            if decrypted.get('request_data'):
                req_data = decrypted['request_data']
                print(f'\n{bold("Request Data:")}')
                for key, value in req_data.items():
                    if key != 'description' and key != 'raw' and key != 'error':
                        print(f'  {bold(key)}: {value}')
                if req_data.get('description'):
                    print(f'  {bold("Description:")} {req_data["description"]}')
                if req_data.get('error'):
                    print(f'  {bold("⚠️ Error:")} {req_data["error"]}')
        else:
            print('🔒 Encrypted (no key available)')
            print(f'{bold("Ciphertext:")} {request.ciphertext[:32]}...')
            print(f'{bold("Request Type:")} Unknown (decryption required)')

    elif payload_type == PayloadType.Response:
        response = payload
        print(f'{bold("Destination Hash:")} {response.destination_hash}')
        print(f'{bold("Source Hash:")} {response.source_hash}')

        if response.decrypted:
            print(f'{bold("🔓 Decrypted Response:")}')
            decrypted = response.decrypted
            print(f'{bold("Tag:")} {decrypted.get("tag", "N/A")}')

            content = decrypted.get('content', {})
            content_type = content.get('type', 'unknown')

            if content_type == 'neighbours':
                print(f'\n{bold("📋 Response Type:")} Neighbours')
                print(f'{bold("Sender Timestamp:")} {datetime.fromtimestamp(content.get("sender_timestamp", 0)).isoformat()}')
                print(f'{bold("Total Neighbours:")} {content.get("neighbours_count", 0)}')
                print(f'{bold("Results in Response:")} {content.get("results_count", 0)}')

                neighbors = content.get('neighbors', [])
                if neighbors:
                    print(f'\n{bold("Neighbors:")}')
                    for i, neighbor in enumerate(neighbors, 1):
                        print(f'  {i}. Pubkey Prefix: {neighbor.get("pubkey_prefix", "N/A")}')
                        print(f'     Heard {neighbor.get("heard_seconds_ago", 0)}s ago')
                        snr_value = neighbor.get("snr", 0) / 4.0
                        print(f'     SNR: {snr_value:.2f} dB')

            elif content_type == 'telemetry':
                print(f'\n{bold("📋 Response Type:")} Telemetry Data')
                tag = content.get('tag', decrypted.get('tag', 0))
                if tag:
                    print(f'{bold("Tag:")} {tag} ({datetime.fromtimestamp(tag).isoformat() if tag > 0 else "N/A"})')
                telemetry_hex = content.get('telemetry_data', '')
                if telemetry_hex:
                    from meshcoredecoder.utils.hex import hex_to_bytes
                    telemetry_bytes = hex_to_bytes(telemetry_hex)
                    print(f'{bold("Telemetry Data Length:")} {len(telemetry_bytes)} bytes')
                    print(f'{bold("Telemetry Data (Hex):")} {telemetry_hex[:64]}...')

                    # Parse LPP (CayenneLPP) format: [channel][type][data]...
                    print(f'\n{bold("LPP Telemetry Entries:")}')
                    offset = 0
                    entry_num = 1
                    while offset + 2 <= len(telemetry_bytes):
                        channel = telemetry_bytes[offset]
                        if channel == 0:
                            break  # End marker
                        offset += 1

                        if offset >= len(telemetry_bytes):
                            break
                        lpp_type = telemetry_bytes[offset]
                        offset += 1

                        # Get data size based on LPP type
                        data_size = _get_lpp_data_size(lpp_type)
                        if offset + data_size > len(telemetry_bytes):
                            break

                        # Read data (big-endian for multi-byte values)
                        data_bytes = telemetry_bytes[offset:offset + data_size]
                        value = _parse_lpp_value(data_bytes, lpp_type)

                        type_name = _get_lpp_type_name(lpp_type)
                        print(f'  {entry_num}. Channel {channel}: {type_name} = {value}')

                        offset += data_size
                        entry_num += 1

                    if entry_num == 1:
                        print(f'  (No valid LPP entries found)')
                else:
                    print(f'{bold("Telemetry Data:")} N/A')

            elif content_type == 'min_max_avg':
                print(f'\n{bold("📋 Response Type:")} Min/Max/Avg Data')
                tag = content.get('tag', 0)
                if tag > 0:
                    print(f'{bold("Tag:")} {tag} ({datetime.fromtimestamp(tag).isoformat()})')
                    print(f'{bold("Note:")} Tag is the sender timestamp from the request (reflected back)')
                current_timestamp = content.get('current_timestamp', 0)
                if current_timestamp > 0:
                    print(f'{bold("Current Timestamp:")} {current_timestamp} ({datetime.fromtimestamp(current_timestamp).isoformat()})')
                data = content.get('data', '')
                if data:
                    print(f'{bold("Data Length:")} {len(data) // 2} bytes')
                    print(f'{bold("Data (Hex):")} {data[:64]}...')
                else:
                    print(f'{bold("Data:")} N/A')

            elif content_type == 'access_list':
                print(f'\n{bold("📋 Response Type:")} Access List')
                tag = content.get('tag', 0)
                if tag > 0:
                    print(f'{bold("Tag:")} {tag} ({datetime.fromtimestamp(tag).isoformat()})')
                    print(f'{bold("Note:")} Tag is the sender timestamp from the request (reflected back)')
                entries = content.get('entries', [])
                # Show raw content for debugging
                if hasattr(payload, 'decrypted') and payload.decrypted:
                    raw_content = payload.decrypted.get('content', {})
                    if isinstance(raw_content, dict) and 'raw' in raw_content:
                        from meshcoredecoder.utils.hex import hex_to_bytes
                        content_bytes = hex_to_bytes(raw_content['raw'])
                        print(f'\n{bold("Debug - Raw Content (first 32 bytes):")} {" ".join(f"{b:02x}" for b in content_bytes[:32])}')
                        print(f'{bold("Debug - Expected prefixes:")} 2e, f6, 05, 02, 96, c1, 35')
                if entries:
                    # Filter out entries with permissions == 0 (deleted entries, should be skipped)
                    # But show them with a note
                    valid_entries = [e for e in entries if e.get('permissions', 0) != 0]
                    deleted_entries = [e for e in entries if e.get('permissions', 0) == 0]

                    if valid_entries:
                        print(f'\n{bold("Access List Entries:")} ({len(valid_entries)} valid)')
                        for i, entry in enumerate(valid_entries, 1):
                            permissions = entry.get('permissions', 0)
                            role = permissions & 0x03  # Lower 2 bits
                            features = permissions >> 2  # Upper 6 bits
                            role_name = {0: 'No access', 1: 'Guest', 2: 'Read-only', 3: 'Admin'}.get(role, 'Unknown')
                            print(f'  {i}. Pubkey Prefix: {entry.get("pubkey_prefix", "N/A")}')
                            print(f'     Permissions: 0x{permissions:02x} (Role: {role_name}, Features: 0x{features:02x})')

                    if deleted_entries:
                        print(f'\n{bold("Note:")} Found {len(deleted_entries)} entry/entries with permissions 0x00 (deleted).')
                        print(f'      These should be skipped during response construction according to the spec.')
                        for i, entry in enumerate(deleted_entries, 1):
                            print(f'      Deleted {i}: Pubkey Prefix: {entry.get("pubkey_prefix", "N/A")}')
                else:
                    print(f'\n{bold("Note:")} No access list entries found.')

            elif content_type == 'login_response':
                print(f'\n{bold("📋 Response Type:")} Login Response')
                timestamp = content.get('timestamp', 0)
                if timestamp > 0:
                    print(f'{bold("Timestamp:")} {timestamp} ({datetime.fromtimestamp(timestamp).isoformat()})')
                response_code = content.get('response_code', 0)
                if response_code == 0x00:
                    print(f'{bold("Response Code:")} 0x{response_code:02x} (Success - RESP_SERVER_LOGIN_OK)')
                else:
                    print(f'{bold("Response Code:")} 0x{response_code:02x} (Failure)')
                legacy_keepalive = content.get('legacy_keepalive', 0)
                print(f'{bold("Legacy Keepalive:")} {legacy_keepalive}')
                is_admin = content.get('is_admin', 0)
                print(f'{bold("Is Admin:")} {bool(is_admin)}')
                permissions = content.get('permissions', 0)
                role = permissions & 0x03  # Lower 2 bits
                features = permissions >> 2  # Upper 6 bits
                role_name = {0: 'No access', 1: 'Guest', 2: 'Read-only', 3: 'Admin'}.get(role, 'Unknown')
                print(f'{bold("Permissions:")} 0x{permissions:02x} (Role: {role_name}, Features: 0x{features:02x})')
                random_blob = content.get('random_blob', '')
                if random_blob:
                    print(f'{bold("Random Blob:")} {random_blob}')
                firmware_version = content.get('firmware_version', 0)
                print(f'{bold("Firmware Version:")} {firmware_version}')

            elif content_type == 'stats':
                print(f'\n{bold("📋 Response Type:")} Stats')
                print(f'{bold("Tag:")} {decrypted.get("tag", "N/A")}')
                stats_data = content.get('stats_data', '')
                if stats_data:
                    from meshcoredecoder.utils.hex import hex_to_bytes
                    stats_bytes = hex_to_bytes(stats_data)

                    # Parse stats data based on MeshCore stats structure
                    # Supports both ServerStats (52 bytes) and RepeaterStats (52 bytes)
                    if len(stats_bytes) >= 40:
                        offset = 0

                        # Battery voltage (uint16_t, millivolts)
                        if offset + 2 <= len(stats_bytes):
                            battery_mv = int.from_bytes(stats_bytes[offset:offset+2], 'little')
                            battery_v = battery_mv / 1000.0
                            battery_percent = min(100, int((battery_v / 4.2) * 100)) if battery_v <= 4.2 else 100
                            print(f'\n{bold("Battery:")} {battery_percent}% / {battery_v:.2f}v')
                        offset += 2

                        # TX Queue length (uint16_t)
                        if offset + 2 <= len(stats_bytes):
                            tx_queue = int.from_bytes(stats_bytes[offset:offset+2], 'little')
                            print(f'{bold("Queue Length:")}')
                            print(f'  TX Queue: {tx_queue}')
                        offset += 2

                        # Noise floor (int16_t, dBm)
                        if offset + 2 <= len(stats_bytes):
                            noise_floor = int.from_bytes(stats_bytes[offset:offset+2], 'little', signed=True)
                            print(f'{bold("Noise Floor:")} {noise_floor}dB')
                        offset += 2

                        # Last RSSI (int16_t, dBm)
                        if offset + 2 <= len(stats_bytes):
                            last_rssi = int.from_bytes(stats_bytes[offset:offset+2], 'little', signed=True)
                            print(f'{bold("Last RSSI:")} {last_rssi}')
                        offset += 2

                        # Packets received (uint32_t)
                        if offset + 4 <= len(stats_bytes):
                            n_packets_recv = int.from_bytes(stats_bytes[offset:offset+4], 'little')
                            print(f'\n{bold("Packets Received:")}')
                            print(f'  Total: {n_packets_recv}')
                        offset += 4

                        # Packets sent (uint32_t)
                        if offset + 4 <= len(stats_bytes):
                            n_packets_sent = int.from_bytes(stats_bytes[offset:offset+4], 'little')
                            print(f'{bold("Packets Sent:")}')
                            print(f'  Total: {n_packets_sent}')
                        offset += 4

                        # Total air time (uint32_t, seconds)
                        if offset + 4 <= len(stats_bytes):
                            total_air_time = int.from_bytes(stats_bytes[offset:offset+4], 'little')
                            days = total_air_time // 86400
                            hours = (total_air_time % 86400) // 3600
                            minutes = (total_air_time % 3600) // 60
                            seconds = total_air_time % 60
                            print(f'\n{bold("Total Airtime:")}')
                            print(f'  TX: {days} days {hours}h {minutes}m {seconds}s')
                        offset += 4

                        # Uptime (uint32_t, seconds)
                        if offset + 4 <= len(stats_bytes):
                            uptime_seconds = int.from_bytes(stats_bytes[offset:offset+4], 'little')
                            days = uptime_seconds // 86400
                            hours = (uptime_seconds % 86400) // 3600
                            minutes = (uptime_seconds % 3600) // 60
                            secs = uptime_seconds % 60
                            print(f'{bold("Uptime:")} {days} days {hours}h {minutes}m {secs}s')
                        offset += 4

                        # Packets sent flood (uint32_t)
                        if offset + 4 <= len(stats_bytes):
                            n_sent_flood = int.from_bytes(stats_bytes[offset:offset+4], 'little')
                            print(f'\n{bold("Packets Sent:")}')
                            print(f'  Flood: {n_sent_flood}')
                        offset += 4

                        # Packets sent direct (uint32_t)
                        if offset + 4 <= len(stats_bytes):
                            n_sent_direct = int.from_bytes(stats_bytes[offset:offset+4], 'little')
                            print(f'  Direct: {n_sent_direct}')
                        offset += 4

                        # Packets received flood (uint32_t)
                        if offset + 4 <= len(stats_bytes):
                            n_recv_flood = int.from_bytes(stats_bytes[offset:offset+4], 'little')
                            print(f'\n{bold("Packets Received:")}')
                            print(f'  Flood: {n_recv_flood}')
                        offset += 4

                        # Packets received direct (uint32_t)
                        if offset + 4 <= len(stats_bytes):
                            n_recv_direct = int.from_bytes(stats_bytes[offset:offset+4], 'little')
                            print(f'  Direct: {n_recv_direct}')
                        offset += 4

                        # Error events (uint16_t, bitmask)
                        if offset + 2 <= len(stats_bytes):
                            err_events = int.from_bytes(stats_bytes[offset:offset+2], 'little')
                            if err_events != 0:
                                print(f'\n{bold("Error Events:")} 0x{err_events:04x}')
                        offset += 2

                        # Last SNR (int16_t, × 4, divide by 4.0 for dB)
                        if offset + 2 <= len(stats_bytes):
                            last_snr_raw = int.from_bytes(stats_bytes[offset:offset+2], 'little', signed=True)
                            last_snr = last_snr_raw / 4.0
                            print(f'{bold("Last SNR:")} {last_snr:.1f}')
                        offset += 2

                        # Direct duplicates (uint16_t)
                        if offset + 2 <= len(stats_bytes):
                            n_direct_dups = int.from_bytes(stats_bytes[offset:offset+2], 'little')
                            print(f'\n{bold("Duplicate Packets Seen:")}')
                            print(f'  Direct: {n_direct_dups}')
                        offset += 2

                        # Flood duplicates (uint16_t)
                        if offset + 2 <= len(stats_bytes):
                            n_flood_dups = int.from_bytes(stats_bytes[offset:offset+2], 'little')
                            print(f'  Flood: {n_flood_dups}')
                        offset += 2

                        # Check if ServerStats (has n_posted, n_post_push) or RepeaterStats (has total_rx_air_time_secs)
                        if offset + 4 <= len(stats_bytes):
                            # Try RepeaterStats first (total_rx_air_time_secs is uint32_t)
                            total_rx_air_time = int.from_bytes(stats_bytes[offset:offset+4], 'little')
                            # If it's a reasonable airtime value (less than a year), it's likely RepeaterStats
                            if total_rx_air_time < 31536000:  # Less than 1 year in seconds
                                days = total_rx_air_time // 86400
                                hours = (total_rx_air_time % 86400) // 3600
                                minutes = (total_rx_air_time % 3600) // 60
                                seconds = total_rx_air_time % 60
                                print(f'\n{bold("Total Airtime:")}')
                                print(f'  RX: {days} days {hours}h {minutes}m {seconds}s')
                            else:
                                # Likely ServerStats - parse as two uint16_t values
                                n_posted = int.from_bytes(stats_bytes[offset:offset+2], 'little')
                                n_post_push = int.from_bytes(stats_bytes[offset+2:offset+4], 'little')
                                print(f'\n{bold("Server Stats:")}')
                                print(f'  Posts: {n_posted}')
                                print(f'  Post Pushes: {n_post_push}')
                        elif offset + 2 <= len(stats_bytes):
                            # Only 2 bytes left - must be ServerStats
                            n_posted = int.from_bytes(stats_bytes[offset:offset+2], 'little')
                            print(f'\n{bold("Server Stats:")}')
                            print(f'  Posts: {n_posted}')

                    else:
                        # Fallback: show raw data
                        print(f'{bold("Stats Data Length:")} {len(stats_bytes)} bytes')
                        print(f'{bold("Stats Data (Hex):")} {stats_data}')
                if content.get('note'):
                    print(f'\n{bold("Note:")} {content["note"]}')

            else:
                print(f'\n{bold("Response Content:")}')
                print(f'{bold("Type:")} {content_type}')
                if content.get('raw'):
                    print(f'{bold("Raw Data:")} {content["raw"][:64]}...')
        else:
            print('🔒 Encrypted (no key available)')
            print(f'{bold("Ciphertext:")} {response.ciphertext[:32]}...')

    elif payload_type == PayloadType.TextMessage:
        text_msg = payload
        print(f'{bold("Destination Hash:")} {text_msg.destination_hash} (0x{text_msg.destination_hash})')
        print(f'{bold("Source Hash:")} {text_msg.source_hash} (0x{text_msg.source_hash})')
        print(f'{bold("Cipher MAC:")} {text_msg.cipher_mac}')
        print(f'{bold("Ciphertext Length:")} {text_msg.ciphertext_length} bytes')

        if text_msg.decrypted:
            print(f'\n{bold("🔓 Decrypted Message:")}')
            decrypted = text_msg.decrypted
            print(f'{bold("Timestamp:")} {datetime.fromtimestamp(decrypted.get("timestamp", 0)).isoformat()}')

            flags = decrypted.get('flags', 0)
            txt_type = decrypted.get('txt_type', 0)
            attempt = decrypted.get('attempt', 0)

            txt_type_names = {
                0: 'Plain Text',
                1: 'CLI Command',
                2: 'Signed Plain Text'
            }
            txt_type_name = txt_type_names.get(txt_type, f'Unknown ({txt_type})')

            print(f'{bold("Text Type:")} {txt_type_name} (0x{txt_type:02x})')
            print(f'{bold("Attempt:")} {attempt}')

            # Show sender pubkey prefix for signed messages
            if txt_type == 0x02 and decrypted.get('sender_pubkey_prefix'):
                print(f'{bold("Sender Pubkey Prefix:")} {decrypted["sender_pubkey_prefix"]}')

            message = decrypted.get("message", "")
            if message:
                print(f'{bold("Message:")} {message}')
        else:
            print('\n🔒 Encrypted (ECDH keys required)')
            print(f'{bold("Ciphertext:")} {text_msg.ciphertext[:64]}...')
            print(f'{bold("Note:")} To decrypt, provide --node-key and --peer-key (or --shared-secret)')

    elif payload_type == PayloadType.AnonRequest:
        anon_req = payload
        print(f'{bold("Destination Hash:")} {anon_req.destination_hash} (0x{anon_req.destination_hash})')
        print(f'{bold("Sender Public Key:")} {anon_req.sender_public_key}')
        print(f'{bold("Cipher MAC:")} {anon_req.cipher_mac}')
        if hasattr(anon_req, 'ciphertext_length') and anon_req.ciphertext_length:
            print(f'{bold("Ciphertext Length:")} {anon_req.ciphertext_length} bytes')

        if anon_req.decrypted:
            print(f'\n{bold("🔓 Decrypted Anonymous Request:")}')
            decrypted = anon_req.decrypted
            print(f'{bold("Timestamp:")} {datetime.fromtimestamp(decrypted.get("timestamp", 0)).isoformat()}')

            req_type = decrypted.get('type', 'unknown')

            if req_type == 'room_server_login':
                print(f'\n{bold("📋 Request Type:")} Room Server Login')
                if decrypted.get('sync_timestamp'):
                    print(f'{bold("Sync Timestamp:")} {datetime.fromtimestamp(decrypted["sync_timestamp"]).isoformat()}')
                if decrypted.get('password'):
                    print(f'{bold("Password:")} {"*" * len(decrypted["password"])}')

            elif req_type == 'repeater_sensor_login':
                print(f'\n{bold("📋 Request Type:")} Repeater/Sensor Login')
                if decrypted.get('password'):
                    print(f'{bold("Password:")} {"*" * len(decrypted["password"])}')

            elif req_type == 'request':
                print(f'\n{bold("📋 Request Type:")} Regular Request')
                if decrypted.get('request_type') is not None:
                    print(f'{bold("Request Type:")} 0x{decrypted["request_type"]:02x}')
                if decrypted.get('request_data'):
                    print(f'{bold("Request Data:")} {bytes_to_hex(decrypted["request_data"])[:64]}...')

            else:
                print(f'\n{bold("Request Type:")} {req_type}')
                if decrypted.get('raw'):
                    print(f'{bold("Raw Data:")} {decrypted["raw"][:64]}...')
        else:
            print('\n🔒 Encrypted (ECDH keys required)')
            print(f'{bold("Ciphertext:")} {anon_req.ciphertext[:64]}...')
            print(f'{bold("Note:")} To decrypt, provide --node-key (peer key comes from packet)')
            print(f'{bold("Note:")} Anonymous requests include sender public key in packet (not from contacts DB)')

    elif payload_type == PayloadType.Path:
        path = payload
        if path.destination_hash:
            print(f'{bold("Destination Hash:")} {path.destination_hash} (0x{path.destination_hash})')
        if path.source_hash:
            print(f'{bold("Source Hash:")} {path.source_hash} (0x{path.source_hash})')
        if hasattr(path, 'cipher_mac') and path.cipher_mac:
            print(f'{bold("Cipher MAC:")} {path.cipher_mac}')
        if hasattr(path, 'ciphertext_length') and path.ciphertext_length:
            print(f'{bold("Ciphertext Length:")} {path.ciphertext_length} bytes')

        if hasattr(path, 'decrypted') and path.decrypted:
            print(f'\n{bold("🔓 Decrypted Path:")}')
            decrypted = path.decrypted
            print(f'{bold("Path Length:")} {decrypted.get("path_len", 0)}')

            path_hashes = decrypted.get('path_hashes', [])
            if path_hashes:
                print(f'{bold("Return Path:")} {" → ".join(path_hashes)}')

            extra_type = decrypted.get('extra_type', 0)
            extra_type_name = get_payload_type_name(PayloadType(extra_type)) if extra_type < 16 else f'0x{extra_type:02x}'
            print(f'{bold("Extra Payload Type:")} {extra_type_name} (0x{extra_type:02x})')

            extra_data = decrypted.get('extra_data', '')
            if extra_data:
                print(f'{bold("Extra Data:")} {extra_data[:64]}...')
                # If extra_type is Response, we could try to parse it further
                if extra_type == 0x01:  # PAYLOAD_TYPE_RESPONSE
                    print(f'{bold("Note:")} Contains embedded Response payload')
        elif path.path_hashes and len(path.path_hashes) > 0:
            # Unencrypted path (shouldn't happen per guide, but handle it)
            print(f'{bold("Path Length:")} {path.path_length}')
            print(f'{bold("Return Path:")} {" → ".join(path.path_hashes)}')
            print(f'{bold("Extra Type:")} 0x{path.extra_type:02x}')
            if path.extra_data:
                print(f'{bold("Extra Data:")} {path.extra_data[:64]}...')
        else:
            print('\n🔒 Encrypted (ECDH keys required)')
            if hasattr(path, 'ciphertext'):
                print(f'{bold("Ciphertext:")} {path.ciphertext[:64]}...')
            print(f'{bold("Note:")} To decrypt, provide --node-key and --peer-key (or --shared-secret)')
            if path.errors:
                for error in path.errors:
                    print(f'{bold("⚠️ Error:")} {error}')

    elif payload_type == PayloadType.GroupData:
        group_data = payload
        print(f'{bold("Channel Hash:")} {group_data.channel_hash}')

        if group_data.decrypted:
            print(f'{bold("🔓 Decrypted Datagram:")}')
            decrypted = group_data.decrypted
            print(f'{bold("Timestamp:")} {datetime.fromtimestamp(decrypted.get("timestamp", 0)).isoformat()}')
            print(f'{bold("Flags:")} 0x{decrypted.get("flags", 0):02x}')

            data_blob = decrypted.get('data', b'')
            if data_blob:
                from meshcoredecoder.utils.hex import bytes_to_hex
                data_hex = bytes_to_hex(data_blob) if isinstance(data_blob, bytes) else str(data_blob)
                print(f'{bold("Data:")} {data_hex[:64]}...')
        else:
            print('🔒 Encrypted (no key available)')
            print(f'{bold("Ciphertext:")} {group_data.ciphertext[:32]}...')

    elif payload_type == PayloadType.Ack:
        ack = payload
        checksum_hex = ack.checksum.upper()
        # Convert to integer for display
        try:
            checksum_int = int(checksum_hex, 16)
            print(f'{bold("Checksum:")} 0x{checksum_hex} ({checksum_int:,})')
            print(f'{bold("Description:")} CRC checksum of message timestamp, text, and sender pubkey')
        except ValueError:
            print(f'{bold("Checksum:")} {ack.checksum}')

    elif payload_type == PayloadType.Trace:
        trace = payload
        print(f'{bold("Trace Tag:")} {trace.trace_tag} (0x{trace.trace_tag})')
        print(f'{bold("Auth Code:")} {trace.auth_code}')
        if trace.flags is not None:
            print(f'{bold("Flags:")} 0x{trace.flags:02x}')

        # Show path hashes if available
        if trace.path_hashes and len(trace.path_hashes) > 0:
            print(f'{bold("Path Hashes:")} {" → ".join(trace.path_hashes)}')

        # Show SNR values per hop
        if trace.snr_values and len(trace.snr_values) > 0:
            print(f'\n{bold("SNR Values Along Path:")}')
            # Use path hashes from trace payload, or just show hop numbers
            path_for_display = trace.path_hashes if trace.path_hashes else None
            for i, snr in enumerate(trace.snr_values):
                hop_info = f'Hop {i+1}'
                if path_for_display and i < len(path_for_display):
                    hop_info = f'Hop {i+1} (Node {path_for_display[i]})'
                print(f'  {hop_info}: {snr:.1f} dB')

            # Summary
            if len(trace.snr_values) > 1:
                avg_snr = sum(trace.snr_values) / len(trace.snr_values)
                min_snr = min(trace.snr_values)
                max_snr = max(trace.snr_values)
                print(f'\n{bold("SNR Summary:")}')
                print(f'  Average: {avg_snr:.1f} dB')
                print(f'  Min: {min_snr:.1f} dB')
                print(f'  Max: {max_snr:.1f} dB')

    else:
        print(f'{bold("Type:")} {get_payload_type_name(payload_type)}')
        print(f'{bold("Valid:")} {"✅" if payload.is_valid else "❌"}')


def bold(text: str) -> str:
    """Make text bold (simple version without colorama)"""
    return f'\033[1m{text}\033[0m'


def _get_lpp_data_size(lpp_type: int) -> int:
    """Get data size in bytes for LPP type"""
    lpp_sizes = {
        0: 1,    # DIGITAL_INPUT
        1: 1,    # DIGITAL_OUTPUT
        2: 2,    # ANALOG_INPUT
        3: 2,    # ANALOG_OUTPUT
        100: 4,  # GENERIC_SENSOR
        101: 2,  # LUMINOSITY
        102: 1,  # PRESENCE
        103: 2,  # TEMPERATURE
        104: 1,  # RELATIVE_HUMIDITY
        113: 6,  # ACCELEROMETER
        115: 2,  # BAROMETRIC_PRESSURE
        116: 2,  # VOLTAGE
        117: 2,  # CURRENT
        118: 4,  # FREQUENCY
        120: 1,  # PERCENTAGE
        121: 2,  # ALTITUDE
        125: 2,  # CONCENTRATION
        128: 2,  # POWER
        130: 4,  # DISTANCE
        131: 4,  # ENERGY
        132: 2,  # DIRECTION
        133: 4,  # UNIXTIME
        134: 6,  # GYROMETER
        135: 3,  # COLOUR
        136: 9,  # GPS
        142: 1,  # SWITCH
    }
    return lpp_sizes.get(lpp_type, 1)  # Default to 1 byte if unknown


def _get_lpp_type_name(lpp_type: int) -> str:
    """Get human-readable name for LPP type"""
    lpp_names = {
        0: 'Digital Input',
        1: 'Digital Output',
        2: 'Analog Input',
        3: 'Analog Output',
        100: 'Generic Sensor',
        101: 'Luminosity',
        102: 'Presence',
        103: 'Temperature',
        104: 'Relative Humidity',
        113: 'Accelerometer',
        115: 'Barometric Pressure',
        116: 'Voltage',
        117: 'Current',
        118: 'Frequency',
        120: 'Percentage',
        121: 'Altitude',
        125: 'Concentration',
        128: 'Power',
        130: 'Distance',
        131: 'Energy',
        132: 'Direction',
        133: 'Unix Time',
        134: 'Gyrometer',
        135: 'Colour',
        136: 'GPS',
        142: 'Switch',
    }
    return lpp_names.get(lpp_type, f'Unknown (0x{lpp_type:02x})')


def _get_lpp_multiplier(lpp_type: int) -> float:
    """Get multiplier for LPP type"""
    lpp_multipliers = {
        0: 1.0,      # DIGITAL_INPUT
        1: 1.0,      # DIGITAL_OUTPUT
        2: 100.0,    # ANALOG_INPUT
        3: 100.0,    # ANALOG_OUTPUT
        100: 1.0,    # GENERIC_SENSOR
        101: 1.0,    # LUMINOSITY
        102: 1.0,    # PRESENCE
        103: 10.0,   # TEMPERATURE
        104: 2.0,    # RELATIVE_HUMIDITY
        113: 1000.0, # ACCELEROMETER
        115: 10.0,   # BAROMETRIC_PRESSURE
        116: 100.0,  # VOLTAGE
        117: 1000.0, # CURRENT
        118: 1.0,    # FREQUENCY
        120: 1.0,    # PERCENTAGE
        121: 1.0,    # ALTITUDE
        125: 1.0,    # CONCENTRATION
        128: 1.0,    # POWER
        130: 1000.0, # DISTANCE
        131: 1000.0, # ENERGY
        132: 1.0,    # DIRECTION
        133: 1.0,    # UNIXTIME
        134: 100.0,  # GYROMETER
        135: 1.0,    # COLOUR
        136: 10000.0, # GPS (lat/lon)
        142: 1.0,    # SWITCH
    }
    return lpp_multipliers.get(lpp_type, 1.0)


def _is_lpp_signed(lpp_type: int) -> bool:
    """Check if LPP type is signed"""
    signed_types = {2, 3, 103, 113, 121, 134, 136}  # ANALOG_INPUT, ANALOG_OUTPUT, TEMPERATURE, ACCELEROMETER, ALTITUDE, GYROMETER, GPS
    return lpp_type in signed_types


def _parse_lpp_value(data_bytes: bytes, lpp_type: int) -> str:
    """Parse LPP value from bytes"""
    multiplier = _get_lpp_multiplier(lpp_type)
    is_signed = _is_lpp_signed(lpp_type)

    # Read as big-endian (LPP uses big-endian)
    value = 0
    for byte in data_bytes:
        value = (value << 8) | byte

    # Handle signed values
    if is_signed:
        bit = 1 << ((len(data_bytes) * 8) - 1)
        if value & bit:
            value = (bit << 1) - value
            sign = -1
        else:
            sign = 1
    else:
        sign = 1

    actual_value = sign * (value / multiplier)

    # Format based on type
    if lpp_type == 103:  # TEMPERATURE
        return f'{actual_value:.1f}°C'
    elif lpp_type == 104:  # RELATIVE_HUMIDITY
        return f'{actual_value:.1f}%'
    elif lpp_type == 116:  # VOLTAGE
        return f'{actual_value:.2f}V'
    elif lpp_type == 117:  # CURRENT
        return f'{actual_value:.3f}A'
    elif lpp_type == 128:  # POWER
        return f'{actual_value:.0f}W'
    elif lpp_type == 101:  # LUMINOSITY
        return f'{actual_value:.0f} lux'
    elif lpp_type == 115:  # BAROMETRIC_PRESSURE
        return f'{actual_value:.1f} hPa'
    elif lpp_type == 136:  # GPS
        # GPS is 9 bytes: 3 bytes lat, 3 bytes lon, 3 bytes alt
        if len(data_bytes) == 9:
            lat_raw = (data_bytes[0] << 16) | (data_bytes[1] << 8) | data_bytes[2]
            lon_raw = (data_bytes[3] << 16) | (data_bytes[4] << 8) | data_bytes[5]
            alt_raw = (data_bytes[6] << 16) | (data_bytes[7] << 8) | data_bytes[8]
            # Handle signed lat/lon
            if lat_raw & 0x800000:
                lat_raw = lat_raw - 0x1000000
            if lon_raw & 0x800000:
                lon_raw = lon_raw - 0x1000000
            if alt_raw & 0x800000:
                alt_raw = alt_raw - 0x1000000
            lat = lat_raw / 10000.0
            lon = lon_raw / 10000.0
            alt = alt_raw / 100.0
            return f'{lat:.4f}°, {lon:.4f}°, {alt:.2f}m'
        else:
            return f'{actual_value}'
    else:
        return f'{actual_value}'


def main():
    """Main CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='CLI tool for decoding MeshCore packets',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--version', action='version', version='0.1.0')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Decode command
    decode_parser = subparsers.add_parser('decode', help='Decode a MeshCore packet')
    decode_parser.add_argument('hex', help='Hex string of the packet to decode')
    decode_parser.add_argument('-k', '--key', '--channel-key', action='append', dest='keys', metavar='SECRET', help='Channel secret key for GroupText/GroupData decryption (hex). Can be specified multiple times for different channels.')
    decode_parser.add_argument('--node-key', action='append', dest='node_keys', metavar='PUB:PRIV', help='Node key pair for ECDH (format: public_key:private_key, both hex). Used for Request/Response/TextMessage decryption.')
    decode_parser.add_argument('--peer-key', action='append', dest='peer_keys', metavar='PUB', help='Peer public key (hex) for matching by source hash')
    decode_parser.add_argument('--shared-secret', action='append', dest='shared_secrets', metavar='PUB:SECRET', help='Shared secret for peer (format: peer_public_key:shared_secret, both hex). Used for Request/Response/TextMessage decryption.')
    decode_parser.add_argument('-j', '--json', action='store_true', help='Output as JSON instead of formatted text')
    decode_parser.add_argument('-s', '--structure', action='store_true', help='Show detailed packet structure analysis')
    decode_parser.add_argument('--verify', action='store_true', help='Verify Ed25519 signatures (async)')

    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate packet format')
    validate_parser.add_argument('hex', help='Hex string to validate')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'decode':
        decode_command(args)
    elif args.command == 'validate':
        validate_command(args)


def decode_command(args):
    """Handle decode command"""
    try:
        # Clean up hex input
        clean_hex = args.hex.replace(' ', '').replace('0x', '').replace('0X', '')

        # Create key store if keys provided
        key_store = None
        key_store_data = {}

        # Add channel secrets (for group messages)
        if args.keys and len(args.keys) > 0:
            # Clean up hex strings (remove spaces, 0x prefixes)
            cleaned_keys = []
            for key in args.keys:
                cleaned_key = key.replace(' ', '').replace('0x', '').replace('0X', '')
                cleaned_keys.append(cleaned_key)
            key_store_data['channel_secrets'] = cleaned_keys

        # Add node key pairs (for ECDH calculation)
        node_keys_dict = {}
        if args.node_keys and len(args.node_keys) > 0:
            for key_pair in args.node_keys:
                try:
                    if ':' not in key_pair:
                        print(f'Warning: Invalid node key format: {key_pair}. Expected format: public_key:private_key', file=sys.stderr)
                        continue
                    pub_key, priv_key = key_pair.split(':', 1)
                    # Clean up hex strings
                    pub_key = pub_key.replace(' ', '').replace('0x', '').replace('0X', '')
                    priv_key = priv_key.replace(' ', '').replace('0x', '').replace('0X', '')
                    node_keys_dict[pub_key] = priv_key
                except Exception as e:
                    print(f'Warning: Failed to parse node key pair "{key_pair}": {e}', file=sys.stderr)

            if node_keys_dict:
                key_store_data['node_keys'] = node_keys_dict

        # Add shared secrets directly (for request/response/text message decryption)
        shared_secrets_dict = {}
        if args.shared_secrets and len(args.shared_secrets) > 0:
            for shared_secret_pair in args.shared_secrets:
                try:
                    if ':' not in shared_secret_pair:
                        print(f'Warning: Invalid shared secret format: {shared_secret_pair}. Expected format: peer_public_key:shared_secret', file=sys.stderr)
                        continue
                    peer_pub_key, shared_secret = shared_secret_pair.split(':', 1)
                    # Clean up hex strings
                    peer_pub_key = peer_pub_key.replace(' ', '').replace('0x', '').replace('0X', '')
                    shared_secret = shared_secret.replace(' ', '').replace('0x', '').replace('0X', '')
                    shared_secrets_dict[peer_pub_key] = shared_secret
                except Exception as e:
                    print(f'Warning: Failed to parse shared secret "{shared_secret_pair}": {e}', file=sys.stderr)

            if shared_secrets_dict:
                key_store_data['shared_secrets'] = shared_secrets_dict

        # Add peer public keys (for matching by source hash)
        peer_public_keys_list = []
        if args.peer_keys and len(args.peer_keys) > 0:
            for peer_key in args.peer_keys:
                try:
                    # Clean up hex string
                    peer_key_clean = peer_key.replace(' ', '').replace('0x', '').replace('0X', '')
                    if len(peer_key_clean) == 64:  # 32 bytes = 64 hex chars
                        peer_public_keys_list.append(peer_key_clean)
                    else:
                        print(f'Warning: Peer key "{peer_key}" is not 64 hex characters (32 bytes)', file=sys.stderr)
                except Exception as e:
                    print(f'Warning: Failed to parse peer key "{peer_key}": {e}', file=sys.stderr)

            if peer_public_keys_list:
                key_store_data['peer_public_keys'] = peer_public_keys_list

        # Create key store if we have any keys
        if key_store_data:
            key_store = MeshCoreKeyStore(key_store_data)

        # Create decryption options
        options = DecryptionOptions(key_store=key_store) if key_store else None

        # Decode packet
        if args.verify:
            # Use async verification
            import asyncio
            loop = asyncio.get_event_loop()
            packet = loop.run_until_complete(
                MeshCoreDecoder.decode_with_verification(clean_hex, options)
            )
        else:
            packet = MeshCoreDecoder.decode(clean_hex, options)

        if args.json:
            # JSON output
            if args.structure:
                # Get structure as well
                if args.verify:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    structure = loop.run_until_complete(
                        MeshCoreDecoder.analyze_structure_with_verification(clean_hex, options)
                    )
                else:
                    structure = MeshCoreDecoder.analyze_structure(clean_hex, options)
                # Use to_dict() for proper serialization
                packet_dict = packet.to_dict() if hasattr(packet, 'to_dict') else packet.__dict__
                structure_dict = structure.__dict__ if hasattr(structure, '__dict__') else {}
                print(json.dumps({'packet': packet_dict, 'structure': structure_dict}, indent=2, default=str))
            else:
                # Use to_dict() for proper serialization
                packet_dict = packet.to_dict() if hasattr(packet, 'to_dict') else packet.__dict__
                print(json.dumps(packet_dict, indent=2, default=str))
        else:
            # Formatted output
            print_formatted_packet(packet, args.keys)

            # Show structure if requested
            if args.structure:
                print(f'\n{bold("=== Packet Structure ===")}')

                if args.verify:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    structure = loop.run_until_complete(
                        MeshCoreDecoder.analyze_structure_with_verification(clean_hex, options)
                    )
                else:
                    structure = MeshCoreDecoder.analyze_structure(clean_hex, options)

                print(f'\n{bold("Main Segments:")}')
                for i, seg in enumerate(structure.segments):
                    print(f'{i + 1}. {bold(seg.name)} (bytes {seg.start_byte}-{seg.end_byte}): {seg.value}')
                    if seg.description:
                        print(f'   {seg.description}')

                if structure.payload and structure.payload.get('segments'):
                    print(f'\n{bold("Payload Segments:")}')
                    for i, seg in enumerate(structure.payload['segments']):
                        print(f'{i + 1}. {bold(seg.name)} (bytes {seg.start_byte}-{seg.end_byte}): {seg.value}')
                        print(f'   {seg.description}')

    except Exception as error:
        print(f'Error: {error}', file=sys.stderr)
        sys.exit(1)


def validate_command(args):
    """Handle validate command"""
    try:
        # Clean up hex input
        clean_hex = args.hex.replace(' ', '').replace('0x', '').replace('0X', '')

        result = MeshCoreDecoder.validate(clean_hex)

        if result.is_valid:
            print('✅ Valid packet format')
            sys.exit(0)
        else:
            print('❌ Invalid packet format')
            if result.errors:
                for error in result.errors:
                    print(f'   {error}')
            sys.exit(1)

    except Exception as error:
        print(f'Error: {error}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
