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
from meshcoredecoder.utils.enum_names import get_route_type_name, get_payload_type_name, get_device_role_name, get_request_type_name
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
    """Show details for all payload types"""
    from datetime import datetime

    payload_type = payload.type
    print(f'{bold("Payload Type:")} {get_payload_type_name(payload_type)}')
    print(f'{bold("Payload Version:")} {payload.version.value}')
    print(f'{bold("Valid:")} {"✅" if payload.is_valid else "❌"}')

    if payload.errors:
        print(f'{bold("Errors:")}')
        for error in payload.errors:
            print(f'  ❌ {error}')

    # Show payload-specific fields
    if payload_type == PayloadType.Advert:
        advert = payload
        print(f'\n{bold("=== Advert Payload Data ===")}')
        print(f'{bold("Public Key:")} {advert.public_key}')
        print(f'{bold("Timestamp:")} {datetime.fromtimestamp(advert.timestamp).isoformat()}')
        print(f'{bold("Signature:")} {advert.signature}')

        # Show signature verification status
        if advert.signature_valid is not None:
            if advert.signature_valid:
                print(f'{bold("Signature Status:")} ✅ Valid Ed25519 signature')
            else:
                print(f'{bold("Signature Status:")} ❌ Invalid Ed25519 signature')
                if advert.signature_error:
                    print(f'{bold("Signature Error:")} {advert.signature_error}')
        else:
            print(f'{bold("Signature Status:")} ⚠️ Not verified (use --verify flag)')

        print(f'\n{bold("App Data:")}')
        print(f'  {bold("Device Role:")} {get_device_role_name(advert.app_data["device_role"])}')
        if advert.app_data.get('name'):
            print(f'  {bold("Device Name:")} {advert.app_data["name"]}')
        if advert.app_data.get('location'):
            loc = advert.app_data['location']
            print(f'  {bold("Location:")} {loc["latitude"]}, {loc["longitude"]}')
        if advert.app_data.get('battery_voltage') is not None:
            print(f'  {bold("Battery Voltage:")} {advert.app_data["battery_voltage"]} V')

    elif payload_type == PayloadType.GroupText:
        group_text = payload
        print(f'\n{bold("=== GroupText Payload Data ===")}')
        print(f'{bold("Channel Hash:")} {group_text.channel_hash}')
        print(f'{bold("Cipher MAC:")} {group_text.cipher_mac}')
        print(f'{bold("Ciphertext Length:")} {group_text.ciphertext_length} bytes')
        print(f'{bold("Ciphertext:")} {group_text.ciphertext[:64]}...' if len(group_text.ciphertext) > 64 else f'{bold("Ciphertext:")} {group_text.ciphertext}')

        if group_text.decrypted:
            print(f'\n{bold("🔓 Decrypted Message:")}')
            if group_text.decrypted.get('sender'):
                print(f'  {bold("Sender:")} {group_text.decrypted["sender"]}')
            print(f'  {bold("Message:")} {group_text.decrypted["message"]}')
            print(f'  {bold("Timestamp:")} {datetime.fromtimestamp(group_text.decrypted["timestamp"]).isoformat()}')
        else:
            print(f'\n{bold("Decryption Status:")} 🔒 Encrypted (no key available)')

    elif payload_type == PayloadType.Trace:
        trace = payload
        print(f'\n{bold("=== Trace Payload Data ===")}')
        print(f'{bold("Trace Tag:")} {trace.trace_tag}')
        print(f'{bold("Auth Code:")} {trace.auth_code}')
        print(f'{bold("Flags:")} 0x{trace.flags:02x}')

        # Show path with SNR per hop
        if trace.path_hashes and len(trace.path_hashes) > 0:
            print(f'\n{bold("Path (with SNR per hop):")}')
            path_with_snr = trace.get_path_with_snr()
            for hop_info in path_with_snr:
                hop_num = hop_info.get('hop', 0)
                node_hash = hop_info.get('nodeHash', '')
                snr = hop_info.get('snr')
                if snr is not None:
                    print(f'  Hop {hop_num}: Node {node_hash} → SNR: {snr:.1f}dB')
                else:
                    print(f'  Hop {hop_num}: Node {node_hash} → SNR: N/A')

        # Also show SNR values as a list
        if trace.snr_values and len(trace.snr_values) > 0:
            snr_str = ', '.join([f'{snr:.1f}dB' for snr in trace.snr_values])
            print(f'\n{bold("SNR Values (all):")} {snr_str}')

    elif payload_type == PayloadType.Request:
        request = payload
        print(f'\n{bold("=== Request Payload Data ===")}')
        print(f'{bold("Destination Hash:")} {request.destination_hash}')
        print(f'{bold("Source Hash:")} {request.source_hash}')
        print(f'{bold("Cipher MAC:")} {request.cipher_mac}')
        print(f'{bold("Ciphertext:")} {request.ciphertext[:64]}...' if len(request.ciphertext) > 64 else f'{bold("Ciphertext:")} {request.ciphertext}')

        if request.decrypted:
            print(f'\n{bold("🔓 Decrypted Request:")}')
            print(f'  {bold("Timestamp:")} {datetime.fromtimestamp(request.timestamp).isoformat()}')
            print(f'  {bold("Request Type:")} {get_request_type_name(request.request_type)}')
            if request.request_data:
                print(f'  {bold("Request Data:")} {request.request_data}')
        else:
            print(f'\n{bold("Decryption Status:")} 🔒 Encrypted (no key available)')

    elif payload_type == PayloadType.Response:
        response = payload
        print(f'\n{bold("=== Response Payload Data ===")}')
        print(f'{bold("Destination Hash:")} {response.destination_hash}')
        print(f'{bold("Source Hash:")} {response.source_hash}')
        print(f'{bold("Cipher MAC:")} {response.cipher_mac}')
        print(f'{bold("Ciphertext Length:")} {response.ciphertext_length} bytes')
        print(f'{bold("Ciphertext:")} {response.ciphertext[:64]}...' if len(response.ciphertext) > 64 else f'{bold("Ciphertext:")} {response.ciphertext}')

        if response.tag is not None:
            print(f'{bold("Tag:")} {response.tag}')

        if response.decrypted:
            # Check if decryption failed with an error
            if 'error' in response.decrypted:
                print(f'\n{bold("Decryption Status:")} ❌ {response.decrypted["error"]}')
            else:
                print(f'\n{bold("🔓 Decrypted Response:")}')
                # Show total count if available
                if 'totalNeighborCount' in response.decrypted:
                    print(f'  {bold("Total Neighbors Available:")} {response.decrypted["totalNeighborCount"]}')
                for key, value in response.decrypted.items():
                    if key != 'error' and key != 'totalNeighborCount':
                        print(f'  {bold(key + ":")} {value}')
        else:
            print(f'\n{bold("Decryption Status:")} 🔒 Encrypted (no key available)')
            print(f'  {bold("Tip:")} Use --node-key PUBKEY:PRIVKEY to provide decryption keys')

        if response.neighbors and len(response.neighbors) > 0:
            print(f'\n{bold("Neighbors:")} {len(response.neighbors)} entries')
            for i, neighbor in enumerate(response.neighbors):  # Show first 10
                print(f'  {i+1}. Node: {neighbor.node_id[:16]}...')
                print(f'     Timestamp: {datetime.fromtimestamp(neighbor.advert_timestamp).isoformat()}')
                # print(f'     Heard Timestamp: {datetime.fromtimestamp(neighbor.heard_timestamp).isoformat()}')
                print(f'     SNR: {neighbor.snr/4:.2f}dB')
            # if len(response.neighbors) > 10:
            #     print(f'  ... and {len(response.neighbors) - 10} more')

    elif payload_type == PayloadType.TextMessage:
        text_msg = payload
        print(f'\n{bold("=== TextMessage Payload Data ===")}')
        print(f'{bold("Destination Hash:")} {text_msg.destination_hash}')
        print(f'{bold("Source Hash:")} {text_msg.source_hash}')
        print(f'{bold("Cipher MAC:")} {text_msg.cipher_mac}')
        print(f'{bold("Ciphertext Length:")} {text_msg.ciphertext_length} bytes')
        print(f'{bold("Ciphertext:")} {text_msg.ciphertext[:64]}...' if len(text_msg.ciphertext) > 64 else f'{bold("Ciphertext:")} {text_msg.ciphertext}')

        if text_msg.decrypted:
            # Check if decryption failed with an error
            if 'error' in text_msg.decrypted:
                print(f'\n{bold("Decryption Status:")} ❌ {text_msg.decrypted["error"]}')
            else:
                print(f'\n{bold("🔓 Decrypted Message:")}')
                for key, value in text_msg.decrypted.items():
                    if key == 'timestamp':
                        print(f'  {bold("Timestamp:")} {datetime.fromtimestamp(value).isoformat()}')
                    elif key == 'flags':
                        print(f'  {bold("Flags:")} 0x{value:02x}')
                    elif key == 'message':
                        print(f'  {bold("Message:")} {value}')
                    elif key != 'error' and key != 'raw':
                        print(f'  {bold(key + ":")} {value}')
                if 'raw' in text_msg.decrypted:
                    print(f'  {bold("Raw (hex):")} {text_msg.decrypted["raw"]}')
        else:
            print(f'\n{bold("Decryption Status:")} 🔒 Encrypted (no key available)')
            print(f'  {bold("Tip:")} Use --node-key PUBKEY:PRIVKEY to provide decryption keys')

    elif payload_type == PayloadType.AnonRequest:
        anon_req = payload
        print(f'\n{bold("=== AnonRequest Payload Data ===")}')
        print(f'{bold("Destination Hash:")} {anon_req.destination_hash}')
        print(f'{bold("Sender Public Key:")} {anon_req.sender_public_key}')
        print(f'{bold("Cipher MAC:")} {anon_req.cipher_mac}')
        print(f'{bold("Ciphertext Length:")} {anon_req.ciphertext_length} bytes')
        print(f'{bold("Ciphertext:")} {anon_req.ciphertext[:64]}...' if len(anon_req.ciphertext) > 64 else f'{bold("Ciphertext:")} {anon_req.ciphertext}')

        if anon_req.decrypted:
            print(f'\n{bold("🔓 Decrypted Request:")}')
            for key, value in anon_req.decrypted.items():
                if key == 'timestamp':
                    print(f'  {bold("Timestamp:")} {datetime.fromtimestamp(value).isoformat()}')
                else:
                    print(f'  {bold(key + ":")} {value}')
        else:
            print(f'\n{bold("Decryption Status:")} 🔒 Encrypted (no key available)')

    elif payload_type == PayloadType.Ack:
        ack = payload
        print(f'\n{bold("=== Ack Payload Data ===")}')
        print(f'{bold("Checksum:")} {ack.checksum}')

    elif payload_type == PayloadType.Path:
        path_payload = payload
        print(f'\n{bold("=== Path Payload Data ===")}')
        print(f'{bold("Path Length:")} {path_payload.path_length} bytes')
        if path_payload.path_hashes and len(path_payload.path_hashes) > 0:
            print(f'{bold("Path Hashes:")} {" → ".join(path_payload.path_hashes)}')
        print(f'{bold("Extra Type:")} 0x{path_payload.extra_type:02x}')
        if path_payload.extra_data:
            print(f'{bold("Extra Data:")} {path_payload.extra_data[:64]}...' if len(path_payload.extra_data) > 64 else f'{bold("Extra Data:")} {path_payload.extra_data}')

    else:
        # Generic fallback for any other payload types
        print(f'\n{bold("=== Payload Data ===")}')
        # Show all attributes of the payload object
        attrs = [attr for attr in dir(payload) if not attr.startswith('_') and not callable(getattr(payload, attr, None))]
        for attr in attrs:
            try:
                value = getattr(payload, attr)
                if value is not None and attr not in ['type', 'version', 'is_valid', 'errors']:
                    # Format the value nicely
                    if isinstance(value, list) and len(value) > 0:
                        if len(value) <= 5:
                            print(f'{bold(attr + ":")} {value}')
                        else:
                            print(f'{bold(attr + ":")} [{len(value)} items] {value[:3]} ... {value[-2:]}')
                    elif isinstance(value, dict):
                        print(f'{bold(attr + ":")} {len(value)} keys')
                    elif isinstance(value, str) and len(value) > 64:
                        print(f'{bold(attr + ":")} {value[:64]}...')
                    else:
                        print(f'{bold(attr + ":")} {value}')
            except Exception:
                pass


def bold(text: str) -> str:
    """Make text bold (simple version without colorama)"""
    return f'\033[1m{text}\033[0m'


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
    decode_parser.add_argument('-k', '--key', action='append', dest='keys', help='Channel secret keys for decryption (hex)')
    decode_parser.add_argument('--node-key', action='append', dest='node_keys', help='Node key pair for Request/Response/TextMessage decryption (format: PUBKEY:PRIVKEY or PUBKEY,PRIVKEY). For Response decryption with key exchange, use SENDER_PUBKEY:OUR_PRIVKEY')
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
        has_keys = False
        key_store_config = {}

        # Add channel secrets if provided
        if args.keys and len(args.keys) > 0:
            key_store_config['channel_secrets'] = args.keys
            has_keys = True

        # Add node keys if provided
        if args.node_keys and len(args.node_keys) > 0:
            node_keys_dict = {}
            for node_key_arg in args.node_keys:
                # Support formats: PUBKEY:PRIVKEY or PUBKEY,PRIVKEY
                if ':' in node_key_arg:
                    pub_key, priv_key = node_key_arg.split(':', 1)
                elif ',' in node_key_arg:
                    pub_key, priv_key = node_key_arg.split(',', 1)
                else:
                    print(f'Error: Invalid node key format: {node_key_arg}', file=sys.stderr)
                    print('Expected format: PUBKEY:PRIVKEY or PUBKEY,PRIVKEY', file=sys.stderr)
                    sys.exit(1)

                # Clean up hex strings
                pub_key = pub_key.replace(' ', '').replace('0x', '').replace('0X', '')
                priv_key = priv_key.replace(' ', '').replace('0x', '').replace('0X', '')

                node_keys_dict[pub_key] = priv_key

            if node_keys_dict:
                key_store_config['node_keys'] = node_keys_dict
                has_keys = True

        if has_keys:
            key_store = MeshCoreKeyStore(key_store_config)

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
                print(json.dumps({'packet': packet.__dict__, 'structure': structure.__dict__}, indent=2, default=str))
            else:
                print(json.dumps(packet.__dict__, indent=2, default=str))
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
