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
from src.decoder.packet_decoder import MeshCorePacketDecoder
from src.crypto.key_manager import MeshCoreKeyStore
from src.types.crypto import DecryptionOptions
from src.utils.enum_names import get_route_type_name, get_payload_type_name, get_device_role_name
from src.types.enums import PayloadType


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
        print(f'{bold("Device Role:")} {get_device_role_name(advert.app_data["device_role"])}')

        if advert.app_data.get('name'):
            print(f'{bold("Device Name:")} {advert.app_data["name"]}')

        if advert.app_data.get('location'):
            loc = advert.app_data['location']
            print(f'{bold("Location:")} {loc["latitude"]}, {loc["longitude"]}')

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
        print(f'{bold("Channel Hash:")} {group_text.channel_hash}')

        if group_text.decrypted:
            print(f'{bold("🔓 Decrypted Message:")}')
            if group_text.decrypted.get('sender'):
                print(f'{bold("Sender:")} {group_text.decrypted["sender"]}')
            print(f'{bold("Message:")} {group_text.decrypted["message"]}')
            print(f'{bold("Timestamp:")} {datetime.fromtimestamp(group_text.decrypted["timestamp"]).isoformat()}')
        else:
            print('🔒 Encrypted (no key available)')
            print(f'{bold("Ciphertext:")} {group_text.ciphertext[:32]}...')

    elif payload_type == PayloadType.Trace:
        trace = payload
        print(f'{bold("Trace Tag:")} {trace.trace_tag}')
        print(f'{bold("Auth Code:")} {trace.auth_code}')
        if trace.snr_values and len(trace.snr_values) > 0:
            snr_str = ', '.join([f'{snr:.1f}dB' for snr in trace.snr_values])
            print(f'{bold("SNR Values:")} {snr_str}')

    else:
        print(f'{bold("Type:")} {get_payload_type_name(payload_type)}')
        print(f'{bold("Valid:")} {"✅" if payload.is_valid else "❌"}')


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
        if args.keys and len(args.keys) > 0:
            key_store = MeshCoreKeyStore({
                'channel_secrets': args.keys
            })

        # Create decryption options
        options = DecryptionOptions(key_store=key_store) if key_store else None

        # Decode packet
        if args.verify:
            # Use async verification
            import asyncio
            loop = asyncio.get_event_loop()
            packet = loop.run_until_complete(
                MeshCorePacketDecoder.decode_with_verification(clean_hex, options)
            )
        else:
            packet = MeshCorePacketDecoder.decode(clean_hex, options)

        if args.json:
            # JSON output
            if args.structure:
                # Get structure as well
                if args.verify:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    structure = loop.run_until_complete(
                        MeshCorePacketDecoder.analyze_structure_with_verification(clean_hex, options)
                    )
                else:
                    structure = MeshCorePacketDecoder.analyze_structure(clean_hex, options)
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
                        MeshCorePacketDecoder.analyze_structure_with_verification(clean_hex, options)
                    )
                else:
                    structure = MeshCorePacketDecoder.analyze_structure(clean_hex, options)

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

        result = MeshCorePacketDecoder.validate(clean_hex)

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
