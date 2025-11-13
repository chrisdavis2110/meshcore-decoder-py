# MeshCore Decoder - Python Port
[![PyPI](https://img.shields.io/pypi/v/meshcoredecoder?color=blue)](https://pypi.org/project/meshcoredecoder/) ![PyPI versions](https://img.shields.io/pypi/pyversions/meshcoredecoder)


A Python library for decoding MeshCore mesh networking packets with full cryptographic support. Complete Python implementation of the [MeshCore Packet Decoder](https://github.com/michaelhart/meshcore-decoder) by [Michael Hart](https://github.com/michaelhart).

## Features

- **Packet Decoding**: Decode MeshCore packets
- **Built-in Decryption**: Decrypt GroupText, TextMessage, and other encrypted payloads
- **Developer Friendly**: Python-first with full type hints and data classes

## Installation

### Install to a single project

```bash
pip install -r requirements.txt
```

### Install via pip (if published)

```bash
pip install meshcoredecoder
```

## Requirements

- `pycryptodome>=3.19.0` - Core cryptography (AES, HMAC)
- `cryptography>=41.0.0` - Ed25519 signature support
- `click>=8.1.0` - CLI improvements

## Quick Start

```python
from meshcoredecoder import MeshCoreDecoder
from meshcoredecoder.types.enums import PayloadType
from meshcoredecoder.utils.enum_names import get_route_type_name, get_payload_type_name, get_device_role_name
import json

# Decode a MeshCore packet
hex_data = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172'
packet = MeshCoreDecoder.decode(hex_data)

print(f"Route Type: {get_route_type_name(packet.route_type)}")
print(f"Payload Type: {get_payload_type_name(packet.payload_type)}")
print(f"Message Hash: {packet.message_hash}")

if packet.payload_type == PayloadType.Advert and packet.payload.get('decoded'):
    advert = packet.payload['decoded']
    print(f"Device Name: {advert.app_data.get('name')}")
    print(f"Device Role: {get_device_role_name(advert.app_data.get('device_role'))}")
    if advert.app_data.get('location'):
        location = advert.app_data['location']
        print(f"Location: {location['latitude']}, {location['longitude']}")
```

## Full Packet Structure Example

Here's what a complete decoded packet looks like:

```python
from meshcoredecoder import MeshCoreDecoder
import json

hex_data = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172'

packet = MeshCoreDecoder.decode(hex_data)

packet_dict = packet.to_dict()
print(json.dumps(packet_dict, indent=2, default=str))
```

**Output:**
```json
{
  "messageHash": "F9C060FE",
  "routeType": 1,
  "payloadType": 4,
  "payloadVersion": 0,
  "pathLength": 0,
  "path": null,
  "payload": {
    "raw": "7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172",
    "decoded": {
      "type": 4,
      "version": 0,
      "isValid": true,
      "publicKey": "7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400",
      "timestamp": 1758455660,
      "signature": "2E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E609",
      "appData": {
        "flags": 146,
        "deviceRole": 2,
        "hasLocation": true,
        "hasName": true,
        "location": {
          "latitude": 47.543968,
          "longitude": -122.108616
        },
        "name": "WW7STR/PugetMesh Cougar"
      }
    }
  },
  "totalBytes": 134,
  "isValid": true
}
```

## Decryption Support

Simply provide your channel secret keys and the library handles everything else:

```python
from meshcoredecoder import MeshCoreDecoder
from meshcoredecoder.crypto import MeshCoreKeyStore
from meshcoredecoder.types.crypto import DecryptionOptions
from meshcoredecoder.types.enums import PayloadType

# Create a key store with channel secret keys
key_store = MeshCoreKeyStore({
    'channel_secrets': [
        '8b3387e9c5cdea6ac9e5edbaa115cd72',  # Public channel (channel hash 11)
        'ff2b7d74e8d20f71505bda9ea8d59a1c',  # A different channel's secret
    ]
})

group_text_hex_data = '...'  # Your encrypted GroupText packet hex

# Decode encrypted GroupText message
options = DecryptionOptions(key_store=key_store)
encrypted_packet = MeshCoreDecoder.decode(group_text_hex_data, options)

if encrypted_packet.payload_type == PayloadType.GroupText and encrypted_packet.payload.get('decoded'):
    group_text = encrypted_packet.payload['decoded']

    if group_text.decrypted:
        print(f"Sender: {group_text.decrypted.get('sender')}")
        print(f"Message: {group_text.decrypted.get('message')}")
        print(f"Timestamp: {group_text.decrypted.get('timestamp')}")
    else:
        print('Message encrypted (no key available)')
```

The library automatically:
- Calculates channel hashes from your secret keys using SHA256
- Handles hash collisions (multiple keys with same first byte) by trying all matching keys
- Verifies message authenticity using HMAC-SHA256
- Decrypts using AES-128 ECB

### With Signature Verification

```python
import asyncio
from meshcoredecoder import MeshCoreDecoder

# Async verification for Ed25519 signatures
async def verify_packet():
    packet = await MeshCoreDecoder.decode_with_verification(hex_data)

    if packet.payload.get('decoded'):
        advert = packet.payload['decoded']
        if hasattr(advert, 'signature_valid'):
            print(f"Signature Valid: {advert.signature_valid}")

asyncio.run(verify_packet())
```

## Packet Structure Analysis

For detailed packet analysis and debugging, use `analyze_structure()` to get byte-level breakdowns:

```python
from meshcoredecoder import MeshCoreDecoder

print('=== Packet Breakdown ===')
hex_data = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172'

print(f"Packet length: {len(hex_data)}")
print(f"Expected bytes: {len(hex_data) / 2}")

structure = MeshCoreDecoder.analyze_structure(hex_data)
print('\nMain segments:')
for i, seg in enumerate(structure.segments):
    print(f"{i+1}. {seg.name} (bytes {seg.start_byte}-{seg.end_byte}): {seg.value}")

print('\nPayload segments:')
for i, seg in enumerate(structure.payload['segments']):
    print(f"{i+1}. {seg.name} (bytes {seg.start_byte}-{seg.end_byte}): {seg.value}")
    print(f"   Description: {seg.description}")
```

**Output:**
```
=== Packet Breakdown ===
Packet length: 268
Expected bytes: 134

Main segments:
1. Header (bytes 0-0): 0x11
2. Path Length (bytes 1-1): 0x00
3. Payload (bytes 2-133): 7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172

Payload segments:
1. Public Key (bytes 0-31): 7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400
   Description: Ed25519 public key
2. Timestamp (bytes 32-35): 6CE7CF68
   Description: 1758455660 (2025-09-21T11:54:20Z)
3. Signature (bytes 36-99): 2E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E609
   Description: Ed25519 signature
4. App Flags (bytes 100-100): 92
   Description: Binary: 10010010 | Bits 0-3 (Role): Room server | Bit 4 (Location): Yes | Bit 5 (Feature1): No | Bit 6 (Feature2): No | Bit 7 (Name): Yes
5. Latitude (bytes 101-104): A076D502
   Description: 47.543968° (47.543968)
6. Longitude (bytes 105-108): 38C5B8F8
   Description: -122.108616° (-122.108616)
7. Node Name (bytes 109-131): 5757375354522F50756765744D65736820436F75676172
   Description: Node name: "WW7STR/PugetMesh Cougar"
```

The `analyze_structure()` method provides:
- **Header breakdown** with bit-level field analysis
- **Byte-accurate segments** with start/end positions
- **Payload field parsing** for all supported packet types
- **Human-readable descriptions** for each field

## Ed25519 Key Derivation

The library includes MeshCore-compatible Ed25519 key derivation using the exact orlp/ed25519 algorithm:

```python
from meshcoredecoder.crypto import derive_public_key, validate_key_pair

# Derive public key from MeshCore private key (64-byte format)
private_key = '18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5'

public_key = derive_public_key(private_key)
print('Derived Public Key:', public_key)
# Output: 4852B69364572B52EFA1B6BB3E6D0ABED4F389A1CBFBB60A9BBA2CCE649CAF0E

# Validate a key pair
is_valid = validate_key_pair(private_key, public_key)
print('Key pair valid:', is_valid)  # True
```

## Command Line Interface

For quick analysis from the terminal, use the CLI:

```bash
# Analyze a packet
python cli.py decode 11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172

# With decryption (provide channel secrets)
python cli.py decode 150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D --key 8b3387e9c5cdea6ac9e5edbaa115cd72

# Show detailed structure analysis
python cli.py decode --structure 11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172

# JSON output
python cli.py decode --json 11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172

# Derive public key from MeshCore private key
python cli.py derive-key 18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5

# Validate key pair
python cli.py validate-key 18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5 4852b69364572b52efa1b6bb3e6d0abed4f389a1cbfbb60a9bba2cce649caf0e
```




## License

MIT License

Copyright (c) 2025 Michael Hart <michaelhart@michaelhart.me> (https://github.com/michaelhart)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
