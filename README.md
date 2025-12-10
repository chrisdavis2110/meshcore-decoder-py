# MeshCore Decoder - Python Port
[![PyPI](https://img.shields.io/pypi/v/meshcoredecoder?color=blue)](https://pypi.org/project/meshcoredecoder/)


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
hex_data = '11007E76...'
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

hex_data = '11007E766...'

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
from meshcoredecoder import MeshCoreDecoder

# Verify Ed25519 signatures
packet = MeshCoreDecoder.decode_with_verification(hex_data)

if packet.payload.get('decoded'):
    advert = packet.payload['decoded']
    if hasattr(advert, 'signature_valid'):
        print(f"Signature Valid: {advert.signature_valid}")
```

## Trace Packets and SNR Analysis

Trace packets include Signal-to-Noise Ratio (SNR) values collected at each hop along the path. The library automatically extracts and correlates SNR values with path hashes:

```python
from meshcoredecoder import MeshCoreDecoder
from meshcoredecoder.types.enums import PayloadType

trace_hex_data = '...'  # Your Trace packet hex
packet = MeshCoreDecoder.decode(trace_hex_data)

if packet.payload_type == PayloadType.Trace and packet.payload.get('decoded'):
    trace = packet.payload['decoded']

    # Get path with SNR per hop
    path_with_snr = trace.get_path_with_snr()
    for hop_info in path_with_snr:
        print(f"Hop {hop_info['hop']}: Node {hop_info['nodeHash']} → SNR: {hop_info['snr']:.1f}dB")

    # Or access SNR values directly
    if trace.snr_values:
        print(f"SNR values: {trace.snr_values}")
```

**Note:** SNR values are stored in the packet's path field as signed int8 values multiplied by 4, and are automatically converted to dB by the decoder. Each SNR value corresponds to the signal quality at that hop in the path.

### SNR Data Sources

SNR (Signal-to-Noise Ratio) data is available from multiple packet types:

1. **TRACE Packets** (already supported) - SNR values for each hop in the path
2. **GetStats Response Packets** (just implemented) - Full neighbor table with SNR values
3. **DISCOVER_RESP Control Packets** (not yet implemented) - SNR in discovery responses

### How GetStats Works

GetStats is a request/response protocol used to query a repeater node for its neighbor table and statistics. Here's how it works:

**1. Sending a GetStats Request:**
- Create a Request packet with `RequestType.GetStats` (0x01)
- The request payload contains:
  - **Destination hash** (1 byte): First byte of target repeater's public key
  - **Source hash** (1 byte): First byte of your public key
  - **Cipher MAC** (2 bytes): MAC for encrypted data
  - **Ciphertext**: Encrypted data containing:
    - Timestamp (4 bytes, Unix timestamp)
    - Request type (1 byte, 0x01 for GetStats)
    - Request data (optional, empty for GetStats)

**2. Receiving a Neighbor List Response:**
- The target repeater responds with a Response packet
- The response payload contains (encrypted):
  - **sender_timestamp** (4 bytes): Unix timestamp when response was created
  - **neighbours_count** (2 bytes): Total number of neighbors available
  - **results_count** (2 bytes): Number of neighbors in this packet
  - **Neighbor entries**: Array of neighbor entries, each containing:
    - pubkey_prefix (1-32 bytes): Public key prefix (length depends on request)
    - heard_seconds_ago (4 bytes): Seconds since neighbor was last heard
    - snr (1 byte): Signal-to-Noise Ratio (int8_t, direct value)

**3. Decoding the Response:**
The decoder automatically extracts neighbor table data when you provide the appropriate node key for decryption.

### Neighbor Table Data from Response Packets

Response payloads from neighbor list requests contain the **full neighbor table** with SNR values. This is the most comprehensive source of neighbor/SNR data. When decrypted with the appropriate node key, the decoder automatically extracts neighbor information:

```python
from meshcoredecoder import MeshCoreDecoder
from meshcoredecoder.types.enums import PayloadType
from meshcoredecoder.types.crypto import DecryptionOptions
from meshcoredecoder.crypto.key_manager import MeshCoreKeyStore
from datetime import datetime

# Create a key store with node keys
# Format: PUBKEY:PRIVKEY or PUBKEY,PRIVKEY
# The public key should match the sender's public key for decryption
key_store = MeshCoreKeyStore()
key_store.add_node_key(
    public_key='969605...',  # 32-byte Ed25519 public key (hex)
    private_key='1010fe...'  # 64-byte Ed25519 private key (hex)
)

# Decode a Response packet with decryption
response_hex = '06002E...'
options = DecryptionOptions(key_store=key_store)
response_packet = MeshCoreDecoder.decode(response_hex, options)

if response_packet.payload_type == PayloadType.Response and response_packet.payload.get('decoded'):
    response = response_packet.payload['decoded']

    # Access decrypted response data
    if response.decrypted:
        if 'totalNeighborCount' in response.decrypted:
            print(f"Total neighbors available: {response.decrypted['totalNeighborCount']}")
        if 'neighborCount' in response.decrypted:
            print(f"Neighbors in this packet: {response.decrypted['neighborCount']}")

    # Access neighbor table with SNR values
    if response.neighbors:
        print(f"\nFound {len(response.neighbors)} neighbors:")
        for i, neighbor in enumerate(response.neighbors, 1):
            print(f"\n  Neighbor {i}:")
            print(f"    Node ID (pubkey prefix): {neighbor.node_id}")
            print(f"    SNR: {neighbor.snr:.1f} dB")
            print(f"    Timestamp: {datetime.fromtimestamp(neighbor.advert_timestamp).isoformat()}")

            # Calculate time since last heard
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).timestamp()
            seconds_ago = int(now - neighbor.heard_timestamp) if neighbor.heard_timestamp > 0 else 0
            print(f"    Last heard: {seconds_ago} seconds ago")

    # Access NeighborEntry properties
    # Each neighbor is a NeighborEntry object with:
    # - node_id: str (hex string of pubkey prefix)
    # - advert_timestamp: int (Unix timestamp)
    # - heard_timestamp: int (Unix timestamp)
    # - snr: float (SNR in dB, direct int8_t value)

    # Convert to dictionary for JSON serialization
    if response.neighbors:
        neighbors_json = [neighbor.to_dict() for neighbor in response.neighbors]
        print(f"\nNeighbors as JSON:")
        import json
        print(json.dumps(neighbors_json, indent=2))
```

**Response Packet Structure (after decryption):**
```
Byte 0-3:   sender_timestamp (uint32_t, little-endian)
Byte 4-5:   neighbours_count (uint16_t, little-endian) - total available
Byte 6-7:   results_count (uint16_t, little-endian) - in this packet
Byte 8+:    Array of neighbor entries, each entry:
            - pubkey_prefix (variable length, 1-32 bytes)
            - heard_seconds_ago (uint32_t, little-endian, 4 bytes)
            - snr (int8_t, 1 byte)
```

**Neighbor Entry Format:**
- **pubkey_prefix**: First N bytes of the neighbor's public key (typically 1 or 4 bytes in compressed format)
- **heard_seconds_ago**: Seconds since the neighbor was last heard (relative to sender_timestamp)
- **snr**: Signal-to-noise ratio as signed int8_t (range: -128 to 127 dB)

**Timestamp Calculation:**
- `timestamp = sender_timestamp - heard_seconds_ago`

**Neighbor List Request/Response Flow:**
1. **Client** sends encrypted Request packet with neighbor list request to target repeater
2. **Repeater** receives request, decrypts it, and processes the request
3. **Repeater** responds with encrypted Response packet containing:
   - sender_timestamp: When the response was created
   - neighbours_count: Total number of neighbors available
   - results_count: Number of neighbors in this packet
   - Neighbor entries: Array of neighbor data with pubkey_prefix, heard_seconds_ago, and SNR
4. **Client** decrypts response using node key (sender's public key + client's private key) to access neighbor table data

**How Repeaters Define Neighbors:**
- Repeaters detect neighbors through zero-hop ADVERT packets broadcast periodically
- When a repeater receives an advertisement, it stores:
  - **Node ID**: Public key prefix (1-32 bytes, depending on request)
  - **Heard Timestamp**: Calculated as `sender_timestamp - heard_seconds_ago`
  - **Advert Timestamp**: Same as heard_timestamp
  - **SNR**: Signal-to-Noise Ratio (stored directly as int8_t)

**SNR Storage Format:**
- Format: `int8_t` (signed 8-bit integer)
- Encoding: Direct value (not multiplied)
- Range: -128 dB to 127 dB
- Usage: `snr_dB = raw_value` (no conversion needed)

**Comparison of SNR Data Sources:**

| Source | SNR Data | Additional Data | Requires Decryption |
|--------|---------|-----------------|---------------------|
| **TRACE Packets** | ✅ Path SNR per hop | Path hashes, trace tag | ❌ No |
| **Response Packets** | ✅ Neighbor SNR | Full neighbor table (pubkey prefixes, timestamps) | ✅ Yes (node key) |
| **DISCOVER_RESP** | ✅ SNR | Node info, tag | ❌ No (not yet implemented) |

**Note:** Response packets are the only source that provides the complete neighbor table with pubkey prefixes, timestamps, and SNR values. TRACE packets provide SNR for the specific path taken, but not the full neighbor table.

**NeighborEntry Object:**

Each neighbor in `response.neighbors` is a `NeighborEntry` object with the following properties:

```python
class NeighborEntry:
    node_id: str              # Pubkey prefix as hex string (1-32 bytes, typically 1 or 4 bytes)
    advert_timestamp: int      # Unix timestamp (same as heard_timestamp)
    heard_timestamp: int      # Unix timestamp (calculated from sender_timestamp - heard_seconds_ago)
    snr: float                # SNR in dB (direct int8_t value, range: -128 to 127)

    def to_dict() -> Dict     # Convert to dictionary for JSON serialization
```

**Example: Filtering and Processing Neighbors:**

```python
# Filter neighbors by SNR threshold
strong_neighbors = [n for n in response.neighbors if n.snr > 10.0]
print(f"Neighbors with SNR > 10 dB: {len(strong_neighbors)}")

# Sort by SNR (strongest first)
sorted_neighbors = sorted(response.neighbors, key=lambda n: n.snr, reverse=True)
print("\nNeighbors sorted by SNR (strongest first):")
for neighbor in sorted_neighbors[:5]:  # Top 5
    print(f"  {neighbor.node_id[:8]}...: {neighbor.snr:.1f} dB")

# Find recently heard neighbors (within last hour)
from datetime import datetime, timezone, timedelta
one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()
recent = [n for n in response.neighbors if n.heard_timestamp > one_hour_ago]
print(f"\nNeighbors heard in last hour: {len(recent)}")
```

**Using the CLI to Decode Response Packets:**

```bash
# Decode a response packet with neighbor data
python cli.py decode <packet_hex> --node-key <PUBKEY>:<PRIVKEY>

# Example:
python cli.py decode 06002E... --node-key 969605...:1010fe...
```

The CLI will automatically:
- Decrypt the response using the provided node key
- Parse the neighbor entries
- Display total neighbors available and neighbors in the packet
- Show each neighbor's pubkey prefix, SNR, and timestamps

## Packet Structure Analysis

For detailed packet analysis and debugging, use `analyze_structure()` to get byte-level breakdowns:

```python
from meshcoredecoder import MeshCoreDecoder

print('=== Packet Breakdown ===')
hex_data = '11007E7662...'

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
3. Payload (bytes 2-133): 7E7662676F7F...

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
private_key = '18469d614044...'

public_key = derive_public_key(private_key)
print('Derived Public Key:', public_key)
# Output: 4852B693645...

# Validate a key pair
is_valid = validate_key_pair(private_key, public_key)
print('Key pair valid:', is_valid)  # True
```

## Command Line Interface

For quick analysis from the terminal, use the CLI:

```bash
# Analyze a packet
python cli.py decode 11007E7662676...

# With decryption (provide channel secrets)
python cli.py decode 150011C3C... --key 8b3387e9c...

# Show detailed structure analysis
python cli.py decode --structure 11007E7662676F7...

# JSON output
python cli.py decode --json 11007E7662676F7F085...

# Derive public key from MeshCore private key
python cli.py derive-key 18469d6140447f77...

# Validate key pair
python cli.py validate-key 18469d6140447f77de13... 4852b69...
```

## Packet Type Examples

Here are examples of how to decode all supported packet types using the Python API in your own scripts. These examples use real test packets from the test suite.

### Setup: Create Key Store

First, set up your keys for decryption:

```python
from meshcoredecoder import MeshCoreDecoder
from meshcoredecoder.crypto import MeshCoreKeyStore
from meshcoredecoder.types.crypto import DecryptionOptions
from meshcoredecoder.types.enums import PayloadType
from datetime import datetime

# Test keys (truncated for readability)
NODE_KEY = "2e5c4e32...:1010fe34..."
PEER_KEY = "969605c0..."
CHANNEL_KEY = "9cd8fcf2..."

# Create key store for encrypted packets
key_store = MeshCoreKeyStore()
key_store.add_node_key(
    "2e5c4e32...",
    "1010fe34..."
)
key_store.add_peer_key("969605c0...")
key_store.add_channel_secret("9cd8fcf2...")

decryption_options = DecryptionOptions(key_store=key_store)
```

### Request/Response Packets

#### GET_STATS Request
```python
packet_hex = "0200962E8AD0F2E571B007FF696A06BFEE285ADB5394"  # ... (truncated)
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.Request:
    request = packet.payload['decoded']
    print(f"Request Type: {request.request_type}")
    print(f"Timestamp: {datetime.fromtimestamp(request.timestamp)}")
```

#### GET_STATS Response
```python
packet_hex = "06002E963EB..."  # ... (truncated)
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.Response:
    response = packet.payload['decoded']
    if response.decrypted and response.decrypted.get('content', {}).get('type') == 'stats':
        print("Response Type: Stats")
        print(f"Tag: {response.decrypted['tag']}")
        # Stats data is in response.decrypted['content']['stats_data']
```

#### GET_NEIGHBOURS Request
```python
packet_hex = "0200962E..."  # ... (truncated)
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.Request:
    request = packet.payload['decoded']
    if request.request_type == 0x06:  # GetNeighbours
        print(f"Request Type: GetNeighbours")
        print(f"Count: {request.request_data.get('count')}")
        print(f"Offset: {request.request_data.get('offset')}")
```

#### GET_NEIGHBOURS Response
```python
packet_hex = "06002E960D..."  # ... (truncated)
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.Response:
    response = packet.payload['decoded']
    if response.decrypted:
        content = response.decrypted.get('content', {})
        if content.get('type') == 'neighbours':
            print(f"Total Neighbours: {content.get('neighbours_count')}")
            print(f"Results in Response: {content.get('results_count')}")
            for i, neighbor in enumerate(content.get('neighbors', []), 1):
                print(f"  {i}. {neighbor.get('pubkey_prefix')} - SNR: {neighbor.get('snr')/4.0:.2f} dB")
```

#### GET_TELEMETRY_DATA Request
```python
packet_hex = "020096..."  # ... (truncated)
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.Request:
    request = packet.payload['decoded']
    if request.request_type == 0x03:  # GetTelemetryData
        print(f"Request Type: GetTelemetryData")
        print(f"Permission Mask: {request.request_data.get('permission_mask_hex')}")
```

#### GET_TELEMETRY_DATA Response
```python
packet_hex = "06002E9..."  # ... (truncated)
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.Response:
    response = packet.payload['decoded']
    if response.decrypted:
        content = response.decrypted.get('content', {})
        if content.get('type') == 'telemetry':
            print("Response Type: Telemetry")
            print(f"Telemetry Data: {content.get('telemetry_data')}")
            # Parse LPP format telemetry data
```

### Unencrypted Packets

#### Advert
```python
packet_hex = "1107D978C2..."  # ... (truncated)
packet = MeshCoreDecoder.decode(packet_hex)

if packet.payload_type == PayloadType.Advert:
    advert = packet.payload['decoded']
    print(f"Device Name: {advert.app_data.get('name')}")
    print(f"Device Role: {advert.app_data.get('device_role')}")
    if advert.app_data.get('location'):
        loc = advert.app_data['location']
        print(f"Location: {loc['latitude']}, {loc['longitude']}")
    print(f"Timestamp: {datetime.fromtimestamp(advert.timestamp)}")
```

#### ACK
```python
packet_hex = "0D055..."
packet = MeshCoreDecoder.decode(packet_hex)

if packet.payload_type == PayloadType.Ack:
    ack = packet.payload['decoded']
    print(f"Checksum: 0x{ack.checksum:08X}")
```

#### Trace
```python
packet_hex = "260..."
packet = MeshCoreDecoder.decode(packet_hex)

if packet.payload_type == PayloadType.Trace:
    trace = packet.payload['decoded']
    print(f"Trace Tag: 0x{trace.trace_tag:08X}")
    print(f"Path Hashes: {' → '.join(trace.path_hashes)}")
    if trace.snr_values:
        print("SNR Values:")
        for i, snr in enumerate(trace.snr_values, 1):
            print(f"  Hop {i}: {snr:.1f} dB")
```

### Encrypted Packets (Require Keys)

#### GroupText
```python
packet_hex = "15062B0..."  # ... (truncated)
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.GroupText:
    group_text = packet.payload['decoded']
    if group_text.decrypted:
        print(f"Sender: {group_text.decrypted.get('sender')}")
        print(f"Message: {group_text.decrypted.get('message')}")
        print(f"Timestamp: {datetime.fromtimestamp(group_text.decrypted.get('timestamp', 0))}")
    else:
        print("Message encrypted (no key available)")
```

#### TextMessage
```python
packet_hex = "0A002..."  # ... (truncated)
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.TextMessage:
    text_msg = packet.payload['decoded']
    if text_msg.decrypted:
        print(f"Message: {text_msg.decrypted.get('message')}")
        print(f"Text Type: {text_msg.decrypted.get('text_type')}")
        print(f"Timestamp: {datetime.fromtimestamp(text_msg.decrypted.get('timestamp', 0))}")
```

#### Path
```python
packet_hex = "2105D..."
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.Path:
    path = packet.payload['decoded']
    print(f"Destination Hash: {path.destination_hash}")
    print(f"Source Hash: {path.source_hash}")
    if path.decrypted:
        print(f"Decrypted Path Data: {path.decrypted}")
    else:
        print("Path encrypted (decryption may have failed)")
```

#### AnonRequest (Login)
```python
packet_hex = "1E013..."  # ... (truncated)
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.AnonRequest:
    anon_req = packet.payload['decoded']
    print(f"Sender Public Key: {anon_req.sender_public_key}")
    print(f"Destination Hash: {anon_req.destination_hash}")
    if anon_req.decrypted:
        print(f"Decrypted Request Data: {anon_req.decrypted}")
```

#### Login Response
```python
packet_hex = "05002..."
packet = MeshCoreDecoder.decode(packet_hex, decryption_options)

if packet.payload_type == PayloadType.Response:
    response = packet.payload['decoded']
    if response.decrypted:
        content = response.decrypted.get('content', {})
        if content.get('type') == 'login_response':
            print(f"Response Code: 0x{content.get('response_code'):02x}")
            print(f"Is Admin: {bool(content.get('is_admin'))}")
            print(f"Permissions: 0x{content.get('permissions'):02x}")
            print(f"Firmware Version: {content.get('firmware_version')}")
```

### Complete Example Script

Here's a complete example that decodes multiple packet types:

```python
from meshcoredecoder import MeshCoreDecoder
from meshcoredecoder.crypto import MeshCoreKeyStore
from meshcoredecoder.types.crypto import DecryptionOptions
from meshcoredecoder.types.enums import PayloadType

# Setup keys (truncated for readability)
key_store = MeshCoreKeyStore()
key_store.add_node_key("2e5c4e32...", "1010fe34...")
key_store.add_peer_key("969605c0...")
key_store.add_channel_secret("9cd8fcf2...")

options = DecryptionOptions(key_store=key_store)

# Example packets (hex strings truncated for readability)
packets = [
    ("Advert", "1107D978...", None),
    ("GroupText", "15062B...", options),
    ("GET_STATS Response", "06002E96...", options),
]

for name, hex_data, opts in packets:
    print(f"\n=== {name} ===")
    packet = MeshCoreDecoder.decode(hex_data, opts)
    print(f"Route Type: {packet.route_type}")
    print(f"Payload Type: {packet.payload_type}")
    print(f"Message Hash: {packet.message_hash}")
    # Process based on payload type...
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
