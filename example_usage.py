"""
Example usage of MeshCore Decoder Python port
"""

from src.decoder.packet_decoder import MeshCorePacketDecoder
from src.crypto.key_manager import MeshCoreKeyStore
from src.types.crypto import DecryptionOptions

# Example 1: Basic packet decoding
print("=== Example 1: Basic Decoding ===")
hex_data = "11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172"

try:
    packet = MeshCorePacketDecoder.decode(hex_data)
    print(f"✅ Packet decoded successfully!")
    print(f"   Message Hash: {packet.message_hash}")
    print(f"   Route Type: {packet.route_type}")
    print(f"   Payload Type: {packet.payload_type}")
    print(f"   Valid: {packet.is_valid}")
    print(f"   Total Bytes: {packet.total_bytes}")
except Exception as e:
    print(f"❌ Error: {e}")


# Example 2: Structure analysis
print("\n=== Example 2: Structure Analysis ===")
try:
    structure = MeshCorePacketDecoder.analyze_structure(hex_data)
    print(f"✅ Structure analyzed!")
    print(f"   Total Segments: {len(structure.segments)}")
    print(f"   Payload Segments: {len(structure.payload['segments'])}")
    for i, seg in enumerate(structure.segments[:3]):  # Show first 3
        print(f"   Segment {i+1}: {seg.name} - {seg.value[:50]}...")
except Exception as e:
    print(f"❌ Error: {e}")


# Example 3: Decryption with key store
print("\n=== Example 3: Decryption Setup ===")
try:
    key_store = MeshCoreKeyStore({
        'channel_secrets': [
            '8b3387e9c5cdea6ac9e5edbaa115cd72',  # Public channel
            'ff2b7d74e8d20f71505bda9ea8d59a1c'
        ]
    })
    print(f"✅ Key store created with {len(key_store._channel_hash_to_keys)} channel hash groups")

    options = DecryptionOptions(key_store=key_store)
    print(f"✅ Decryption options configured")
except Exception as e:
    print(f"❌ Error: {e}")


# Example 4: Validation
print("\n=== Example 4: Packet Validation ===")
try:
    validation = MeshCorePacketDecoder.validate(hex_data)
    print(f"✅ Validation result:")
    print(f"   Valid: {validation.is_valid}")
    if validation.errors:
        print(f"   Errors: {validation.errors}")
except Exception as e:
    print(f"❌ Error: {e}")


print("\n=== Example 5: JSON Output ===")
try:
    packet = MeshCorePacketDecoder.decode(hex_data)
    packet_dict = packet.to_dict()

    import json
    json_output = json.dumps(packet_dict, indent=2, default=str)
    print("✅ JSON serialization successful!")
    print(json_output[:200] + "...\n")

    # Or use the convenience method
    json_str = MeshCorePacketDecoder.decode_to_json(hex_data)
    print("JSON output length:", len(json_str), "characters")
except Exception as e:
    print(f"❌ Error: {e}")


print("\n✅ Examples complete!")
print("\nTo decode encrypted packets, use:")
print("  from src.types.crypto import DecryptionOptions")
print("  options = DecryptionOptions(key_store=your_key_store)")
print("  packet = MeshCorePacketDecoder.decode(hex_data, options)")
print("\nFor JSON output:")
print("  packet_dict = packet.to_dict()")
print("  json_output = json.dumps(packet_dict, indent=2)")
