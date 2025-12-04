"""
MeshCore Packet Decoder - Python Implementation
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Main entry point for the MeshCore decoder Python port
"""

__version__ = "0.1.6"

# Main decoder
from src.decoder.packet_decoder import MeshCorePacketDecoder

# Crypto
from src.crypto.key_manager import MeshCoreKeyStore
from src.crypto.ed25519_verifier import Ed25519SignatureVerifier

# Type exports
from src.types.enums import (
    RouteType, PayloadType, PayloadVersion, DeviceRole, AdvertFlags, RequestType
)
from src.types.crypto import CryptoKeyStore, DecryptionOptions, DecryptionResult, ValidationResult
from src.types.packet import DecodedPacket, PacketStructure, PacketSegment, PayloadSegment, HeaderBreakdown
from src.types.payloads import (
    BasePayload, AdvertPayload, TracePayload, GroupTextPayload,
    RequestPayload, TextMessagePayload, AnonRequestPayload,
    AckPayload, PathPayload, ResponsePayload
)

# Utility exports
from src.utils.hex import hex_to_bytes, bytes_to_hex, number_to_hex, byte_to_hex
from src.utils.enum_names import (
    get_route_type_name, get_payload_type_name, get_payload_version_name,
    get_device_role_name, get_request_type_name
)
from src.utils.auth_token import (
    create_auth_token, verify_auth_token, parse_auth_token, decode_auth_token_payload,
    AuthTokenPayload, AuthToken
)

# Enum exports
__all__ = [
    # Main decoder
    'MeshCorePacketDecoder',
    'MeshCoreKeyStore',
    'Ed25519SignatureVerifier',
    # Enums
    'RouteType', 'PayloadType', 'PayloadVersion', 'DeviceRole', 'AdvertFlags', 'RequestType',
    # Crypto types
    'CryptoKeyStore', 'DecryptionOptions', 'DecryptionResult', 'ValidationResult',
    # Packet types
    'DecodedPacket', 'PacketStructure', 'PacketSegment', 'PayloadSegment', 'HeaderBreakdown',
    # Payload types
    'AdvertPayload', 'TracePayload', 'GroupTextPayload',
    'RequestPayload', 'TextMessagePayload', 'AnonRequestPayload',
    'AckPayload', 'PathPayload', 'ResponsePayload',
    # Utilities
    'hex_to_bytes', 'bytes_to_hex', 'number_to_hex', 'byte_to_hex',
    'get_route_type_name', 'get_payload_type_name', 'get_payload_version_name',
    'get_device_role_name', 'get_request_type_name',
    'create_auth_token', 'verify_auth_token', 'parse_auth_token', 'decode_auth_token_payload',
    'AuthTokenPayload', 'AuthToken',
]

# Convenience aliases
MeshCoreDecoder = MeshCorePacketDecoder
