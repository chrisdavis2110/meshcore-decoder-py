"""
Packet-related type definitions
"""

from typing import List, Optional, Dict, Any
from .enums import RouteType, PayloadType, PayloadVersion


class DecodedPacket:
    """Main decoded packet structure"""
    def __init__(
        self,
        message_hash: str,
        route_type: RouteType,
        payload_type: PayloadType,
        payload_version: PayloadVersion,
        path_length: int,
        payload: Dict[str, Any],
        total_bytes: int,
        is_valid: bool,
        transport_codes: Optional[List[int]] = None,
        path: Optional[List[str]] = None,
        errors: Optional[List[str]] = None
    ):
        # Packet metadata
        self.message_hash = message_hash

        # Header information
        self.route_type = route_type
        self.payload_type = payload_type
        self.payload_version = payload_version

        # Transport and routing
        self.transport_codes = transport_codes
        self.path_length = path_length
        self.path = path

        # Payload data
        self.payload = payload

        # Metadata
        self.total_bytes = total_bytes
        self.is_valid = is_valid
        self.errors = errors or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            'messageHash': self.message_hash,
            'routeType': self.route_type.value,
            'payloadType': self.payload_type.value,
            'payloadVersion': self.payload_version.value,
            'pathLength': self.path_length,
            'path': self.path,
            'payload': {
                'raw': self.payload.get('raw', ''),
                'decoded': self.payload.get('decoded')
            },
            'totalBytes': self.total_bytes,
            'isValid': self.is_valid
        }

        if self.transport_codes:
            result['transportCodes'] = list(self.transport_codes)

        if self.errors:
            result['errors'] = self.errors

        # Recursively convert decoded payload if it exists
        if self.payload.get('decoded') and hasattr(self.payload['decoded'], 'to_dict'):
            result['payload']['decoded'] = self.payload['decoded'].to_dict()

        return result


class PacketSegment:
    """Segment of packet structure"""
    def __init__(
        self,
        name: str,
        description: str,
        start_byte: int,
        end_byte: int,
        value: str,
        header_breakdown: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.description = description
        self.start_byte = start_byte
        self.end_byte = end_byte
        self.value = value
        self.header_breakdown = header_breakdown


class PayloadSegment:
    """Segment of payload structure"""
    def __init__(
        self,
        name: str,
        description: str,
        start_byte: int,
        end_byte: int,
        value: str,
        decrypted_message: Optional[str] = None
    ):
        self.name = name
        self.description = description
        self.start_byte = start_byte
        self.end_byte = end_byte
        self.value = value
        self.decrypted_message = decrypted_message


class HeaderBreakdown:
    """Detailed header breakdown with bit-level fields"""
    def __init__(
        self,
        full_binary: str,
        fields: List[Dict[str, str]]
    ):
        self.full_binary = full_binary
        self.fields = fields


class PacketStructure:
    """Interface for detailed structure analysis"""
    def __init__(
        self,
        segments: List[PacketSegment],
        total_bytes: int,
        raw_hex: str,
        message_hash: str,
        payload: Dict[str, Any]
    ):
        self.segments = segments
        self.total_bytes = total_bytes
        self.raw_hex = raw_hex
        self.message_hash = message_hash
        self.payload = payload
