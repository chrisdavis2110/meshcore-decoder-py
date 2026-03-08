"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

MeshCore packet type definitions.
Reference: docs/packet_format.md and docs/payloads.md
"""

from enum import Enum


class RouteType(Enum):
    """Route types from packet header bits 0-1 (mask 0x03). See packet_format.md."""
    TransportFlood = 0x00   # ROUTE_TYPE_TRANSPORT_FLOOD
    Flood = 0x01            # ROUTE_TYPE_FLOOD
    Direct = 0x02           # ROUTE_TYPE_DIRECT
    TransportDirect = 0x03  # ROUTE_TYPE_TRANSPORT_DIRECT


class PayloadType(Enum):
    """Payload types from packet header bits 2-5 (mask 0x3C). See packet_format.md."""
    Request = 0x00        # PAYLOAD_TYPE_REQ
    Response = 0x01       # PAYLOAD_TYPE_RESPONSE
    TextMessage = 0x02    # PAYLOAD_TYPE_TXT_MSG
    Ack = 0x03            # PAYLOAD_TYPE_ACK
    Advert = 0x04         # PAYLOAD_TYPE_ADVERT
    GroupText = 0x05      # PAYLOAD_TYPE_GRP_TXT
    GroupData = 0x06      # PAYLOAD_TYPE_GRP_DATA
    AnonRequest = 0x07    # PAYLOAD_TYPE_ANON_REQ
    Path = 0x08           # PAYLOAD_TYPE_PATH
    Trace = 0x09          # PAYLOAD_TYPE_TRACE
    Multipart = 0x0A      # PAYLOAD_TYPE_MULTIPART
    Control = 0x0B        # PAYLOAD_TYPE_CONTROL
    Reserved0C = 0x0C     # reserved
    Reserved0D = 0x0D     # reserved
    Reserved0E = 0x0E     # reserved
    RawCustom = 0x0F      # PAYLOAD_TYPE_RAW_CUSTOM


class PayloadVersion(Enum):
    Version1 = 0x00
    Version2 = 0x01
    Version3 = 0x02
    Version4 = 0x03


class DeviceRole(Enum):
    ChatNode = 0x01
    Repeater = 0x02
    RoomServer = 0x03
    Sensor = 0x04


class AdvertFlags(Enum):
    HasLocation = 0x10
    HasFeature1 = 0x20
    HasFeature2 = 0x40
    HasName = 0x80


class RequestType(Enum):
    """Request types in REQ payload ciphertext. See payloads.md Request type table."""
    GetStats = 0x01
    Keepalive = 0x02  # deprecated
    GetTelemetryData = 0x03
    GetMinMaxAvgData = 0x04
    GetAccessList = 0x05
    GetNeighbours = 0x06
    GetOwnerInfo = 0x07
