"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Utility functions to get human-readable names for enum values
"""

from src.types.enums import RouteType, PayloadType, PayloadVersion, DeviceRole, RequestType


def get_route_type_name(route_type: RouteType) -> str:
    """Get human-readable name for RouteType enum value"""
    try:
        return route_type.name
    except ValueError:
        return f"Unknown ({route_type})"


def get_payload_type_name(payload_type: PayloadType) -> str:
    """Get human-readable name for PayloadType enum value"""
    try:
        return payload_type.name
    except ValueError:
        return f"Unknown ({payload_type})"


def get_payload_version_name(version: PayloadVersion) -> str:
    """Get human-readable name for PayloadVersion enum value"""
    mapping = {
        PayloadVersion.Version1: 'Version 1',
        PayloadVersion.Version2: 'Version 2',
        PayloadVersion.Version3: 'Version 3',
        PayloadVersion.Version4: 'Version 4',
    }
    return mapping.get(version, f"Unknown ({version})")


def get_device_role_name(role: DeviceRole) -> str:
    """Get human-readable name for DeviceRole enum value"""
    mapping = {
        DeviceRole.ChatNode: 'Chat Node',
        DeviceRole.Repeater: 'Repeater',
        DeviceRole.RoomServer: 'Room Server',
        DeviceRole.Sensor: 'Sensor',
    }
    return mapping.get(role, f"Unknown ({role})")


def get_request_type_name(request_type: RequestType) -> str:
    """Get human-readable name for RequestType enum value"""
    mapping = {
        RequestType.GetStats: 'Get Stats',
        RequestType.Keepalive: 'Keepalive (deprecated)',
        RequestType.GetTelemetryData: 'Get Telemetry Data',
        RequestType.GetMinMaxAvgData: 'Get Min/Max/Avg Data',
        RequestType.GetAccessList: 'Get Access List',
    }
    return mapping.get(request_type, f"Unknown ({request_type})")
