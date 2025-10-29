"""
Payload type definitions
Reference: https://github.com/meshcore-dev/MeshCore/blob/main/docs/payloads.md
"""

from typing import Dict, Optional, List, Any
from .enums import PayloadType, PayloadVersion, DeviceRole, RequestType


class BasePayload:
    """Base payload interface"""
    def __init__(
        self,
        payload_type: PayloadType,
        version: PayloadVersion,
        is_valid: bool,
        errors: Optional[List[str]] = None
    ):
        self.type = payload_type
        self.version = version
        self.is_valid = is_valid
        self.errors = errors or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            'type': self.type.value,
            'version': self.version.value,
            'isValid': self.is_valid
        }
        if self.errors:
            result['errors'] = self.errors
        return result


class AdvertPayload(BasePayload):
    """Advertisement payload"""
    def __init__(
        self,
        public_key: str,
        timestamp: int,
        signature: str,
        app_data: Dict[str, Any],
        signature_valid: Optional[bool] = None,
        signature_error: Optional[str] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.public_key = public_key
        self.timestamp = timestamp
        self.signature = signature
        self.signature_valid = signature_valid
        self.signature_error = signature_error
        self.app_data = app_data

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = super().to_dict()
        result.update({
            'publicKey': self.public_key,
            'timestamp': self.timestamp,
            'signature': self.signature,
            'appData': {
                'flags': self.app_data.get('flags'),
                'deviceRole': self.app_data.get('device_role').value if isinstance(self.app_data.get('device_role'), DeviceRole) else self.app_data.get('device_role'),
                'hasLocation': self.app_data.get('has_location', False),
                'hasName': self.app_data.get('has_name', False)
            }
        })
        if self.signature_valid is not None:
            result['signatureValid'] = self.signature_valid
        if self.signature_error:
            result['signatureError'] = self.signature_error

        # Add location if present
        if self.app_data.get('location'):
            result['appData']['location'] = self.app_data['location']

        # Add name if present
        if self.app_data.get('name'):
            result['appData']['name'] = self.app_data['name']

        return result


class TracePayload(BasePayload):
    """Trace payload"""
    def __init__(
        self,
        trace_tag: str,
        auth_code: int,
        flags: int,
        path_hashes: List[str],
        snr_values: Optional[List[float]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.trace_tag = trace_tag
        self.auth_code = auth_code
        self.flags = flags
        self.path_hashes = path_hashes
        self.snr_values = snr_values or []


class GroupTextPayload(BasePayload):
    """Group text message payload"""
    def __init__(
        self,
        channel_hash: str,
        cipher_mac: str,
        ciphertext: str,
        ciphertext_length: int,
        decrypted: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.channel_hash = channel_hash
        self.cipher_mac = cipher_mac
        self.ciphertext = ciphertext
        self.ciphertext_length = ciphertext_length
        self.decrypted = decrypted


class RequestPayload(BasePayload):
    """Request payload"""
    def __init__(
        self,
        destination_hash: str,
        source_hash: str,
        cipher_mac: str,
        ciphertext: str,
        timestamp: int,
        request_type: RequestType,
        request_data: Optional[str] = None,
        decrypted: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.destination_hash = destination_hash
        self.source_hash = source_hash
        self.cipher_mac = cipher_mac
        self.ciphertext = ciphertext
        self.timestamp = timestamp
        self.request_type = request_type
        self.request_data = request_data
        self.decrypted = decrypted


class TextMessagePayload(BasePayload):
    """Text message payload"""
    def __init__(
        self,
        destination_hash: str,
        source_hash: str,
        cipher_mac: str,
        ciphertext: str,
        ciphertext_length: int,
        decrypted: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.destination_hash = destination_hash
        self.source_hash = source_hash
        self.cipher_mac = cipher_mac
        self.ciphertext = ciphertext
        self.ciphertext_length = ciphertext_length
        self.decrypted = decrypted


class AnonRequestPayload(BasePayload):
    """Anonymous request payload"""
    def __init__(
        self,
        destination_hash: str,
        sender_public_key: str,
        cipher_mac: str,
        ciphertext: str,
        ciphertext_length: int,
        decrypted: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.destination_hash = destination_hash
        self.sender_public_key = sender_public_key
        self.cipher_mac = cipher_mac
        self.ciphertext = ciphertext
        self.ciphertext_length = ciphertext_length
        self.decrypted = decrypted


class AckPayload(BasePayload):
    """Acknowledgment payload"""
    def __init__(
        self,
        checksum: str,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.checksum = checksum


class PathPayload(BasePayload):
    """Path payload"""
    def __init__(
        self,
        path_length: int,
        path_hashes: List[str],
        extra_type: int,
        extra_data: str,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.path_length = path_length
        self.path_hashes = path_hashes
        self.extra_type = extra_type
        self.extra_data = extra_data


class ResponsePayload(BasePayload):
    """Response payload"""
    def __init__(
        self,
        destination_hash: str,
        source_hash: str,
        cipher_mac: str,
        ciphertext: str,
        ciphertext_length: int,
        decrypted: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.destination_hash = destination_hash
        self.source_hash = source_hash
        self.cipher_mac = cipher_mac
        self.ciphertext = ciphertext
        self.ciphertext_length = ciphertext_length
        self.decrypted = decrypted


# Union type for all payload types
PayloadData = (
    AdvertPayload | TracePayload | GroupTextPayload | RequestPayload |
    TextMessagePayload | AnonRequestPayload | AckPayload | PathPayload | ResponsePayload
)
