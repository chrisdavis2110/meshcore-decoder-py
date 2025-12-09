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

        # Add battery voltage if present
        if self.app_data.get('battery_voltage') is not None:
            result['appData']['batteryVoltage'] = self.app_data['battery_voltage']

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

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = super().to_dict()
        result.update({
            'traceTag': self.trace_tag,
            'authCode': self.auth_code,
            'flags': self.flags,
            'pathHashes': self.path_hashes
        })

        # Include SNR values if available
        if self.snr_values:
            result['snrValues'] = self.snr_values

            # Create path with SNR per hop for easier analysis
            path_with_snr = []
            for i, path_hash in enumerate(self.path_hashes):
                hop_info = {'nodeHash': path_hash}
                if i < len(self.snr_values):
                    hop_info['snr'] = self.snr_values[i]
                path_with_snr.append(hop_info)
            result['path'] = path_with_snr

        return result

    def get_path_with_snr(self) -> List[Dict[str, Any]]:
        """Get path with SNR values per hop"""
        path_with_snr = []
        for i, path_hash in enumerate(self.path_hashes):
            hop_info = {'nodeHash': path_hash, 'hop': i + 1}
            if i < len(self.snr_values):
                hop_info['snr'] = self.snr_values[i]
            path_with_snr.append(hop_info)
        return path_with_snr


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


class GroupDataPayload(BasePayload):
    """Group datagram payload"""
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

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = super().to_dict()
        result.update({
            'destinationHash': self.destination_hash,
            'sourceHash': self.source_hash,
            'cipherMac': self.cipher_mac,
            'ciphertext': self.ciphertext,
            'timestamp': self.timestamp,
            'requestType': self.request_type.value,
            'requestTypeName': self.request_type.name
        })
        if self.request_data:
            result['requestData'] = self.request_data
        if self.decrypted:
            result['decrypted'] = self.decrypted
        return result


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
        destination_hash: Optional[str] = None,
        source_hash: Optional[str] = None,
        cipher_mac: Optional[str] = None,
        ciphertext: Optional[str] = None,
        decrypted: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.path_length = path_length
        self.path_hashes = path_hashes
        self.extra_type = extra_type
        self.extra_data = extra_data
        self.destination_hash = destination_hash
        self.source_hash = source_hash
        self.cipher_mac = cipher_mac
        self.ciphertext = ciphertext
        self.decrypted = decrypted


class NeighborEntry:
    """Neighbor table entry with SNR data"""
    def __init__(
        self,
        node_id: str,  # 32-byte Ed25519 public key (hex)
        advert_timestamp: int,  # Unix timestamp from advertisement
        heard_timestamp: int,  # Local time when advertisement was received
        snr: float  # SNR in dB (converted from int8_t * 4)
    ):
        self.node_id = node_id
        self.advert_timestamp = advert_timestamp
        self.heard_timestamp = heard_timestamp
        self.snr = snr

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'nodeId': self.node_id,
            'advertTimestamp': self.advert_timestamp,
            'heardTimestamp': self.heard_timestamp,
            'snr': self.snr
        }


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
        tag: Optional[int] = None,
        neighbors: Optional[List[NeighborEntry]] = None,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.destination_hash = destination_hash
        self.source_hash = source_hash
        self.cipher_mac = cipher_mac
        self.ciphertext = ciphertext
        self.ciphertext_length = ciphertext_length
        self.decrypted = decrypted
        self.tag = tag  # Response tag (4 bytes, little-endian)
        self.neighbors = neighbors or []  # Neighbor table entries (for GetStats responses)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = super().to_dict()
        result.update({
            'destinationHash': self.destination_hash,
            'sourceHash': self.source_hash,
            'cipherMac': self.cipher_mac,
            'ciphertext': self.ciphertext,
            'ciphertextLength': self.ciphertext_length
        })

        if self.tag is not None:
            result['tag'] = self.tag

        if self.decrypted:
            result['decrypted'] = self.decrypted

        if self.neighbors:
            result['neighbors'] = [neighbor.to_dict() for neighbor in self.neighbors]
            result['neighborCount'] = len(self.neighbors)

        return result


# Union type for all payload types
PayloadData = (
    AdvertPayload | TracePayload | GroupTextPayload | GroupDataPayload | RequestPayload |
    TextMessagePayload | AnonRequestPayload | AckPayload | PathPayload | ResponsePayload
)
