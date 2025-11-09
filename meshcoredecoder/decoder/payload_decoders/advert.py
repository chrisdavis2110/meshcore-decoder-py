"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Advert payload decoder with Ed25519 signature verification
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from ...types.payloads import AdvertPayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion, DeviceRole, AdvertFlags
from ...utils.hex import bytes_to_hex
from ...utils.enum_names import get_device_role_name


class AdvertPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[AdvertPayload]:
        """Decode an Advert payload"""
        if options is None:
            options = {}

        try:
            # Start of appdata section: public_key(32) + timestamp(4) + signature(64) + flags(1) = 101 bytes
            if len(payload) < 101:
                result = AdvertPayload(
                    payload_type=PayloadType.Advert,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['Advertisement payload too short'],
                    public_key='',
                    timestamp=0,
                    signature='',
                    app_data={'flags': 0, 'device_role': DeviceRole.ChatNode, 'has_location': False, 'has_name': False}
                )

                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid Advert Data',
                        description='Advert payload too short (minimum 101 bytes required)',
                        start_byte=options.get('segment_offset', 0),
                        end_byte=(options.get('segment_offset', 0) + len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)
            current_offset = 0

            # Parse advertisement structure from payloads.md
            public_key = bytes_to_hex(payload[current_offset:current_offset + 32])
            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Public Key',
                    description='Ed25519 public key',
                    start_byte=segment_offset + current_offset,
                    end_byte=segment_offset + current_offset + 31,
                    value=public_key
                ))
            current_offset += 32

            timestamp = AdvertPayloadDecoder._read_uint32_le(payload, current_offset)
            if options.get('include_segments'):
                timestamp_date = datetime.fromtimestamp(timestamp)
                segments.append(PayloadSegment(
                    name='Timestamp',
                    description=f'{timestamp} ({timestamp_date.strftime("%Y-%m-%dT%H:%M:%S")}Z)',
                    start_byte=segment_offset + current_offset,
                    end_byte=segment_offset + current_offset + 3,
                    value=bytes_to_hex(payload[current_offset:current_offset + 4])
                ))
            current_offset += 4

            signature = bytes_to_hex(payload[current_offset:current_offset + 64])
            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Signature',
                    description='Ed25519 signature',
                    start_byte=segment_offset + current_offset,
                    end_byte=segment_offset + current_offset + 63,
                    value=signature
                ))
            current_offset += 64

            flags = payload[current_offset]
            if options.get('include_segments'):
                binary_str = f'{flags:08b}'
                device_role = AdvertPayloadDecoder._parse_device_role(flags)
                role_name = get_device_role_name(device_role)
                has_location = bool(flags & AdvertFlags.HasLocation.value)
                has_name = bool(flags & AdvertFlags.HasName.value)
                flag_desc = f' | Bits 0-3 (Role): {role_name} | Bit 4 (Location): {"Yes" if has_location else "No"} | Bit 7 (Name): {"Yes" if has_name else "No"}'
                segments.append(PayloadSegment(
                    name='App Flags',
                    description=f'Binary: {binary_str}{flag_desc}',
                    start_byte=segment_offset + current_offset,
                    end_byte=segment_offset + current_offset,
                    value=f'{flags:02X}'
                ))
            current_offset += 1

            app_data = {
                'flags': flags,
                'device_role': AdvertPayloadDecoder._parse_device_role(flags),
                'has_location': bool(flags & AdvertFlags.HasLocation.value),
                'has_name': bool(flags & AdvertFlags.HasName.value)
            }

            advert = AdvertPayload(
                payload_type=PayloadType.Advert,
                version=PayloadVersion.Version1,
                is_valid=True,
                public_key=public_key,
                timestamp=timestamp,
                signature=signature,
                app_data=app_data
            )

            offset = current_offset

            # Location data (if HasLocation flag is set)
            if flags & AdvertFlags.HasLocation.value and len(payload) >= offset + 8:
                lat = AdvertPayloadDecoder._read_int32_le(payload, offset) / 1000000
                lon = AdvertPayloadDecoder._read_int32_le(payload, offset + 4) / 1000000
                advert.app_data['location'] = {
                    'latitude': round(lat * 1000000) / 1000000,  # Keep precision
                    'longitude': round(lon * 1000000) / 1000000
                }

                if options.get('include_segments'):
                    segments.append(PayloadSegment(
                        name='Latitude',
                        description=f'{lat}° ({lat})',
                        start_byte=segment_offset + offset,
                        end_byte=segment_offset + offset + 3,
                        value=bytes_to_hex(payload[offset:offset + 4])
                    ))

                    segments.append(PayloadSegment(
                        name='Longitude',
                        description=f'{lon}° ({lon})',
                        start_byte=segment_offset + offset + 4,
                        end_byte=segment_offset + offset + 7,
                        value=bytes_to_hex(payload[offset + 4:offset + 8])
                    ))

                offset += 8

            # Feature1 data (battery voltage in mV) - if HasFeature1 flag is set
            if flags & AdvertFlags.HasFeature1.value and len(payload) >= offset + 2:
                battery_voltage_mv = AdvertPayloadDecoder._read_uint16_le(payload, offset)
                advert.app_data['battery_voltage'] = battery_voltage_mv/1000

                if options.get('include_segments'):
                    segments.append(PayloadSegment(
                        name='Battery Voltage (feat1)',
                        description=f'Battery voltage: {battery_voltage_mv/1000} V',
                        start_byte=segment_offset + offset,
                        end_byte=segment_offset + offset + 1,
                        value=bytes_to_hex(payload[offset:offset + 2])
                    ))

                offset += 2

            # Skip feature2 field for now (HasFeature2)
            if flags & AdvertFlags.HasFeature2.value:
                offset += 2

            # Name data (if HasName flag is set)
            if flags & AdvertFlags.HasName.value and len(payload) > offset:
                name_bytes = payload[offset:]
                raw_name = name_bytes.decode('utf-8', errors='replace').split('\0')[0]
                advert.app_data['name'] = AdvertPayloadDecoder._sanitize_control_characters(raw_name) or raw_name

                if options.get('include_segments'):
                    segments.append(PayloadSegment(
                        name='Node Name',
                        description=f'Node name: "{advert.app_data.get("name")}"',
                        start_byte=segment_offset + offset,
                        end_byte=segment_offset + len(payload) - 1,
                        value=bytes_to_hex(name_bytes)
                    ))

            if options.get('include_segments'):
                advert.segments = segments

            return advert
        except Exception as error:
            return AdvertPayload(
                payload_type=PayloadType.Advert,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                public_key='',
                timestamp=0,
                signature='',
                app_data={'flags': 0, 'device_role': DeviceRole.ChatNode, 'has_location': False, 'has_name': False}
            )

    @staticmethod
    def _parse_device_role(flags: int) -> DeviceRole:
        """Parse device role from flags byte"""
        role_value = flags & 0x0F
        if role_value == 0x01:
            return DeviceRole.ChatNode
        elif role_value == 0x02:
            return DeviceRole.Repeater
        elif role_value == 0x03:
            return DeviceRole.RoomServer
        elif role_value == 0x04:
            return DeviceRole.Sensor
        else:
            return DeviceRole.ChatNode

    @staticmethod
    def _read_uint16_le(buffer: bytes, offset: int) -> int:
        """Read a 16-bit unsigned integer in little-endian format"""
        return buffer[offset] | (buffer[offset + 1] << 8)

    @staticmethod
    def _read_uint32_le(buffer: bytes, offset: int) -> int:
        """Read a 32-bit unsigned integer in little-endian format"""
        return (
            buffer[offset] |
            (buffer[offset + 1] << 8) |
            (buffer[offset + 2] << 16) |
            (buffer[offset + 3] << 24)
        )

    @staticmethod
    def _read_int32_le(buffer: bytes, offset: int) -> int:
        """Read a 32-bit signed integer in little-endian format"""
        value = AdvertPayloadDecoder._read_uint32_le(buffer, offset)
        # Convert unsigned to signed
        return value - 0x100000000 if value > 0x7FFFFFFF else value

    @staticmethod
    def _sanitize_control_characters(value: Optional[str]) -> Optional[str]:
        """Remove control characters from string"""
        if not value:
            return None
        import re
        sanitized = value.strip().rstrip('\0').replace('\0', '')
        # Remove control characters
        sanitized = re.sub(r'[\x00-\x1F\x7F]', '', sanitized)
        return sanitized if sanitized else None

    @staticmethod
    async def decode_with_verification(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[AdvertPayload]:
        """Decode advertisement payload with signature verification"""
        from src.crypto.ed25519_verifier import Ed25519SignatureVerifier

        if options is None:
            options = {}

        # First decode normally
        advert = AdvertPayloadDecoder.decode(payload, options)
        if not advert or not advert.is_valid:
            return advert

        # Perform signature verification
        try:
            # Extract app_data from the payload (everything after public_key + timestamp + signature)
            app_data_start = 32 + 4 + 64  # public_key + timestamp + signature
            app_data_bytes = payload[app_data_start:]
            app_data_hex = bytes_to_hex(app_data_bytes)

            signature_valid = await Ed25519SignatureVerifier.verify_advertisement_signature(
                advert.public_key,
                advert.signature,
                advert.timestamp,
                app_data_hex
            )

            advert.signature_valid = signature_valid

            if not signature_valid:
                advert.signature_error = 'Ed25519 signature verification failed'
                advert.is_valid = False
                if not advert.errors:
                    advert.errors = []
                advert.errors.append('Invalid Ed25519 signature')
        except Exception as error:
            advert.signature_valid = False
            advert.signature_error = str(error)
            advert.is_valid = False
            if not advert.errors:
                advert.errors = []
            advert.errors.append('Signature verification failed: ' + str(error))

        return advert
