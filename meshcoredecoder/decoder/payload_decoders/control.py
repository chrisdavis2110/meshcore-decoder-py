"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Control payload decoder.
Structure per docs/payloads.md: flags (1, upper 4 bits = sub_type), data (rest).
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import ControlPayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...utils.hex import bytes_to_hex


# Sub-types from payloads.md (upper 4 bits of flags)
CONTROL_SUB_TYPE_DISCOVER_REQ = 0x8
CONTROL_SUB_TYPE_DISCOVER_RESP = 0x9


class ControlPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[ControlPayload]:
        """Decode a Control payload. See docs/payloads.md Control data."""
        if options is None:
            options = {}

        try:
            if len(payload) < 1:
                result = ControlPayload(
                    payload_type=PayloadType.Control,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['Control payload too short (minimum 1 byte for flags)'],
                    flags=0,
                    sub_type=0,
                    data_hex=''
                )
                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid Control Data',
                        description='Control payload too short',
                        start_byte=options.get('segment_offset', 0),
                        end_byte=options.get('segment_offset', 0) + max(0, len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]
                return result

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)
            offset = 0

            flags = payload[offset]
            sub_type = (flags >> 4) & 0x0F
            lower_bits = flags & 0x0F

            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Flags',
                    description=f'Upper 4 bits = sub_type (0x{sub_type:x}), lower 4 bits = type-specific',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset,
                    value=f'{flags:02x}'
                ))
            offset += 1

            data_bytes = payload[offset:]
            data_hex = bytes_to_hex(data_bytes)
            parsed: Dict[str, Any] = {}

            if sub_type == CONTROL_SUB_TYPE_DISCOVER_REQ and len(data_bytes) >= 5:
                # DISCOVER_REQ: type_filter(1), tag(4), since(4 optional)
                type_filter = data_bytes[0]
                parsed['sub_type_name'] = 'DISCOVER_REQ'
                parsed['prefix_only'] = bool(lower_bits & 0x01)
                parsed['type_filter'] = type_filter
                parsed['type_filter_hex'] = f'0x{type_filter:02x}'
                if len(data_bytes) >= 9:
                    tag = (
                        data_bytes[1] |
                        (data_bytes[2] << 8) |
                        (data_bytes[3] << 16) |
                        (data_bytes[4] << 24)
                    )
                    parsed['tag'] = tag
                    parsed['tag_hex'] = f'0x{tag:08x}'
                if len(data_bytes) >= 13:
                    since = (
                        data_bytes[5] |
                        (data_bytes[6] << 8) |
                        (data_bytes[7] << 16) |
                        (data_bytes[8] << 24)
                    )
                    parsed['since'] = since
                    parsed['since_hex'] = f'0x{since:08x}'

                if options.get('include_segments'):
                    segments.append(PayloadSegment(
                        name='Type Filter',
                        description=f'Bit mask for ADV_TYPE_*: 0x{type_filter:02x}',
                        start_byte=segment_offset + offset,
                        end_byte=segment_offset + offset,
                        value=f'{type_filter:02x}'
                    ))
                    if len(data_bytes) >= 9:
                        segments.append(PayloadSegment(
                            name='Tag',
                            description=f'Random tag from sender: 0x{parsed["tag"]:08x}',
                            start_byte=segment_offset + offset + 1,
                            end_byte=segment_offset + offset + 4,
                            value=bytes_to_hex(data_bytes[1:5])
                        ))
                    if len(data_bytes) >= 13:
                        segments.append(PayloadSegment(
                            name='Since',
                            description=f'Epoch timestamp (optional): {parsed["since"]}',
                            start_byte=segment_offset + offset + 5,
                            end_byte=segment_offset + offset + 8,
                            value=bytes_to_hex(data_bytes[5:9])
                        ))

            elif sub_type == CONTROL_SUB_TYPE_DISCOVER_RESP and len(data_bytes) >= 6:
                # DISCOVER_RESP: snr(1, signed, SNR*4), tag(4), pubkey(8 or 32)
                snr_raw = data_bytes[0]
                snr_signed = snr_raw - 256 if snr_raw > 127 else snr_raw
                snr_db = snr_signed / 4.0
                tag = (
                    data_bytes[1] |
                    (data_bytes[2] << 8) |
                    (data_bytes[3] << 16) |
                    (data_bytes[4] << 24)
                )
                parsed['sub_type_name'] = 'DISCOVER_RESP'
                parsed['node_type'] = lower_bits
                parsed['snr_raw'] = snr_raw
                parsed['snr_db'] = round(snr_db, 2)
                parsed['tag'] = tag
                parsed['tag_hex'] = f'0x{tag:08x}'
                if len(data_bytes) >= 6 + 8:
                    pubkey_len = 32 if len(data_bytes) >= 6 + 32 else 8
                    pubkey_hex = bytes_to_hex(data_bytes[5:5 + pubkey_len])
                    parsed['pubkey_len'] = pubkey_len
                    parsed['pubkey'] = pubkey_hex

                if options.get('include_segments'):
                    segments.append(PayloadSegment(
                        name='SNR',
                        description=f'SNR*4 (signed): {snr_db:.2f} dB',
                        start_byte=segment_offset + offset,
                        end_byte=segment_offset + offset,
                        value=f'{snr_raw:02x}'
                    ))
                    segments.append(PayloadSegment(
                        name='Tag',
                        description=f'Reflected from DISCOVER_REQ: 0x{tag:08x}',
                        start_byte=segment_offset + offset + 1,
                        end_byte=segment_offset + offset + 4,
                        value=bytes_to_hex(data_bytes[1:5])
                    ))
                    if len(data_bytes) >= 6 + 8:
                        pubkey_len = 32 if len(data_bytes) >= 6 + 32 else 8
                        segments.append(PayloadSegment(
                            name='Pubkey',
                            description=f'Node ID or prefix ({pubkey_len} bytes)',
                            start_byte=segment_offset + offset + 5,
                            end_byte=segment_offset + offset + 4 + pubkey_len,
                            value=bytes_to_hex(data_bytes[5:5 + pubkey_len])
                        ))

            else:
                parsed['raw'] = data_hex
                if options.get('include_segments') and len(data_bytes) > 0:
                    segments.append(PayloadSegment(
                        name='Data',
                        description=f'Control data ({len(data_bytes)} bytes)',
                        start_byte=segment_offset + offset,
                        end_byte=segment_offset + len(payload) - 1,
                        value=data_hex
                    ))

            result = ControlPayload(
                payload_type=PayloadType.Control,
                version=PayloadVersion.Version1,
                is_valid=True,
                flags=flags,
                sub_type=sub_type,
                data_hex=data_hex,
                parsed=parsed
            )
            if options.get('include_segments'):
                result.segments = segments
            return result

        except Exception as error:
            return ControlPayload(
                payload_type=PayloadType.Control,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                flags=0,
                sub_type=0,
                data_hex=''
            )
