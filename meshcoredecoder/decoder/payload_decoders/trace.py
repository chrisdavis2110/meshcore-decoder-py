"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Trace payload decoder
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import TracePayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...utils.hex import byte_to_hex, bytes_to_hex, number_to_hex


class TracePayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        path_data: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[TracePayload]:
        """Decode a Trace payload"""
        if options is None:
            options = {}

        try:
            if len(payload) < 9:
                result = TracePayload(
                    payload_type=PayloadType.Trace,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['Trace payload too short (need at least tag(4) + auth(4) + flags(1))'],
                    trace_tag='00000000',
                    auth_code=0,
                    flags=0,
                    path_hashes=[]
                )

                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid Trace Data',
                        description='Trace payload too short (minimum 9 bytes required)',
                        start_byte=options.get('segment_offset', 0),
                        end_byte=(options.get('segment_offset', 0) + len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]

                return result

            offset = 0
            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)

            # Trace Tag (4 bytes) - unique identifier
            trace_tag_raw = TracePayloadDecoder._read_uint32_le(payload, offset)
            trace_tag = number_to_hex(trace_tag_raw, 8)

            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Trace Tag',
                    description=f'Unique identifier for this trace: 0x{trace_tag_raw:08x}',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset + 3,
                    value=bytes_to_hex(payload[offset:offset + 4])
                ))
            offset += 4

            # Auth Code (4 bytes) - authentication/verification code
            auth_code = TracePayloadDecoder._read_uint32_le(payload, offset)

            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Auth Code',
                    description=f'Authentication/verification code: {auth_code}',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset + 3,
                    value=bytes_to_hex(payload[offset:offset + 4])
                ))
            offset += 4

            # Flags (1 byte) - application-defined control flags
            flags = payload[offset]

            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Flags',
                    description=f'Application-defined control flags: 0x{flags:02x} ({flags:08b}b)',
                    start_byte=segment_offset + offset,
                    end_byte=segment_offset + offset,
                    value=f'{flags:02X}'
                ))
            offset += 1

            # Remaining bytes are path hashes (node hashes in the trace path)
            path_hashes: List[str] = []
            path_hashes_start = offset
            while offset < len(payload):
                path_hashes.append(byte_to_hex(payload[offset]))
                offset += 1

            if options.get('include_segments') and path_hashes:
                path_hashes_display = ' '.join(path_hashes)
                segments.append(PayloadSegment(
                    name='Path Hashes',
                    description=f'Node hashes in trace path: {path_hashes_display}',
                    start_byte=segment_offset + path_hashes_start,
                    end_byte=segment_offset + len(payload) - 1,
                    value=bytes_to_hex(payload[path_hashes_start:])
                ))

            # Extract SNR values from path field for TRACE packets
            snr_values: Optional[List[float]] = None
            if path_data and len(path_data) > 0:
                snr_values = []
                for hex_byte in path_data:
                    byte_value = int(hex_byte, 16)
                    # Convert unsigned byte to signed int8 (SNR values are stored as signed int8 * 4)
                    snr_signed = byte_value - 256 if byte_value > 127 else byte_value
                    snr_values.append(snr_signed / 4.0)  # Convert to dB

            result = TracePayload(
                payload_type=PayloadType.Trace,
                version=PayloadVersion.Version1,
                is_valid=True,
                trace_tag=trace_tag,
                auth_code=auth_code,
                flags=flags,
                path_hashes=path_hashes,
                snr_values=snr_values
            )

            if options.get('include_segments'):
                result.segments = segments

            return result
        except Exception as error:
            return TracePayload(
                payload_type=PayloadType.Trace,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                trace_tag='00000000',
                auth_code=0,
                flags=0,
                path_hashes=[]
            )

    @staticmethod
    def _read_uint32_le(buffer: bytes, offset: int) -> int:
        """Read a 32-bit unsigned integer in little-endian format"""
        return (
            buffer[offset] |
            (buffer[offset + 1] << 8) |
            (buffer[offset + 2] << 16) |
            (buffer[offset + 3] << 24)
        )
