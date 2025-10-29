"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Ack payload decoder
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import AckPayload
from ...types.packet import PayloadSegment
from ...types.enums import PayloadType, PayloadVersion
from ...utils.hex import bytes_to_hex


class AckPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[AckPayload]:
        """Decode an Ack payload"""
        if options is None:
            options = {}

        try:
            # Based on MeshCore payloads.md - Ack payload structure:
            # - checksum (4 bytes) - CRC checksum of message timestamp, text, and sender pubkey

            if len(payload) < 4:
                result = AckPayload(
                    payload_type=PayloadType.Ack,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['Ack payload too short (minimum 4 bytes for checksum)'],
                    checksum=''
                )

                if options.get('include_segments'):
                    result.segments = [PayloadSegment(
                        name='Invalid Ack Data',
                        description='Ack payload too short (minimum 4 bytes required for checksum)',
                        start_byte=options.get('segment_offset', 0),
                        end_byte=(options.get('segment_offset', 0) + len(payload) - 1),
                        value=bytes_to_hex(payload)
                    )]

                return result

            segments: List[PayloadSegment] = []
            segment_offset = options.get('segment_offset', 0)

            # Parse checksum (4 bytes as hex)
            checksum = bytes_to_hex(payload[0:4])
            if options.get('include_segments'):
                segments.append(PayloadSegment(
                    name='Checksum',
                    description=f'CRC checksum of message timestamp, text, and sender pubkey: 0x{checksum}',
                    start_byte=segment_offset,
                    end_byte=segment_offset + 3,
                    value=checksum
                ))

            # Any additional data (if present)
            if options.get('include_segments') and len(payload) > 4:
                segments.append(PayloadSegment(
                    name='Additional Data',
                    description='Extra data in Ack payload',
                    start_byte=segment_offset + 4,
                    end_byte=segment_offset + len(payload) - 1,
                    value=bytes_to_hex(payload[4:])
                ))

            result = AckPayload(
                payload_type=PayloadType.Ack,
                version=PayloadVersion.Version1,
                is_valid=True,
                checksum=checksum
            )

            if options.get('include_segments'):
                result.segments = segments

            return result
        except Exception as error:
            return AckPayload(
                payload_type=PayloadType.Ack,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                checksum=''
            )
