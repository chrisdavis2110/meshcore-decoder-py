"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Path payload decoder
"""

from typing import Optional, Dict, Any, List
from ...types.payloads import PathPayload
from ...types.enums import PayloadType, PayloadVersion
from ...utils.hex import byte_to_hex, bytes_to_hex


class PathPayloadDecoder:
    @staticmethod
    def decode(
        payload: bytes,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[PathPayload]:
        """Decode a Path payload"""
        if options is None:
            options = {}

        try:
            # Based on MeshCore payloads.md - Path payload structure:
            # - path_length (1 byte)
            # - path (variable length) - list of node hashes (one byte each)
            # - extra_type (1 byte) - bundled payload type
            # - extra (rest of data) - bundled payload content

            if len(payload) < 2:
                return PathPayload(
                    payload_type=PayloadType.Path,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=['Path payload too short (minimum 2 bytes: path length + extra type)'],
                    path_length=0,
                    path_hashes=[],
                    extra_type=0,
                    extra_data=''
                )

            path_length = payload[0]

            if len(payload) < 1 + path_length + 1:
                return PathPayload(
                    payload_type=PayloadType.Path,
                    version=PayloadVersion.Version1,
                    is_valid=False,
                    errors=[f'Path payload too short (need {1 + path_length + 1} bytes for path length + path + extra type)'],
                    path_length=path_length,
                    path_hashes=[],
                    extra_type=0,
                    extra_data=''
                )

            # Parse path hashes (one byte each)
            path_hashes: List[str] = []
            for i in range(path_length):
                path_hashes.append(byte_to_hex(payload[1 + i]))

            # Parse extra type (1 byte after path)
            extra_type = payload[1 + path_length]

            # Parse extra data (remaining bytes)
            extra_data = ''
            if len(payload) > 1 + path_length + 1:
                extra_data = bytes_to_hex(payload[1 + path_length + 1:])

            return PathPayload(
                payload_type=PayloadType.Path,
                version=PayloadVersion.Version1,
                is_valid=True,
                path_length=path_length,
                path_hashes=path_hashes,
                extra_type=extra_type,
                extra_data=extra_data
            )
        except Exception as error:
            return PathPayload(
                payload_type=PayloadType.Path,
                version=PayloadVersion.Version1,
                is_valid=False,
                errors=[str(error)],
                path_length=0,
                path_hashes=[],
                extra_type=0,
                extra_data=''
            )
