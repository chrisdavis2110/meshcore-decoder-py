"""
Hex encoding/decoding utilities
"""


def byte_to_hex(byte: int) -> str:
    """Convert a single byte to uppercase hex string"""
    return f"{byte:02X}".upper()


def bytes_to_hex(bytes_data: bytes) -> str:
    """Convert bytes to uppercase hex string"""
    return ''.join(byte_to_hex(b) for b in bytes_data)


def number_to_hex(num: int, pad_length: int = 8) -> str:
    """Convert a number to uppercase hex string with specified padding"""
    # Use unsigned 32-bit interpretation
    unsigned = num & 0xFFFFFFFF
    return f"{unsigned:0{pad_length}X}".upper()


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string to bytes"""
    # Remove any whitespace and convert to uppercase
    clean_hex = hex_string.replace(' ', '').upper()

    # Validate hex string
    if not all(c in '0123456789ABCDEF' for c in clean_hex):
        raise ValueError(f"Invalid hex string: invalid characters")

    if len(clean_hex) % 2 != 0:
        raise ValueError("Invalid hex string: odd length")

    try:
        return bytes.fromhex(clean_hex)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}")
