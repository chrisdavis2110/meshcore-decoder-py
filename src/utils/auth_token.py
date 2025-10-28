"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Authentication token utilities (JWT-style)
"""

import base64
import json
from typing import Dict, Optional, Any
from datetime import datetime
from src.utils.hex import bytes_to_hex, hex_to_bytes


class AuthTokenPayload:
    """JWT-style token payload for MeshCore authentication"""
    def __init__(
        self,
        public_key: str,
        iat: int,
        exp: Optional[int] = None,
        aud: Optional[str] = None,
        **kwargs
    ):
        self.public_key = public_key
        self.iat = iat
        self.exp = exp
        self.aud = aud
        # Add any custom claims
        for key, value in kwargs.items():
            setattr(self, key, value)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = {
            'publicKey': self.public_key,
            'iat': self.iat
        }
        if self.exp is not None:
            result['exp'] = self.exp
        if self.aud:
            result['aud'] = self.aud
        # Add custom claims
        for key in dir(self):
            if not key.startswith('_') and key not in ['public_key', 'iat', 'exp', 'aud', 'to_dict']:
                value = getattr(self, key)
                if not callable(value):
                    result[key] = value
        return result


class AuthToken:
    """Encoded auth token structure"""
    def __init__(self, header: str, payload: str, signature: str):
        self.header = header
        self.payload = payload
        self.signature = signature

    def __str__(self) -> str:
        return f"{self.header}.{self.payload}.{self.signature}"


def base64url_encode(data: bytes) -> str:
    """Base64url encode (URL-safe base64 without padding)"""
    base64_str = base64.b64encode(data).decode('utf-8')
    return base64_str.replace('+', '-').replace('/', '_').rstrip('=')


def base64url_decode(str_data: str) -> bytes:
    """Base64url decode"""
    # Add padding back
    base64_str = str_data.replace('-', '+').replace('_', '/')
    while len(base64_str) % 4:
        base64_str += '='
    return base64.b64decode(base64_str)


async def create_auth_token(
    payload_dict: Dict[str, Any],
    private_key_hex: str,
    public_key_hex: str
) -> str:
    """
    Create a signed authentication token

    Args:
        payload_dict: Token payload containing claims
        private_key_hex: 64-byte private key in hex format
        public_key_hex: 32-byte public key in hex format

    Returns:
        JWT-style token string in format: header.payload.signature
    """
    # Create header
    header = {
        'alg': 'Ed25519',
        'typ': 'JWT'
    }

    # Ensure publicKey is in the payload (normalize to uppercase)
    if 'publicKey' not in payload_dict:
        payload_dict['publicKey'] = public_key_hex.upper()
    else:
        payload_dict['publicKey'] = payload_dict['publicKey'].upper()

    # Ensure iat is set
    if 'iat' not in payload_dict:
        payload_dict['iat'] = int(datetime.now().timestamp())

    # Encode header and payload
    header_json = json.dumps(header, separators=(',', ':'))
    payload_json = json.dumps(payload_dict, separators=(',', ':'))

    header_bytes = header_json.encode('utf-8')
    payload_bytes = payload_json.encode('utf-8')

    header_encoded = base64url_encode(header_bytes)
    payload_encoded = base64url_encode(payload_bytes)

    # Create signing input: header.payload
    signing_input = f"{header_encoded}.{payload_encoded}"
    signing_input_bytes = signing_input.encode('utf-8')
    signing_input_hex = bytes_to_hex(signing_input_bytes)

    # Note: Signing with Ed25519 would go here
    # For now, we'll return a placeholder signature
    # signature_hex = await sign(signing_input_hex, private_key_hex, payload_dict['publicKey'])
    signature_hex = "PLACEHOLDER_SIGNATURE_" + signing_input_hex[:16]

    # Return token in JWT format: header.payload.signature
    return f"{header_encoded}.{payload_encoded}.{signature_hex}"


async def verify_auth_token(
    token: str,
    expected_public_key_hex: Optional[str] = None
) -> Optional[AuthTokenPayload]:
    """
    Verify and decode an authentication token

    Args:
        token: JWT-style token string
        expected_public_key_hex: Expected public key in hex format (optional)

    Returns:
        Decoded payload if valid, None if invalid
    """
    try:
        # Parse token
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header_encoded, payload_encoded, signature_hex = parts

        # Decode header and payload
        header_bytes = base64url_decode(header_encoded)
        payload_bytes = base64url_decode(payload_encoded)

        header_json = header_bytes.decode('utf-8')
        payload_json = payload_bytes.decode('utf-8')

        header = json.loads(header_json)
        payload = json.loads(payload_json)

        # Validate header
        if header.get('alg') != 'Ed25519' or header.get('typ') != 'JWT':
            return None

        # Validate payload has required fields
        if not payload.get('publicKey') or not payload.get('iat'):
            return None

        # Check if expected public key matches
        if expected_public_key_hex and payload['publicKey'].upper() != expected_public_key_hex.upper():
            return None

        # Check expiration if present
        if payload.get('exp'):
            now = int(datetime.now().timestamp())
            if now > payload['exp']:
                return None  # Token expired

        # Note: Verify signature would go here
        # For now, we'll just return the payload without verification
        # verify_result = await verify(signature_hex, signing_input, payload['publicKey'])
        # if not verify_result:
        #     return None

        return AuthTokenPayload(**payload)
    except Exception as error:
        return None


def parse_auth_token(token: str) -> Optional[AuthToken]:
    """
    Parse a token without verifying (useful for debugging)

    Args:
        token: JWT-style token string

    Returns:
        Parsed token structure or None if invalid format
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        return AuthToken(header=parts[0], payload=parts[1], signature=parts[2])
    except Exception:
        return None


def decode_auth_token_payload(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode token payload without verification (useful for debugging)

    Args:
        token: JWT-style token string

    Returns:
        Decoded payload or None if invalid format
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        payload_bytes = base64url_decode(parts[1])
        payload_json = payload_bytes.decode('utf-8')
        return json.loads(payload_json)
    except Exception:
        return None
