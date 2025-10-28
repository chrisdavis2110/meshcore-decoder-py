"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Ed25519 signature verification for MeshCore packets
"""

from typing import Optional
from src.utils.hex import hex_to_bytes, bytes_to_hex

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    try:
        import ed25519 as ed25519_module
        CRYPTOGRAPHY_AVAILABLE = False
        ED25519_MODULE_AVAILABLE = True
    except ImportError:
        CRYPTOGRAPHY_AVAILABLE = False
        ED25519_MODULE_AVAILABLE = False
        print("Warning: No Ed25519 library available. Signature verification disabled.")


class Ed25519SignatureVerifier:
    """Ed25519 signature verification for MeshCore advertisement packets"""

    @staticmethod
    async def verify_advertisement_signature(
        public_key_hex: str,
        signature_hex: str,
        timestamp: int,
        app_data_hex: str
    ) -> bool:
        """
        Verify an Ed25519 signature for MeshCore advertisement packets

        According to MeshCore protocol, the signed message for advertisements is:
        public_key (32 bytes) + timestamp (4 bytes LE) + app_data (variable)
        """
        try:
            # Convert hex strings to bytes
            public_key = hex_to_bytes(public_key_hex)
            signature = hex_to_bytes(signature_hex)
            app_data = hex_to_bytes(app_data_hex)

            # Construct the signed message according to MeshCore format
            message = Ed25519SignatureVerifier._construct_advert_signed_message(
                public_key_hex, timestamp, app_data
            )

            # Verify the signature
            return Ed25519SignatureVerifier._verify_signature(signature, message, public_key)
        except Exception as error:
            print(f'Ed25519 signature verification failed: {error}')
            return False

    @staticmethod
    def _construct_advert_signed_message(
        public_key_hex: str,
        timestamp: int,
        app_data: bytes
    ) -> bytes:
        """
        Construct the signed message for MeshCore advertisements
        According to MeshCore source (Mesh.cpp lines 242-248):
        Format: public_key (32 bytes) + timestamp (4 bytes LE) + app_data (variable length)
        """
        public_key = hex_to_bytes(public_key_hex)

        # Timestamp (4 bytes, little-endian)
        timestamp_bytes = timestamp.to_bytes(4, byteorder='little')

        # Concatenate: public_key + timestamp + app_data
        message = public_key + timestamp_bytes + app_data

        return message

    @staticmethod
    def _verify_signature(signature: bytes, message: bytes, public_key: bytes) -> bool:
        """Verify Ed25519 signature using available library"""
        if CRYPTOGRAPHY_AVAILABLE:
            return Ed25519SignatureVerifier._verify_with_cryptography(signature, message, public_key)
        elif ED25519_MODULE_AVAILABLE:
            return Ed25519SignatureVerifier._verify_with_ed25519_module(signature, message, public_key)
        else:
            print("No Ed25519 library available for verification")
            return False

    @staticmethod
    def _verify_with_cryptography(signature: bytes, message: bytes, public_key: bytes) -> bool:
        """Verify using cryptography library"""
        try:
            public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            public_key_obj.verify(signature, message)
            return True
        except Exception as e:
            print(f'Cryptography library verification error: {e}')
            return False

    @staticmethod
    def _verify_with_ed25519_module(signature: bytes, message: bytes, public_key: bytes) -> bool:
        """Verify using ed25519 module"""
        try:
            # Create public key object
            public_key_obj = ed25519_mod.VerifyingKey(public_key)
            public_key_obj.verify(signature, message)
            return True
        except Exception as e:
            print(f'Ed25519 module verification error: {e}')
            return False

    @staticmethod
    def get_signed_message_description(
        public_key_hex: str,
        timestamp: int,
        app_data_hex: str
    ) -> str:
        """Get a human-readable description of what was signed"""
        from datetime import datetime
        ts_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        return f"Public Key: {public_key_hex} + Timestamp: {timestamp} ({ts_str}) + App Data: {app_data_hex}"

    @staticmethod
    def get_signed_message_hex(
        public_key_hex: str,
        timestamp: int,
        app_data_hex: str
    ) -> str:
        """Get the hex representation of the signed message for debugging"""
        app_data = hex_to_bytes(app_data_hex)
        message = Ed25519SignatureVerifier._construct_advert_signed_message(
            public_key_hex, timestamp, app_data
        )
        return bytes_to_hex(message)
