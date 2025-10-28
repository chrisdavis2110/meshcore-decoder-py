"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Crypto-related type definitions
"""

from typing import Dict, List, Protocol, Optional, Any


class CryptoKeyStore(Protocol):
    """Protocol for key storage"""
    # node keys for TextMessage/Request decryption
    node_keys: Dict[str, str]  # nodePublicKey -> privateKey (hex)

    def add_node_key(self, public_key: str, private_key: str) -> None:
        """Add/update keys"""
        ...

    def has_channel_key(self, channel_hash: str) -> bool:
        """Check if keys are available"""
        ...

    def has_node_key(self, public_key: str) -> bool:
        """Check if node key is available"""
        ...

    def get_channel_keys(self, channel_hash: str) -> List[str]:
        """Get channel keys for a channel hash"""
        ...


class DecryptionOptions:
    """Options for packet decryption"""
    def __init__(
        self,
        key_store: Optional[CryptoKeyStore] = None,
        attempt_decryption: bool = True,  # default: true if keyStore provided
        include_raw_ciphertext: bool = True  # default: true
    ):
        self.key_store = key_store
        self.attempt_decryption = attempt_decryption if key_store else False
        self.include_raw_ciphertext = include_raw_ciphertext


class DecryptionResult:
    """Result of a decryption operation"""
    def __init__(
        self,
        success: bool,
        data: Optional[Any] = None,
        error: Optional[str] = None
    ):
        self.success = success
        self.data = data
        self.error = error


class ValidationResult:
    """Result of a validation operation"""
    def __init__(
        self,
        is_valid: bool,
        errors: Optional[List[str]] = None
    ):
        self.is_valid = is_valid
        self.errors = errors or []
