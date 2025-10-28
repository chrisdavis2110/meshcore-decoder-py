"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Key management for MeshCore crypto operations
"""

from typing import Dict, List, Optional
from src.types.crypto import CryptoKeyStore
from src.crypto.channel_crypto import ChannelCrypto


class MeshCoreKeyStore:
    """
    Key store for MeshCore packet decryption

    Manages:
    - Node keys for TextMessage/Request decryption
    - Channel secrets for GroupText decryption
    """

    def __init__(self, initial_keys: Optional[Dict[str, any]] = None):
        """Initialize key store with optional initial keys"""
        self.node_keys: Dict[str, str] = {}  # nodePublicKey -> privateKey (hex)
        self._channel_hash_to_keys: Dict[str, List[str]] = {}  # channelHash -> [secret_keys...]

        if initial_keys:
            if 'channel_secrets' in initial_keys:
                self.add_channel_secrets(initial_keys['channel_secrets'])

            if 'node_keys' in initial_keys:
                for pub_key, priv_key in initial_keys['node_keys'].items():
                    self.add_node_key(pub_key, priv_key)

    def add_node_key(self, public_key: str, private_key: str) -> None:
        """Add or update a node key"""
        normalized_pub_key = public_key.upper()
        self.node_keys[normalized_pub_key] = private_key

    def has_channel_key(self, channel_hash: str) -> bool:
        """Check if a channel key exists for the given hash"""
        normalized_hash = channel_hash.lower()
        return normalized_hash in self._channel_hash_to_keys

    def has_node_key(self, public_key: str) -> bool:
        """Check if a node key exists for the given public key"""
        normalized_pub_key = public_key.upper()
        return normalized_pub_key in self.node_keys

    def get_channel_keys(self, channel_hash: str) -> List[str]:
        """Get all channel keys that match the given channel hash (handles collisions)"""
        normalized_hash = channel_hash.lower()
        return self._channel_hash_to_keys.get(normalized_hash, [])

    def get_node_key(self, public_key: str) -> Optional[str]:
        """Get a node key by public key"""
        normalized_pub_key = public_key.upper()
        return self.node_keys.get(normalized_pub_key)

    def add_channel_secrets(self, secret_keys: List[str]) -> None:
        """
        Add channel keys by secret keys (new simplified API)
        Automatically calculates channel hashes
        """
        for secret_key in secret_keys:
            channel_hash = ChannelCrypto.calculate_channel_hash(secret_key).lower()

            # Handle potential hash collisions
            if channel_hash not in self._channel_hash_to_keys:
                self._channel_hash_to_keys[channel_hash] = []
            self._channel_hash_to_keys[channel_hash].append(secret_key)
