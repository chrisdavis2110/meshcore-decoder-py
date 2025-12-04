"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Channel encryption/decryption using MeshCore algorithm
"""

import hmac
import hashlib
import re
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from ..types.crypto import DecryptionResult
from ..utils.hex import hex_to_bytes, bytes_to_hex

# Try to import Ed25519/X25519 for key exchange
try:
    from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    X25519_AVAILABLE = True
    ED25519_AVAILABLE = True
except ImportError:
    X25519_AVAILABLE = False
    ED25519_AVAILABLE = False

# Try to import PyNaCl for proper Ed25519 to X25519 conversion
try:
    import nacl.utils
    from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519
    PYNaCl_AVAILABLE = True
except ImportError:
    PYNaCl_AVAILABLE = False


class ChannelCrypto:
    @staticmethod
    def decrypt_group_text_message(
        ciphertext: str,
        cipher_mac: str,
        channel_key: str
    ) -> DecryptionResult:
        """
        Decrypt GroupText message using MeshCore algorithm:
        - HMAC-SHA256 verification with 2-byte MAC
        - AES-128 ECB decryption
        """
        try:
            # Convert hex strings to byte arrays
            channel_key_full = hex_to_bytes(channel_key)

            # MeshCore uses only the first 16 bytes of the channel key for encryption
            # Channel keys are typically 16 bytes, but we handle longer keys gracefully
            if len(channel_key_full) < 16:
                return DecryptionResult(success=False, error=f'Channel key too short: {len(channel_key_full)} bytes (need at least 16 bytes)')

            channel_key_16 = channel_key_full[:16]
            mac_bytes = hex_to_bytes(cipher_mac)

            # MeshCore uses 32-byte channel secret: 16-byte key + 16 zero bytes
            channel_secret = bytearray(32)
            channel_secret[:16] = channel_key_16
            # Rest are already zero

            # Step 1: Verify HMAC-SHA256 using full 32-byte channel secret
            ciphertext_bytes = hex_to_bytes(ciphertext)

            h = hmac.new(channel_secret, ciphertext_bytes, hashlib.sha256)
            calculated_mac_bytes = h.digest()
            calculated_mac_first2 = calculated_mac_bytes[:2]

            if calculated_mac_first2[0] != mac_bytes[0] or calculated_mac_first2[1] != mac_bytes[1]:
                return DecryptionResult(success=False, error='MAC verification failed')

            # Step 2: Decrypt using AES-128 ECB with first 16 bytes of channel secret
            key_bytes = channel_key_16

            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted_bytes = cipher.decrypt(ciphertext_bytes)

            if not decrypted_bytes or len(decrypted_bytes) < 5:
                return DecryptionResult(success=False, error='Decrypted content too short')

            # Parse MeshCore format: timestamp(4) + flags(1) + message_text
            timestamp = (
                decrypted_bytes[0] |
                (decrypted_bytes[1] << 8) |
                (decrypted_bytes[2] << 16) |
                (decrypted_bytes[3] << 24)
            )

            flags_and_attempt = decrypted_bytes[4]

            # Extract message text with UTF-8 decoding
            message_bytes = decrypted_bytes[5:]
            try:
                message_text = message_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # Try to decode as much as possible
                message_text = message_bytes.decode('utf-8', errors='replace')

            # Remove null terminator if present
            null_index = message_text.find('\0')
            if null_index >= 0:
                message_text = message_text[:null_index]

            # Parse sender and message (format: "sender: message")
            colon_index = message_text.find(': ')
            sender = None
            content = message_text

            if 0 < colon_index < 50:
                potential_sender = message_text[:colon_index]
                if not re.search(r'[:\[\]]', potential_sender):
                    sender = potential_sender
                    content = message_text[colon_index + 2:]

            return DecryptionResult(
                success=True,
                data={
                    'timestamp': timestamp,
                    'flags': flags_and_attempt,
                    'sender': sender,
                    'message': content
                }
            )
        except Exception as error:
            error_msg = str(error) if isinstance(error, Exception) else 'Decryption failed'
            return DecryptionResult(success=False, error=error_msg)

    @staticmethod
    def _ed25519_to_x25519_private(ed25519_private: bytes) -> Optional[bytes]:
        """
        Convert Ed25519 private key to X25519 private key
        Uses Libsodium's crypto_sign_ed25519_sk_to_curve25519 if available
        """
        if len(ed25519_private) < 32:
            return None

        # For 64-byte Ed25519 keys, use first 32 bytes (seed)
        seed = ed25519_private[:32]

        # Use PyNaCl (Libsodium) conversion if available
        if PYNaCl_AVAILABLE:
            try:
                # Libsodium's crypto_sign_ed25519_sk_to_curve25519 expects 64-byte Ed25519 private key
                # Format: 32-byte seed + 32-byte public key
                if len(ed25519_private) >= 64:
                    # Use first 64 bytes (seed + public key)
                    ed25519_private_64 = ed25519_private[:64]
                    x25519_private = crypto_sign_ed25519_sk_to_curve25519(ed25519_private_64)
                    return x25519_private
                elif len(ed25519_private) == 32:
                    # For 32-byte keys (seed only), we can still use Libsodium
                    # Libsodium can work with 32-byte seed, but it's better to have 64 bytes
                    # Try padding with zeros (this might not work, but worth trying)
                    # Actually, let's derive the public key or use a different approach
                    # For now, try the seed directly - Libsodium might handle it
                    try:
                        # Some Libsodium implementations accept 32-byte seed
                        # Pad to 64 bytes with zeros (seed + placeholder public key)
                        ed25519_private_64 = ed25519_private[:32] + b'\x00' * 32
                        x25519_private = crypto_sign_ed25519_sk_to_curve25519(ed25519_private_64)
                        return x25519_private
                    except:
                        # If that fails, use fallback
                        pass
            except Exception as e:
                # Conversion failed, try fallback
                pass

        # Fallback: Use SHA-512 method with MeshCore clamping
        try:
            hash_obj = hashlib.sha512(seed)
            hash_bytes = hash_obj.digest()

            # Use first 32 bytes of hash as X25519 private key (clamped with MeshCore method)
            x25519_private = bytearray(hash_bytes[:32])
            x25519_private[0] &= 248
            x25519_private[31] &= 63  # MeshCore specific (not 127)
            x25519_private[31] |= 64

            return bytes(x25519_private)
        except Exception:
            return None

    @staticmethod
    def _ed25519_to_x25519_public(ed25519_public: bytes) -> Optional[bytes]:
        """
        Convert Ed25519 public key to X25519 public key
        Uses Libsodium's crypto_sign_ed25519_pk_to_curve25519 if available
        """
        if len(ed25519_public) < 32:
            return None

        # Use PyNaCl (Libsodium) conversion if available - this is the correct method
        if PYNaCl_AVAILABLE:
            try:
                x25519_public = crypto_sign_ed25519_pk_to_curve25519(ed25519_public[:32])
                return x25519_public
            except Exception as e:
                # Conversion failed
                return None

        # Fallback: Try using bytes directly (won't work but might give better error)
        try:
            return ed25519_public[:32]
        except Exception:
            return None

    @staticmethod
    def _meshcore_clamp_private_key(private_key_bytes: bytes) -> Optional[bytes]:
        """
        Clamp private key according to MeshCore's ed25519_key_exchange implementation
        MeshCore uses: e[0] &= 248; e[31] &= 63; e[31] |= 64;
        This differs from standard X25519 which uses: e[31] &= 127

        Args:
            private_key_bytes: Ed25519 private key (32-byte seed or 64-byte seed+pub)

        Returns:
            Clamped private key (32 bytes) or None if invalid
        """
        if len(private_key_bytes) < 32:
            return None

        # Extract seed (first 32 bytes)
        seed = private_key_bytes[:32]

        # MeshCore clamping: e[0] &= 248; e[31] &= 63; e[31] |= 64;
        clamped = bytearray(seed)
        clamped[0] &= 248  # Clear bits 0-2
        clamped[31] &= 63  # Clear bits 6-7 (MeshCore specific: 63 = 0x3F)
        clamped[31] |= 64  # Set bit 6

        return bytes(clamped)

    @staticmethod
    def _ed25519_key_exchange(private_key_bytes: bytes, public_key_bytes: bytes) -> Optional[bytes]:
        """
        Perform Ed25519 key exchange to derive shared secret
        Matches decrypt_response.py implementation which uses MeshCore's exact clamping

        Args:
            private_key_bytes: Ed25519 private key (32-byte seed or 64-byte seed+pub)
            public_key_bytes: Other party's Ed25519 public key (32 bytes)

        Returns:
            Shared secret (32 bytes) or None if key exchange fails
        """
        if not X25519_AVAILABLE or not ED25519_AVAILABLE:
            return None

        try:
            # Method 1: Use cryptography library's Ed25519 keys (matches decrypt_response.py)
            # This properly handles the seed format
            try:
                # Load Ed25519 private key (handles both 32-byte and 64-byte formats)
                # For 64-byte keys, use only first 32 bytes (the seed)
                if len(private_key_bytes) >= 64:
                    ed25519_private_seed = private_key_bytes[:32]
                else:
                    ed25519_private_seed = private_key_bytes[:32]

                ed25519_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_private_seed)

                # Load Ed25519 public key
                if len(public_key_bytes) < 32:
                    return None
                ed25519_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes[:32])

                # Convert Ed25519 private key to X25519 using MeshCore's clamping
                # Get the raw private bytes (seed)
                private_raw = ed25519_private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )

                # Extract first 32 bytes (the seed/scalar)
                scalar = bytearray(private_raw[:32])

                # Apply MeshCore clamping: e[0] &= 248; e[31] &= 63; e[31] |= 64;
                scalar[0] &= 248
                scalar[31] &= 63  # MeshCore specific (not 127)
                scalar[31] |= 64

                x25519_private = x25519.X25519PrivateKey.from_private_bytes(bytes(scalar))

                # Convert Ed25519 public key to X25519 using PyNaCl
                if not PYNaCl_AVAILABLE:
                    return None

                public_raw = ed25519_public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )

                # Use PyNaCl for Edwards-to-Montgomery conversion
                x25519_public_bytes = crypto_sign_ed25519_pk_to_curve25519(public_raw)
                x25519_public = x25519.X25519PublicKey.from_public_bytes(x25519_public_bytes)

                # Perform X25519 key exchange
                shared_secret = x25519_private.exchange(x25519_public)
                return shared_secret

            except Exception as e:
                # If cryptography library method fails, fall back to PyNaCl conversion
                pass

            # Method 2: Fallback to PyNaCl conversion (standard Libsodium method)
            x25519_private_bytes = ChannelCrypto._ed25519_to_x25519_private(private_key_bytes)
            x25519_public_bytes = ChannelCrypto._ed25519_to_x25519_public(public_key_bytes)

            if not x25519_private_bytes or not x25519_public_bytes:
                return None

            try:
                x25519_private = x25519.X25519PrivateKey.from_private_bytes(x25519_private_bytes)
                x25519_public = x25519.X25519PublicKey.from_public_bytes(x25519_public_bytes)

                # Perform key exchange
                shared_secret = x25519_private.exchange(x25519_public)
                return shared_secret
            except Exception as e:
                return None
        except Exception:
            return None

    @staticmethod
    def decrypt_node_message(
        ciphertext: str,
        cipher_mac: str,
        node_private_key: str,
        node_public_key: Optional[str] = None,
        other_public_key: Optional[str] = None
    ) -> DecryptionResult:
        """
        Decrypt node-to-node message (Request/Response) using MeshCore algorithm:
        - HMAC-SHA256 verification with 2-byte MAC
        - AES-128 ECB decryption
        Uses Ed25519 key exchange (ECDH) to derive shared secret

        Args:
            node_private_key: Our Ed25519 private key in hex format
            node_public_key: Our Ed25519 public key in hex format (optional, for fallback)
            other_public_key: Other party's Ed25519 public key in hex format (required for key exchange)
        """
        try:
            # First, try Ed25519 key exchange if we have the other party's public key
            # This is the correct method according to MeshCore source code
            if other_public_key:
                other_pub_bytes = hex_to_bytes(other_public_key)
                our_priv_bytes = hex_to_bytes(node_private_key)

                if len(other_pub_bytes) == 32 and len(our_priv_bytes) >= 32:
                    shared_secret = ChannelCrypto._ed25519_key_exchange(our_priv_bytes, other_pub_bytes)

                    if shared_secret and len(shared_secret) >= 32:
                        mac_bytes = hex_to_bytes(cipher_mac)
                        ciphertext_bytes = hex_to_bytes(ciphertext)

                        # According to MeshCore source code (MACThenDecrypt):
                        # - sha.resetHMAC(shared_secret, PUB_KEY_SIZE) where PUB_KEY_SIZE = 32
                        # - So HMAC uses the FULL 32-byte shared secret directly, not 16 bytes + zeros!
                        # - Then decrypt uses shared_secret (probably first 16 bytes for AES-128)

                        # Method 1: Use full 32-byte shared secret for HMAC (as per MeshCore source)
                        # This matches MeshCore's MACThenDecrypt: HMAC(shared_secret[32], ciphertext)
                        shared_secret_32 = shared_secret[:32]
                        shared_secret_16 = shared_secret[:16]  # For AES-128

                        # HMAC uses full 32-byte shared secret (PUB_KEY_SIZE = 32)
                        h = hmac.new(shared_secret_32, ciphertext_bytes, hashlib.sha256)
                        calculated_mac_bytes = h.digest()
                        calculated_mac_first2 = calculated_mac_bytes[:2]

                        if calculated_mac_first2[0] == mac_bytes[0] and calculated_mac_first2[1] == mac_bytes[1]:
                            # MAC verified, decrypt using first 16 bytes for AES-128
                            cipher = AES.new(shared_secret_16, AES.MODE_ECB)
                            decrypted_bytes = cipher.decrypt(ciphertext_bytes)
                            if decrypted_bytes and len(decrypted_bytes) >= 4:
                                return DecryptionResult(success=True, data=decrypted_bytes)

                        # Method 2: Try using first 16 bytes for both HMAC and AES (fallback)
                        # Some implementations might pad with zeros
                        shared_secret_16 = shared_secret[:16]
                        node_secret = bytearray(32)
                        node_secret[:16] = shared_secret_16

                        h = hmac.new(node_secret, ciphertext_bytes, hashlib.sha256)
                        calculated_mac_bytes = h.digest()
                        calculated_mac_first2 = calculated_mac_bytes[:2]

                        if calculated_mac_first2[0] == mac_bytes[0] and calculated_mac_first2[1] == mac_bytes[1]:
                            cipher = AES.new(shared_secret_16, AES.MODE_ECB)
                            decrypted_bytes = cipher.decrypt(ciphertext_bytes)
                            if decrypted_bytes and len(decrypted_bytes) >= 4:
                                return DecryptionResult(success=True, data=decrypted_bytes)

                        # All methods failed - the shared secret from key exchange is wrong
                        # This means the Ed25519 key exchange implementation doesn't match MeshCore
                        return DecryptionResult(
                            success=False,
                            error=f'Key exchange succeeded but MAC verification failed. '
                                  f'Shared secret length: {len(shared_secret)} bytes. '
                                  f'Tried: full 32-byte shared secret for HMAC (as per MeshCore MACThenDecrypt), 16-byte + zeros. '
                                  f'Issue: Ed25519 key exchange may not match MeshCore implementation exactly. '
                                  f'MeshCore uses custom ed25519_key_exchange() with Edwards-to-Montgomery conversion.'
                        )
                    else:
                        # Key exchange failed
                        return DecryptionResult(
                            success=False,
                            error=f'Ed25519 key exchange failed. Check that private key and public key are compatible. Private key length: {len(our_priv_bytes)}, Public key length: {len(other_pub_bytes)}'
                        )

            # Fallback to old methods if key exchange not available or failed
            # Convert hex strings to byte arrays
            node_key_full = hex_to_bytes(node_private_key)

            # MeshCore uses only the first 16 bytes of the private key for encryption
            # Ed25519 private keys can be 32 bytes (seed) or 64 bytes (seed + public key)
            # We extract just the first 16 bytes for the AES key
            if len(node_key_full) < 16:
                return DecryptionResult(success=False, error=f'Private key too short: {len(node_key_full)} bytes (need at least 16 bytes)')

            # Try different byte ranges if key is longer than 16 bytes
            # For 64-byte keys, try: bytes 0-15 (first half of seed) and bytes 16-31 (second half of seed)
            key_ranges_to_try = []
            if len(node_key_full) >= 16:
                key_ranges_to_try.append(('0-15', node_key_full[0:16]))
            if len(node_key_full) >= 32:
                key_ranges_to_try.append(('16-31', node_key_full[16:32]))
            if len(node_key_full) >= 48:
                key_ranges_to_try.append(('32-47', node_key_full[32:48]))
            if len(node_key_full) >= 64:
                key_ranges_to_try.append(('48-63', node_key_full[48:64]))

            mac_bytes = hex_to_bytes(cipher_mac)
            ciphertext_bytes = hex_to_bytes(ciphertext)

            # Try each key range
            errors_tried = []
            for range_name, node_key_16 in key_ranges_to_try:

                # MeshCore uses 32-byte node secret: 16-byte key + 16 zero bytes
                node_secret = bytearray(32)
                node_secret[:16] = node_key_16
                # Rest are already zero

                # Step 1: Verify HMAC-SHA256 using full 32-byte node secret
                h = hmac.new(node_secret, ciphertext_bytes, hashlib.sha256)
                calculated_mac_bytes = h.digest()
                calculated_mac_first2 = calculated_mac_bytes[:2]

                if calculated_mac_first2[0] != mac_bytes[0] or calculated_mac_first2[1] != mac_bytes[1]:
                    errors_tried.append(f'bytes {range_name}: MAC mismatch')
                    continue

                # Step 2: Decrypt using AES-128 ECB with first 16 bytes of node secret
                key_bytes = node_key_16

                cipher = AES.new(key_bytes, AES.MODE_ECB)
                decrypted_bytes = cipher.decrypt(ciphertext_bytes)

                if not decrypted_bytes or len(decrypted_bytes) < 4:
                    errors_tried.append(f'bytes {range_name}: decrypted content too short')
                    continue

                # Success!
                return DecryptionResult(
                    success=True,
                    data=decrypted_bytes
                )

            # If we get here, all key ranges failed
            # Try additional derivation methods:

            # Method 1: SHA256 hash of full key (first 16 bytes)
            if len(node_key_full) >= 32:
                try:
                    key_hash = hashlib.sha256(node_key_full).digest()[:16]
                    node_secret = bytearray(32)
                    node_secret[:16] = key_hash

                    h = hmac.new(node_secret, ciphertext_bytes, hashlib.sha256)
                    calculated_mac_bytes = h.digest()
                    calculated_mac_first2 = calculated_mac_bytes[:2]

                    if calculated_mac_first2[0] == mac_bytes[0] and calculated_mac_first2[1] == mac_bytes[1]:
                        cipher = AES.new(key_hash, AES.MODE_ECB)
                        decrypted_bytes = cipher.decrypt(ciphertext_bytes)

                        if decrypted_bytes and len(decrypted_bytes) >= 4:
                            return DecryptionResult(success=True, data=decrypted_bytes)
                except:
                    pass

            # Method 2: SHA256 hash of seed part only (first 32 bytes for 64-byte keys)
            if len(node_key_full) >= 32:
                try:
                    seed_part = node_key_full[:32]
                    key_hash = hashlib.sha256(seed_part).digest()[:16]
                    node_secret = bytearray(32)
                    node_secret[:16] = key_hash

                    h = hmac.new(node_secret, ciphertext_bytes, hashlib.sha256)
                    calculated_mac_bytes = h.digest()
                    calculated_mac_first2 = calculated_mac_bytes[:2]

                    if calculated_mac_first2[0] == mac_bytes[0] and calculated_mac_first2[1] == mac_bytes[1]:
                        cipher = AES.new(key_hash, AES.MODE_ECB)
                        decrypted_bytes = cipher.decrypt(ciphertext_bytes)

                        if decrypted_bytes and len(decrypted_bytes) >= 4:
                            return DecryptionResult(success=True, data=decrypted_bytes)
                except:
                    pass

            # Method 3: Try using last 16 bytes of seed (bytes 16-31) with hash
            if len(node_key_full) >= 32:
                try:
                    seed_second_half = node_key_full[16:32]
                    key_hash = hashlib.sha256(seed_second_half).digest()[:16]
                    node_secret = bytearray(32)
                    node_secret[:16] = key_hash

                    h = hmac.new(node_secret, ciphertext_bytes, hashlib.sha256)
                    calculated_mac_bytes = h.digest()
                    calculated_mac_first2 = calculated_mac_bytes[:2]

                    if calculated_mac_first2[0] == mac_bytes[0] and calculated_mac_first2[1] == mac_bytes[1]:
                        cipher = AES.new(key_hash, AES.MODE_ECB)
                        decrypted_bytes = cipher.decrypt(ciphertext_bytes)

                        if decrypted_bytes and len(decrypted_bytes) >= 4:
                            return DecryptionResult(success=True, data=decrypted_bytes)
                except:
                    pass

            # If public key provided, try combining public and private keys
            if node_public_key:
                try:
                    pubkey_bytes = hex_to_bytes(node_public_key)
                    if len(pubkey_bytes) >= 16:
                        # Method: Use first 16 bytes of public key
                        pubkey_16 = pubkey_bytes[:16]
                        node_secret = bytearray(32)
                        node_secret[:16] = pubkey_16

                        h = hmac.new(node_secret, ciphertext_bytes, hashlib.sha256)
                        calculated_mac_bytes = h.digest()
                        calculated_mac_first2 = calculated_mac_bytes[:2]

                        if calculated_mac_first2[0] == mac_bytes[0] and calculated_mac_first2[1] == mac_bytes[1]:
                            cipher = AES.new(pubkey_16, AES.MODE_ECB)
                            decrypted_bytes = cipher.decrypt(ciphertext_bytes)
                            if decrypted_bytes and len(decrypted_bytes) >= 4:
                                return DecryptionResult(success=True, data=decrypted_bytes)

                        # Method: XOR first 16 bytes of private and public key
                        if len(node_key_full) >= 16:
                            xor_key = bytes([a ^ b for a, b in zip(node_key_full[:16], pubkey_16)])
                            node_secret = bytearray(32)
                            node_secret[:16] = xor_key

                            h = hmac.new(node_secret, ciphertext_bytes, hashlib.sha256)
                            calculated_mac_bytes = h.digest()
                            calculated_mac_first2 = calculated_mac_bytes[:2]

                            if calculated_mac_first2[0] == mac_bytes[0] and calculated_mac_first2[1] == mac_bytes[1]:
                                cipher = AES.new(xor_key, AES.MODE_ECB)
                                decrypted_bytes = cipher.decrypt(ciphertext_bytes)
                                if decrypted_bytes and len(decrypted_bytes) >= 4:
                                    return DecryptionResult(success=True, data=decrypted_bytes)

                        # Method: SHA256 of concatenated private + public key (first 16 bytes)
                        combined = node_key_full[:32] + pubkey_bytes[:32] if len(node_key_full) >= 32 else node_key_full + pubkey_bytes
                        combined_hash = hashlib.sha256(combined).digest()[:16]
                        node_secret = bytearray(32)
                        node_secret[:16] = combined_hash

                        h = hmac.new(node_secret, ciphertext_bytes, hashlib.sha256)
                        calculated_mac_bytes = h.digest()
                        calculated_mac_first2 = calculated_mac_bytes[:2]

                        if calculated_mac_first2[0] == mac_bytes[0] and calculated_mac_first2[1] == mac_bytes[1]:
                            cipher = AES.new(combined_hash, AES.MODE_ECB)
                            decrypted_bytes = cipher.decrypt(ciphertext_bytes)
                            if decrypted_bytes and len(decrypted_bytes) >= 4:
                                return DecryptionResult(success=True, data=decrypted_bytes)
                except:
                    pass

            # Build comprehensive error message
            key_length = len(node_key_full)
            ranges_tried = ', '.join([r[0] for r in key_ranges_to_try])
            error_msg = f'MAC verification failed. Key length: {key_length} bytes. Tried ranges: {ranges_tried}'
            if errors_tried:
                error_msg += f'. Errors: {"; ".join(errors_tried)}'
            if node_public_key:
                error_msg += '. Also tried public key and combined key methods.'
            return DecryptionResult(success=False, error=error_msg)
        except Exception as error:
            error_msg = str(error) if isinstance(error, Exception) else 'Decryption failed'
            return DecryptionResult(success=False, error=error_msg)

    @staticmethod
    def calculate_channel_hash(secret_key_hex: str) -> str:
        """
        Calculate MeshCore channel hash from secret key
        Returns the first byte of SHA256(secret) as hex string
        """
        hash_obj = hashlib.sha256(hex_to_bytes(secret_key_hex))
        hash_bytes = hash_obj.digest()
        return f"{hash_bytes[0]:02x}"
