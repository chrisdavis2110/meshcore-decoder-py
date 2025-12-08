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
            channel_key_16 = hex_to_bytes(channel_key)
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
            key_bytes = hex_to_bytes(channel_key)

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
    def calculate_channel_hash(secret_key_hex: str) -> str:
        """
        Calculate MeshCore channel hash from secret key
        Returns the first byte of SHA256(secret) as hex string
        """
        hash_obj = hashlib.sha256(hex_to_bytes(secret_key_hex))
        hash_bytes = hash_obj.digest()
        return f"{hash_bytes[0]:02x}"

    @staticmethod
    def _ed25519_key_exchange(private_key_bytes: bytes, public_key_bytes: bytes) -> Optional[bytes]:
        """
        Perform Ed25519 key exchange to derive shared secret
        Matches MeshCore's exact implementation with proper Ed25519 to X25519 conversion

        Args:
            private_key_bytes: Ed25519 private key (32-byte seed or 64-byte seed+pub)
            public_key_bytes: Other party's Ed25519 public key (32 bytes)

        Returns:
            Shared secret (32 bytes) or None if key exchange fails
        """
        if not X25519_AVAILABLE or not ED25519_AVAILABLE:
            return None

        try:
            # Method 1: Use cryptography library's Ed25519 keys with proper conversion
            try:
                # Load Ed25519 private key (handles both 32-byte and 64-byte formats)
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
                # If cryptography library method fails, try fallback
                pass

            # Method 2: Fallback using PyNaCl conversion directly
            if PYNaCl_AVAILABLE:
                try:
                    # Convert Ed25519 private key to X25519
                    if len(private_key_bytes) >= 64:
                        ed25519_private_64 = private_key_bytes[:64]
                    else:
                        # Pad to 64 bytes if needed
                        ed25519_private_64 = private_key_bytes[:32] + b'\x00' * 32

                    x25519_private_bytes = crypto_sign_ed25519_sk_to_curve25519(ed25519_private_64)
                    x25519_public_bytes = crypto_sign_ed25519_pk_to_curve25519(public_key_bytes[:32])

                    if X25519_AVAILABLE:
                        x25519_private = x25519.X25519PrivateKey.from_private_bytes(x25519_private_bytes)
                        x25519_public = x25519.X25519PublicKey.from_public_bytes(x25519_public_bytes)
                        shared_secret = x25519_private.exchange(x25519_public)
                        return shared_secret
                except Exception:
                    pass

            return None
        except Exception:
            return None

    @staticmethod
    def calculate_shared_secret(peer_public_key: str, my_private_key: str) -> Optional[bytes]:
        """
        Calculate ECDH shared secret using Ed25519 keys
        MeshCore uses Ed25519 keys but performs X25519 ECDH (Curve25519)
        Uses proper Ed25519 to X25519 conversion matching MeshCore's implementation

        Args:
            peer_public_key: Peer's Ed25519 public key (32 bytes, hex string)
            my_private_key: Our Ed25519 private key (64 bytes, hex string)

        Returns:
            32-byte shared secret, or None if calculation fails
        """
        try:
            peer_pub_bytes = hex_to_bytes(peer_public_key)
            my_priv_bytes = hex_to_bytes(my_private_key)

            if len(peer_pub_bytes) != 32:
                return None
            if len(my_priv_bytes) < 32:
                return None

            # Use the proper key exchange method
            return ChannelCrypto._ed25519_key_exchange(my_priv_bytes, peer_pub_bytes)
        except Exception as error:
            return None

    @staticmethod
    def decrypt_request_payload(
        ciphertext: str,
        cipher_mac: str,
        shared_secret: bytes
    ) -> DecryptionResult:
        """
        Decrypt Request payload using MeshCore algorithm:
        - HMAC-SHA256 verification with 2-byte MAC
        - AES-128 ECB decryption

        Args:
            ciphertext: Encrypted data (hex string)
            cipher_mac: MAC for verification (2 bytes, hex string)
            shared_secret: 32-byte ECDH shared secret (bytes)

        Returns:
            DecryptionResult with decrypted data
        """
        try:
            if shared_secret is None or len(shared_secret) < 32:
                return DecryptionResult(success=False, error='Invalid shared secret')

            mac_bytes = hex_to_bytes(cipher_mac)
            ciphertext_bytes = hex_to_bytes(ciphertext)

            # Step 1: Verify HMAC-SHA256 using full 32-byte shared secret
            h = hmac.new(shared_secret, ciphertext_bytes, hashlib.sha256)
            calculated_mac_bytes = h.digest()
            calculated_mac_first2 = calculated_mac_bytes[:2]

            if calculated_mac_first2[0] != mac_bytes[0] or calculated_mac_first2[1] != mac_bytes[1]:
                return DecryptionResult(success=False, error='MAC verification failed')

            # Step 2: Decrypt using AES-128 ECB with first 16 bytes of shared secret
            aes_key = shared_secret[:16]

            cipher = AES.new(aes_key, AES.MODE_ECB)
            decrypted_bytes = cipher.decrypt(ciphertext_bytes)

            if not decrypted_bytes or len(decrypted_bytes) < 5:
                return DecryptionResult(success=False, error='Decrypted content too short')

            # Parse MeshCore request format: timestamp(4) + request_type(1) + request_data(variable)
            timestamp = (
                decrypted_bytes[0] |
                (decrypted_bytes[1] << 8) |
                (decrypted_bytes[2] << 16) |
                (decrypted_bytes[3] << 24)
            )

            request_type = decrypted_bytes[4]
            request_data = decrypted_bytes[5:]

            return DecryptionResult(
                success=True,
                data={
                    'timestamp': timestamp,
                    'request_type': request_type,
                    'request_data': request_data
                }
            )
        except Exception as error:
            error_msg = str(error) if isinstance(error, Exception) else 'Decryption failed'
            return DecryptionResult(success=False, error=error_msg)

    @staticmethod
    def decrypt_text_message_payload(
        ciphertext: str,
        cipher_mac: str,
        shared_secret: bytes
    ) -> DecryptionResult:
        """
        Decrypt TextMessage payload using MeshCore algorithm:
        - HMAC-SHA256 verification with 2-byte MAC
        - AES-128 ECB decryption

        Args:
            ciphertext: Encrypted data (hex string)
            cipher_mac: MAC for verification (2 bytes, hex string)
            shared_secret: 32-byte ECDH shared secret (bytes)

        Returns:
            DecryptionResult with decrypted data (timestamp, flags, message)
        """
        try:
            if shared_secret is None or len(shared_secret) < 32:
                return DecryptionResult(success=False, error='Invalid shared secret')

            mac_bytes = hex_to_bytes(cipher_mac)
            ciphertext_bytes = hex_to_bytes(ciphertext)

            # Step 1: Verify HMAC-SHA256 using full 32-byte shared secret
            h = hmac.new(shared_secret, ciphertext_bytes, hashlib.sha256)
            calculated_mac_bytes = h.digest()
            calculated_mac_first2 = calculated_mac_bytes[:2]

            if calculated_mac_first2[0] != mac_bytes[0] or calculated_mac_first2[1] != mac_bytes[1]:
                return DecryptionResult(success=False, error='MAC verification failed')

            # Step 2: Decrypt using AES-128 ECB with first 16 bytes of shared secret
            aes_key = shared_secret[:16]

            cipher = AES.new(aes_key, AES.MODE_ECB)
            decrypted_bytes = cipher.decrypt(ciphertext_bytes)

            if not decrypted_bytes or len(decrypted_bytes) < 5:
                return DecryptionResult(success=False, error='Decrypted content too short')

            # Parse MeshCore text message format: timestamp(4) + flags(1) + message_text
            timestamp = (
                decrypted_bytes[0] |
                (decrypted_bytes[1] << 8) |
                (decrypted_bytes[2] << 16) |
                (decrypted_bytes[3] << 24)
            )

            flags = decrypted_bytes[4]
            txt_type = flags >> 2  # Upper 6 bits
            attempt = flags & 0x03  # Lower 2 bits

            # Extract message text (null-terminated, may have padding)
            message_bytes = decrypted_bytes[5:]

            # Handle special case: txt_type 0x02 (signed message)
            # First 4 bytes are sender pubkey prefix, then text
            sender_pubkey_prefix = None
            if txt_type == 0x02 and len(message_bytes) >= 4:
                sender_pubkey_prefix = bytes_to_hex(message_bytes[:4])
                message_bytes = message_bytes[4:]  # Skip pubkey prefix

            try:
                message_text = message_bytes.decode('utf-8')
            except UnicodeDecodeError:
                message_text = message_bytes.decode('utf-8', errors='replace')

            # Remove null terminator if present
            null_index = message_text.find('\0')
            if null_index >= 0:
                message_text = message_text[:null_index]

            result_data = {
                'timestamp': timestamp,
                'flags': flags,
                'txt_type': txt_type,
                'attempt': attempt,
                'message': message_text
            }

            if sender_pubkey_prefix:
                result_data['sender_pubkey_prefix'] = sender_pubkey_prefix

            return DecryptionResult(
                success=True,
                data=result_data
            )
        except Exception as error:
            error_msg = str(error) if isinstance(error, Exception) else 'Decryption failed'
            return DecryptionResult(success=False, error=error_msg)

    @staticmethod
    def decrypt_response_payload(
        ciphertext: str,
        cipher_mac: str,
        shared_secret: bytes
    ) -> DecryptionResult:
        """
        Decrypt Response payload using MeshCore algorithm:
        - HMAC-SHA256 verification with 2-byte MAC
        - AES-128 ECB decryption

        Args:
            ciphertext: Encrypted data (hex string)
            cipher_mac: MAC for verification (2 bytes, hex string)
            shared_secret: 32-byte ECDH shared secret (bytes)

        Returns:
            DecryptionResult with decrypted data (tag, content)
        """
        try:
            if shared_secret is None or len(shared_secret) < 32:
                return DecryptionResult(success=False, error='Invalid shared secret')

            mac_bytes = hex_to_bytes(cipher_mac)
            ciphertext_bytes = hex_to_bytes(ciphertext)

            # Step 1: Verify HMAC-SHA256 using full 32-byte shared secret
            h = hmac.new(shared_secret, ciphertext_bytes, hashlib.sha256)
            calculated_mac_bytes = h.digest()
            calculated_mac_first2 = calculated_mac_bytes[:2]

            if calculated_mac_first2[0] != mac_bytes[0] or calculated_mac_first2[1] != mac_bytes[1]:
                return DecryptionResult(success=False, error='MAC verification failed')

            # Step 2: Decrypt using AES-128 ECB with first 16 bytes of shared secret
            aes_key = shared_secret[:16]

            cipher = AES.new(aes_key, AES.MODE_ECB)
            decrypted_bytes = cipher.decrypt(ciphertext_bytes)

            if not decrypted_bytes or len(decrypted_bytes) < 4:
                return DecryptionResult(success=False, error='Decrypted content too short')

            # Parse MeshCore response format: tag(4) + content(variable)
            tag = (
                decrypted_bytes[0] |
                (decrypted_bytes[1] << 8) |
                (decrypted_bytes[2] << 16) |
                (decrypted_bytes[3] << 24)
            )

            content = decrypted_bytes[4:]

            return DecryptionResult(
                success=True,
                data={
                    'tag': tag,
                    'content': content
                }
            )
        except Exception as error:
            error_msg = str(error) if isinstance(error, Exception) else 'Decryption failed'
            return DecryptionResult(success=False, error=error_msg)

    @staticmethod
    def decrypt_anon_request_payload(
        ciphertext: str,
        cipher_mac: str,
        shared_secret: bytes
    ) -> DecryptionResult:
        """
        Decrypt Anonymous Request payload using MeshCore algorithm:
        - HMAC-SHA256 verification with 2-byte MAC
        - AES-128 ECB decryption

        Args:
            ciphertext: Encrypted data (hex string)
            cipher_mac: MAC for verification (2 bytes, hex string)
            shared_secret: 32-byte ECDH shared secret (bytes)

        Returns:
            DecryptionResult with decrypted data (timestamp, request_type, request_data, or room server login fields)
        """
        try:
            if shared_secret is None or len(shared_secret) < 32:
                return DecryptionResult(success=False, error='Invalid shared secret')

            mac_bytes = hex_to_bytes(cipher_mac)
            ciphertext_bytes = hex_to_bytes(ciphertext)

            # Step 1: Verify HMAC-SHA256 using full 32-byte shared secret
            h = hmac.new(shared_secret, ciphertext_bytes, hashlib.sha256)
            calculated_mac_bytes = h.digest()
            calculated_mac_first2 = calculated_mac_bytes[:2]

            if calculated_mac_first2[0] != mac_bytes[0] or calculated_mac_first2[1] != mac_bytes[1]:
                return DecryptionResult(success=False, error='MAC verification failed')

            # Step 2: Decrypt using AES-128 ECB with first 16 bytes of shared secret
            aes_key = shared_secret[:16]

            cipher = AES.new(aes_key, AES.MODE_ECB)
            decrypted_bytes = cipher.decrypt(ciphertext_bytes)

            if not decrypted_bytes or len(decrypted_bytes) < 4:
                return DecryptionResult(success=False, error='Decrypted content too short')

            # Parse MeshCore anon request format: timestamp(4) + [sync_timestamp(4) for room server] + password or request_data
            timestamp = (
                decrypted_bytes[0] |
                (decrypted_bytes[1] << 8) |
                (decrypted_bytes[2] << 16) |
                (decrypted_bytes[3] << 24)
            )

            # Check if this is a room server login (has sync_timestamp)
            # Room server: timestamp(4) + sync_timestamp(4) + password
            # Repeater/Sensor: timestamp(4) + password
            # Regular request: timestamp(4) + req_type(1) + req_data
            result_data = {
                'timestamp': timestamp
            }

            if len(decrypted_bytes) >= 8:
                # Could be room server login with sync_timestamp
                sync_timestamp = (
                    decrypted_bytes[4] |
                    (decrypted_bytes[5] << 8) |
                    (decrypted_bytes[6] << 16) |
                    (decrypted_bytes[7] << 24)
                )

                # Check if bytes 4-7 look like a valid timestamp (reasonable Unix timestamp)
                # If sync_timestamp is 0 or very small, it might actually be the start of a password
                # Room server sync_timestamp should be a reasonable timestamp (e.g., > 1000000000)
                is_likely_sync_timestamp = (sync_timestamp > 1000000000)

                if is_likely_sync_timestamp:
                    # Room server login: timestamp(4) + sync_timestamp(4) + password
                    result_data['sync_timestamp'] = sync_timestamp
                    # Try to decode password (null-terminated string)
                    password_bytes = decrypted_bytes[8:]
                    try:
                        password = password_bytes.decode('utf-8')
                        null_index = password.find('\0')
                        if null_index >= 0:
                            password = password[:null_index]
                        result_data['password'] = password
                        result_data['type'] = 'room_server_login'
                    except UnicodeDecodeError:
                        # Might be regular request format
                        if len(decrypted_bytes) >= 5:
                            request_type = decrypted_bytes[4]
                            request_data = decrypted_bytes[5:]
                            result_data['request_type'] = request_type
                            result_data['request_data'] = request_data
                            result_data['type'] = 'request'
                else:
                    # sync_timestamp is 0 or very small - could be repeater/sensor login OR regular request
                    # Check if byte 4 is a valid request type first (0x01-0x06)
                    if len(decrypted_bytes) >= 5:
                        request_type_byte = decrypted_bytes[4]
                        is_valid_request_type = (0x01 <= request_type_byte <= 0x06)

                        if is_valid_request_type:
                            # Regular request: timestamp(4) + req_type(1) + req_data
                            request_type = request_type_byte
                            request_data = decrypted_bytes[5:]
                            result_data['request_type'] = request_type
                            result_data['request_data'] = request_data
                            result_data['type'] = 'request'
                        else:
                            # Not a valid request type - likely repeater/sensor login
                            # Repeater/Sensor login: timestamp(4) + password(null-terminated string)
                            # Password starts at byte 4
                            password_bytes = decrypted_bytes[4:]
                            try:
                                password = password_bytes.decode('utf-8')
                                null_index = password.find('\0')
                                if null_index >= 0:
                                    password = password[:null_index]
                                result_data['password'] = password
                                result_data['type'] = 'repeater_sensor_login'
                            except UnicodeDecodeError:
                                # If it's not valid UTF-8, treat as unknown
                                result_data['raw'] = bytes_to_hex(decrypted_bytes[4:])
                                result_data['type'] = 'unknown'
                    else:
                        # Too short - can't determine
                        result_data['raw'] = bytes_to_hex(decrypted_bytes)
                        result_data['type'] = 'unknown'
            elif len(decrypted_bytes) >= 5:
                # Could be regular request format or repeater/sensor login
                # Check if byte 4 is a valid request type (0x01-0x06)
                request_type_byte = decrypted_bytes[4]
                is_valid_request_type = (0x01 <= request_type_byte <= 0x06)

                if is_valid_request_type:
                    # Regular request format: timestamp(4) + req_type(1) + req_data
                    request_type = request_type_byte
                    request_data = decrypted_bytes[5:]
                    result_data['request_type'] = request_type
                    result_data['request_data'] = request_data
                    result_data['type'] = 'request'
                else:
                    # Repeater/Sensor login: timestamp(4) + password(null-terminated string)
                    # Byte 4 is the start of the password string
                    password_bytes = decrypted_bytes[4:]
                    try:
                        password = password_bytes.decode('utf-8')
                        null_index = password.find('\0')
                        if null_index >= 0:
                            password = password[:null_index]
                        result_data['password'] = password
                        result_data['type'] = 'repeater_sensor_login'
                    except UnicodeDecodeError:
                        # If it's not valid UTF-8, might still be a request with invalid type
                        # or corrupted data - try as request anyway
                        result_data['request_type'] = request_type_byte
                        result_data['request_data'] = decrypted_bytes[5:]
                        result_data['type'] = 'request'
            else:
                # Too short - can't determine type
                result_data['raw'] = bytes_to_hex(decrypted_bytes)
                result_data['type'] = 'unknown'

            return DecryptionResult(
                success=True,
                data=result_data
            )
        except Exception as error:
            error_msg = str(error) if isinstance(error, Exception) else 'Decryption failed'
            return DecryptionResult(success=False, error=error_msg)

    @staticmethod
    def decrypt_path_payload(
        ciphertext: str,
        cipher_mac: str,
        shared_secret: bytes
    ) -> DecryptionResult:
        """
        Decrypt Path payload using MeshCore algorithm:
        - HMAC-SHA256 verification with 2-byte MAC
        - AES-128 ECB decryption

        Args:
            ciphertext: Encrypted data (hex string)
            cipher_mac: MAC for verification (2 bytes, hex string)
            shared_secret: 32-byte ECDH shared secret (bytes)

        Returns:
            DecryptionResult with decrypted data (path_len, path, extra_type, extra)
        """
        try:
            if shared_secret is None or len(shared_secret) < 32:
                return DecryptionResult(success=False, error='Invalid shared secret')

            mac_bytes = hex_to_bytes(cipher_mac)
            ciphertext_bytes = hex_to_bytes(ciphertext)

            # Step 1: Verify HMAC-SHA256 using full 32-byte shared secret
            h = hmac.new(shared_secret, ciphertext_bytes, hashlib.sha256)
            calculated_mac_bytes = h.digest()
            calculated_mac_first2 = calculated_mac_bytes[:2]

            if calculated_mac_first2[0] != mac_bytes[0] or calculated_mac_first2[1] != mac_bytes[1]:
                return DecryptionResult(success=False, error='MAC verification failed')

            # Step 2: Decrypt using AES-128 ECB with first 16 bytes of shared secret
            aes_key = shared_secret[:16]

            cipher = AES.new(aes_key, AES.MODE_ECB)
            decrypted_bytes = cipher.decrypt(ciphertext_bytes)

            if not decrypted_bytes or len(decrypted_bytes) < 2:
                return DecryptionResult(success=False, error='Decrypted content too short')

            # Parse MeshCore path format: path_len(1) + path(path_len) + extra_type(1) + extra(variable)
            path_len = decrypted_bytes[0]

            if len(decrypted_bytes) < 1 + path_len + 1:
                return DecryptionResult(success=False, error='Decrypted content too short for path structure')

            path = decrypted_bytes[1:1 + path_len]
            extra_type = decrypted_bytes[1 + path_len]
            extra = decrypted_bytes[2 + path_len:] if len(decrypted_bytes) > 2 + path_len else b''

            return DecryptionResult(
                success=True,
                data={
                    'path_len': path_len,
                    'path': path,
                    'extra_type': extra_type,
                    'extra': extra
                }
            )
        except Exception as error:
            error_msg = str(error) if isinstance(error, Exception) else 'Decryption failed'
            return DecryptionResult(success=False, error=error_msg)

    @staticmethod
    def decrypt_group_data_payload(
        ciphertext: str,
        cipher_mac: str,
        channel_key: str
    ) -> DecryptionResult:
        """
        Decrypt GroupData payload using MeshCore algorithm:
        - HMAC-SHA256 verification with 2-byte MAC
        - AES-128 ECB decryption
        Uses channel shared key (not ECDH-derived secret)

        Args:
            ciphertext: Encrypted data (hex string)
            cipher_mac: MAC for verification (2 bytes, hex string)
            channel_key: Channel shared key (hex string)

        Returns:
            DecryptionResult with decrypted data (timestamp, flags, data)
        """
        try:
            # Convert hex strings to byte arrays
            channel_key_16 = hex_to_bytes(channel_key)
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
            key_bytes = hex_to_bytes(channel_key)

            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted_bytes = cipher.decrypt(ciphertext_bytes)

            if not decrypted_bytes or len(decrypted_bytes) < 5:
                return DecryptionResult(success=False, error='Decrypted content too short')

            # Parse MeshCore format: timestamp(4) + flags(1) + data blob
            timestamp = (
                decrypted_bytes[0] |
                (decrypted_bytes[1] << 8) |
                (decrypted_bytes[2] << 16) |
                (decrypted_bytes[3] << 24)
            )

            flags = decrypted_bytes[4]
            data_blob = decrypted_bytes[5:]

            return DecryptionResult(
                success=True,
                data={
                    'timestamp': timestamp,
                    'flags': flags,
                    'data': data_blob
                }
            )
        except Exception as error:
            error_msg = str(error) if isinstance(error, Exception) else 'Decryption failed'
            return DecryptionResult(success=False, error=error_msg)
