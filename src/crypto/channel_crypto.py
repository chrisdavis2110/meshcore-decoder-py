"""
Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
MIT License

Channel encryption/decryption using MeshCore algorithm
"""

import hmac
import hashlib
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from src.types.crypto import DecryptionResult
from src.utils.hex import hex_to_bytes, bytes_to_hex


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
