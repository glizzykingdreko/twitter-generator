import base64
import hashlib
import json
import os
import re
import time
from typing import Dict, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..exceptions import InvalidGuestIdError

class XPForwardedForGenerator:
    """
    Generator and decoder for X-XP-Forwarded-For authentication tokens.
    
    This class provides methods to generate and decode Twitter/X's
    x-xp-forwarded-for tokens using AES-256-GCM encryption.
    """
    
    # AES-256-GCM base encryption key (extracted from WASM binary)
    AES_KEY_HEX = '0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05'
    
    # GCM parameters
    IV_LENGTH = 12      # 12 bytes (96 bits) - standard for GCM
    AUTH_TAG_LENGTH = 16  # 16 bytes (128 bits)
    
    # Token validity duration
    TOKEN_VALIDITY_MS = 60 * 60 * 1000  # 1 hour
    
    def __init__(self, guest_id: Optional[str] = None):
        """
        Initialize the generator.
        
        Args:
            guest_id: Optional guest ID from cookie for key derivation
        """
        self.guest_id = guest_id
        self._base_key = bytes.fromhex(self.AES_KEY_HEX)
    
    def generate(self, env: Dict) -> Dict:
        """
        Generate x-xp-forwarded-for token.
        
        Args:
            env: Dictionary with keys:
                - userAgent: Browser user agent
                - hasBeenActive: User activation state
                - webdriver: Webdriver detection flag
                - guestId: Twitter guest_id cookie value (optional, for key derivation)
        
        Returns:
            Dictionary with 'str' (base64 token) and 'expiryTimeMillis'
        """
        # Build client signals
        signals = self._build_client_signals(env)
        
        # Serialize to JSON
        json_data = json.dumps(signals, separators=(',', ':'))
        
        # Use derived key if guestId is provided, otherwise use default key
        key = None
        guest_id = env.get('guestId') or self.guest_id
        if guest_id:
            key = self._derive_key_from_guest_id(guest_id)
        
        # Encrypt
        encrypted = self._encrypt(json_data, key)
        
        # Encode as base64
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decode(self, token: str, key: Optional[bytes] = None) -> Dict:
        """
        Decode and decrypt a token.
        
        Args:
            token: Base64-encoded or hex-encoded token
            key: 32-byte encryption key (defaults to base key)
        
        Returns:
            Decoded client signals dictionary
        """
        # Check if hex or base64
        if re.match(r'^[0-9a-fA-F]+$', token) and len(token) % 2 == 0:
            # Hex encoded
            ciphertext = bytes.fromhex(token)
        else:
            # Base64 encoded
            ciphertext = base64.b64decode(token)
        
        # Decrypt
        json_data = self._decrypt(ciphertext, key)
        
        # Parse JSON
        return json.loads(json_data)
    
    def decode_with_key(self, token: str, key_hex: str) -> Dict:
        """
        Decrypt with a custom key.
        
        Args:
            token: Base64 or hex encoded token
            key_hex: 64-character hex key
        
        Returns:
            Decoded client signals dictionary
        """
        key = bytes.fromhex(key_hex)
        return self.decode(token, key)
    
    def decode_with_guest_id(self, token: str, guest_id: str) -> Dict:
        """
        Decrypt token using guest_id for key derivation.
        This is the actual method used by Twitter/X.
        
        Args:
            token: Base64 or hex encoded token
            guest_id: Guest ID from cookie
        
        Returns:
            Decoded client signals dictionary
        """
        derived_key = self._derive_key_hex_from_guest_id(guest_id)
        return self.decode_with_key(token, derived_key)
    
    def _derive_key_from_guest_id(self, guest_id: str) -> bytes:
        """
        Derive encryption key from guest_id.
        Formula: SHA256(baseKey + guestId)
        
        Args:
            guest_id: Guest ID from cookie (e.g., "v1%3A176824413470818950")
        
        Returns:
            32-byte derived key
        """
        combined = self.AES_KEY_HEX + guest_id
        return hashlib.sha256(combined.encode('utf-8')).digest()
    
    def _derive_key_hex_from_guest_id(self, guest_id: str) -> str:
        """
        Derive encryption key from guest_id and return as hex string.
        
        Args:
            guest_id: Guest ID from cookie
        
        Returns:
            64-character hex key
        """
        return self._derive_key_from_guest_id(guest_id).hex()
    
    def _encrypt(self, plaintext: Union[str, bytes], key: Optional[bytes] = None) -> bytes:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            key: 32-byte encryption key (defaults to base key)
        
        Returns:
            IV + ciphertext + auth tag
        """
        if key is None:
            key = self._base_key
        
        # Convert string to bytes if needed
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate random 12-byte IV
        iv = os.urandom(self.IV_LENGTH)
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Encrypt (GCM automatically appends auth tag)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        
        # Combine: IV + ciphertext (ciphertext includes auth tag)
        return iv + ciphertext
    
    def _decrypt(self, ciphertext: bytes, key: Optional[bytes] = None) -> str:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            ciphertext: IV + encrypted data + auth tag
            key: 32-byte encryption key (defaults to base key)
        
        Returns:
            Decrypted plaintext as string
        """
        if key is None:
            key = self._base_key
        
        # Extract components
        iv = ciphertext[:self.IV_LENGTH]
        encrypted = ciphertext[self.IV_LENGTH:]
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Decrypt (GCM automatically verifies auth tag)
        try:
            plaintext = aesgcm.decrypt(iv, encrypted, None)
        except InvalidTag:
            raise InvalidGuestIdError("Wrong guest ID provided")
        
        return plaintext.decode('utf-8')
    
    def _build_client_signals(self, env: Dict) -> Dict:
        """
        Build client signals from browser environment.
        
        Args:
            env: Dictionary with keys:
                - userAgent: Browser user agent
                - hasBeenActive: User activation state
                - webdriver: Webdriver detection flag
                - guestId: Twitter guest_id cookie value (optional, for key derivation)
        
        Returns:
            ClientSignals dictionary
        """
        return {
            'navigator_properties': {
                'user_agent': env.get('userAgent', 'Mozilla/5.0'),
                'has_been_active': env.get('hasBeenActive', False),
                'webdriver': env.get('webdriver', False),
                'guest_id': env.get('guestId', '')
            },
            'created_at': int(time.time() * 1000)
        }