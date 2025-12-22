"""BE3600 Router Encryption Module.

Implements the sign+data encryption scheme used by TP-Link BE3600 routers
with firmware version 1.1.0+ (2025).

The encryption flow:
1. Get RSA public key and sequence from /login?form=auth
2. Hash password: SHA256("admin" + password)
3. Generate random AES-256 key and IV
4. Encrypt password with AES-CBC
5. Create signature with AES key info and hash
6. Encrypt signature chunks with RSA
7. Send { sign: <rsa_encrypted_sig>, data: <aes_encrypted_password> }
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from binascii import b2a_hex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# Configure module logger
logger = logging.getLogger(__name__)


class CryptoError(Exception):
    """Base exception for cryptographic errors."""

    pass


class KeyNotSetError(CryptoError):
    """Raised when attempting crypto operations without proper key setup."""

    pass


class AuthenticationError(CryptoError):
    """Raised when authentication fails."""

    pass


@dataclass
class RSAKeyPair:
    """RSA public key components."""

    n: str  # Modulus (hex string)
    e: str  # Exponent (hex string)

    @property
    def key_length(self) -> int:
        """Get the key length in hex characters."""
        return len(self.n)


@dataclass
class AESKeyPair:
    """AES key and IV pair."""

    key: str  # 16-character key
    iv: str  # 16-character IV

    def formatted(self) -> str:
        """Get key in router format: k=<key>&i=<iv>"""
        return f"k={self.key}&i={self.iv}"


class BE3600Crypto:
    """Encryption handler for BE3600 routers.

    This class implements the encryption scheme used by TP-Link BE3600 routers.
    It handles RSA encryption for signatures, AES encryption for payloads,
    and password hashing.

    Attributes:
        SIGNATURE_CHUNK_SIZE: Maximum size of each RSA-encrypted chunk.
    """

    SIGNATURE_CHUNK_SIZE = 53

    def __init__(self) -> None:
        """Initialize the crypto handler with empty keys."""
        # RSA key for signature (from /login?form=auth)
        self._rsa_key: Optional[RSAKeyPair] = None
        # RSA key for password (from /login?form=keys)
        self._pwd_rsa_key: Optional[RSAKeyPair] = None
        self._sequence: Optional[int] = None
        self._aes_key: Optional[AESKeyPair] = None
        self._password_hash: Optional[str] = None

    @property
    def rsa_n(self) -> Optional[str]:
        """Get RSA modulus (for backward compatibility)."""
        return self._rsa_key.n if self._rsa_key else None

    @property
    def rsa_e(self) -> Optional[str]:
        """Get RSA exponent (for backward compatibility)."""
        return self._rsa_key.e if self._rsa_key else None

    @property
    def pwd_rsa_n(self) -> Optional[str]:
        """Get password RSA modulus (for backward compatibility)."""
        return self._pwd_rsa_key.n if self._pwd_rsa_key else None

    @property
    def pwd_rsa_e(self) -> Optional[str]:
        """Get password RSA exponent (for backward compatibility)."""
        return self._pwd_rsa_key.e if self._pwd_rsa_key else None

    @property
    def sequence(self) -> Optional[int]:
        """Get the current sequence number."""
        return self._sequence

    @property
    def aes_key(self) -> Optional[str]:
        """Get AES key (for backward compatibility)."""
        return self._aes_key.key if self._aes_key else None

    @property
    def aes_iv(self) -> Optional[str]:
        """Get AES IV (for backward compatibility)."""
        return self._aes_key.iv if self._aes_key else None

    @property
    def hash(self) -> Optional[str]:
        """Get password hash (for backward compatibility)."""
        return self._password_hash

    def set_rsa_key(self, n: str, e: str) -> None:
        """Set RSA public key for signature encryption.

        Args:
            n: RSA modulus as hex string.
            e: RSA exponent as hex string.
        """
        self._rsa_key = RSAKeyPair(n=n, e=e)
        logger.debug("Set RSA signature key (length: %d)", len(n))

    def set_password_rsa_key(self, n: str, e: str) -> None:
        """Set RSA public key for password encryption.

        Args:
            n: RSA modulus as hex string.
            e: RSA exponent as hex string.
        """
        self._pwd_rsa_key = RSAKeyPair(n=n, e=e)
        logger.debug("Set RSA password key (length: %d)", len(n))

    def set_sequence(self, seq: int) -> None:
        """Set the sequence number from the router.

        Args:
            seq: Sequence number obtained from authentication endpoint.
        """
        self._sequence = seq
        logger.debug("Set sequence number")

    def generate_aes_key(self, use_hex: bool = True) -> None:
        """Generate random AES key and IV.

        Args:
            use_hex: If True, use 16-char hex strings (library style).
                     If False, use 16-digit numeric strings (original JS style).
        """
        if use_hex:
            # Library style: 8 random bytes -> 16 hex chars
            key = b2a_hex(Random.get_random_bytes(8)).decode()
            iv = b2a_hex(Random.get_random_bytes(8)).decode()
        else:
            # Original JS style: 16 random digits
            import random
            key = ''.join([str(random.randint(0, 9)) for _ in range(16)])
            iv = ''.join([str(random.randint(0, 9)) for _ in range(16)])

        self._aes_key = AESKeyPair(key=key, iv=iv)
        logger.debug("Generated new AES key pair")

    def get_aes_formatted_key(self) -> str:
        """Get AES key in router format: k=<key>&i=<iv>

        Returns:
            Formatted key string or empty string if not set.
        """
        if not self._aes_key:
            return ""
        return self._aes_key.formatted()

    def hash_password(
        self,
        password: str,
        username: str = "admin",
        use_md5: bool = False
    ) -> str:
        """Hash password with username prefix.

        Args:
            password: The password to hash.
            username: The username (default: admin).
            use_md5: Use MD5 instead of SHA256 (for older firmware).

        Returns:
            The hexadecimal hash string.
        """
        combined = f"{username}{password}"
        if use_md5:
            self._password_hash = hashlib.md5(combined.encode()).hexdigest()
        else:
            self._password_hash = hashlib.sha256(combined.encode()).hexdigest()
        logger.debug("Generated password hash (algorithm: %s)",
                     "MD5" if use_md5 else "SHA256")
        return self._password_hash

    def aes_encrypt(self, data: str) -> str:
        """Encrypt data with AES-CBC and return base64.

        Args:
            data: The plaintext data to encrypt.

        Returns:
            Base64-encoded ciphertext.

        Raises:
            KeyNotSetError: If AES key has not been generated.
        """
        if not self._aes_key:
            raise KeyNotSetError("AES key not generated - call generate_aes_key() first")

        key_bytes = self._aes_key.key.encode('utf-8')
        iv_bytes = self._aes_key.iv.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        padded = pad(data.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode()

    def aes_decrypt(self, data: str) -> str:
        """Decrypt base64 AES-CBC data.

        Args:
            data: Base64-encoded ciphertext.

        Returns:
            Decrypted plaintext.

        Raises:
            KeyNotSetError: If AES key has not been generated.
        """
        if not self._aes_key:
            raise KeyNotSetError("AES key not generated - call generate_aes_key() first")

        key_bytes = self._aes_key.key.encode('utf-8')
        iv_bytes = self._aes_key.iv.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        encrypted = base64.b64decode(data)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode()

    def rsa_encrypt_chunk(self, data: str) -> str:
        """Encrypt a chunk of data with RSA using PKCS1v1.5.

        Args:
            data: The data chunk to encrypt.

        Returns:
            Hex-encoded ciphertext, zero-padded to key length.

        Raises:
            KeyNotSetError: If RSA key has not been set.
        """
        if not self._rsa_key:
            raise KeyNotSetError("RSA key not set - call set_rsa_key() first")

        # Convert hex strings to integers
        n = int(self._rsa_key.n, 16)
        e = int(self._rsa_key.e, 16)

        # Create RSA key and encrypt
        rsa_key = RSA.construct((n, e))
        cipher = PKCS1_v1_5.new(rsa_key)
        encrypted = cipher.encrypt(data.encode())

        # Pad result to key length
        result = encrypted.hex()
        key_len = self._rsa_key.key_length
        if len(result) < key_len:
            result = result.zfill(key_len)

        return result

    def generate_signature(
        self,
        data_length: int,
        include_aes_key: bool = True
    ) -> str:
        """Generate the encrypted signature.

        Args:
            data_length: Length of the encrypted data.
            include_aes_key: Whether to include AES key in signature (first login).

        Returns:
            RSA-encrypted signature string.

        Raises:
            KeyNotSetError: If required keys/hash not set.
        """
        if not self._password_hash:
            raise KeyNotSetError("Password hash not set - call hash_password() first")
        if self._sequence is None:
            raise KeyNotSetError("Sequence not set - call set_sequence() first")

        # Build signature payload
        sig_parts: List[str] = []
        if include_aes_key:
            sig_parts.append(self.get_aes_formatted_key())
        sig_parts.append(f"h={self._password_hash}")
        sig_parts.append(f"s={self._sequence + data_length}")

        signature = "&".join(sig_parts)
        logger.debug("Generated signature payload (length: %d)", len(signature))

        # Encrypt in chunks
        encrypted_sig = ""
        for i in range(0, len(signature), self.SIGNATURE_CHUNK_SIZE):
            chunk = signature[i:i + self.SIGNATURE_CHUNK_SIZE]
            encrypted_sig += self.rsa_encrypt_chunk(chunk)

        return encrypted_sig

    def rsa_encrypt_password(self, password: str, use_oaep: bool = False) -> str:
        """RSA encrypt the plain password for login.

        Uses the password-specific RSA key from /login?form=keys if available,
        otherwise falls back to the auth RSA key.

        Args:
            password: Plain text password.
            use_oaep: Use OAEP padding (True) or PKCS1v1.5 (False).

        Returns:
            Hex string of encrypted password (padded to key length).

        Raises:
            KeyNotSetError: If no RSA key is available.
        """
        # Use password-specific key if available
        rsa_key = self._pwd_rsa_key or self._rsa_key
        if not rsa_key:
            raise KeyNotSetError("RSA key not set")

        # Convert hex strings to integers
        n = int(rsa_key.n, 16)
        e = int(rsa_key.e, 16)

        # Create RSA key
        key = RSA.construct((n, e))

        if use_oaep:
            cipher = PKCS1_OAEP.new(key)
        else:
            cipher = PKCS1_v1_5.new(key)

        # Encrypt
        encrypted = cipher.encrypt(password.encode())

        # Pad to key length (modulus length in hex)
        result = encrypted.hex()
        key_len = rsa_key.key_length
        if len(result) < key_len:
            result = result.zfill(key_len)

        return result

    def serialize_payload(self, payload: Dict[str, Any]) -> str:
        """Serialize payload as URL-encoded key-value pairs.

        This matches the router's serialize() JavaScript function.

        Args:
            payload: Dictionary to serialize.

        Returns:
            URL-encoded string.
        """
        parts: List[str] = []
        for key, value in payload.items():
            if value is None:
                continue
            if isinstance(value, bool):
                value = "true" if value else "false"
            elif isinstance(value, (dict, list)):
                value = json.dumps(value)
            parts.append(f"{quote(str(key))}={quote(str(value))}")
        return "&".join(parts)

    def encrypt_for_login(self, password: str) -> Tuple[str, str]:
        """Encrypt password for login request.

        The login flow:
        1. RSA encrypt the plain password
        2. Create URL-encoded payload: password=<rsa_encrypted>&operation=login&confirm=true
        3. AES encrypt the serialized payload
        4. Generate signature with AES key info

        Args:
            password: Plain text password.

        Returns:
            Tuple of (sign, data) for the login request.

        Raises:
            KeyNotSetError: If required keys not set.
        """
        # Generate fresh AES key
        self.generate_aes_key()
        logger.debug("Generated AES key for login")

        # Hash the password (used in signature)
        self.hash_password(password)

        # RSA encrypt the password
        rsa_encrypted_password = self.rsa_encrypt_password(password)
        logger.debug("RSA encrypted password (length: %d)", len(rsa_encrypted_password))

        # Create payload - serialized as URL-encoded format
        payload = {
            "password": rsa_encrypted_password,
            "operation": "login",
            "confirm": True
        }
        serialized = self.serialize_payload(payload)
        logger.debug("Serialized payload (length: %d)", len(serialized))

        # AES encrypt the serialized payload
        encrypted_data = self.aes_encrypt(serialized)

        # Generate signature (include AES key for initial login)
        sign = self.generate_signature(len(encrypted_data), include_aes_key=True)

        return sign, encrypted_data


class BE3600Client:
    """HTTP client for BE3600 router with encryption support.

    This client handles the full authentication flow including:
    - Fetching RSA keys from the router
    - Encrypting credentials
    - Managing session tokens

    Attributes:
        host: Router IP address or hostname.
        username: Router admin username.
        stok: Session token (set after login).
        sysauth: System auth cookie (set after login).

    Example:
        >>> client = BE3600Client('192.168.0.1', 'my_password')
        >>> if client.login():
        ...     status = client.get_status()
        ...     print(status)
    """

    DEFAULT_TIMEOUT = 15.0

    def __init__(
        self,
        host: str,
        password: str,
        username: str = "admin",
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the BE3600 HTTP client.

        Args:
            host: Router IP address or hostname.
            password: Router admin password.
            username: Router admin username.
            timeout: HTTP request timeout in seconds.
        """
        self.host = host
        self.password = password
        self.username = username
        self.base_url = f"http://{host}"
        self._timeout = timeout
        self.crypto = BE3600Crypto()
        self.stok: Optional[str] = None
        self.sysauth: Optional[str] = None

    def _get_auth_info(self) -> Dict[str, Any]:
        """Get RSA key and sequence from router.

        Returns:
            Dictionary containing 'key' list and 'seq' number.

        Raises:
            AuthenticationError: If auth info cannot be retrieved.
        """
        url = f"{self.base_url}/cgi-bin/luci/;stok=/login?form=auth&operation=read"
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") and "data" in data:
                    return data["data"]
        raise AuthenticationError("Failed to get auth info from router")

    def _get_keys_info(self) -> Dict[str, Any]:
        """Get password RSA key from router.

        Returns:
            Dictionary containing 'password' key list.

        Raises:
            AuthenticationError: If keys info cannot be retrieved.
        """
        url = f"{self.base_url}/cgi-bin/luci/;stok=/login?form=keys&operation=read"
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") and "data" in data:
                    return data["data"]
        raise AuthenticationError("Failed to get keys info from router")

    def login(self) -> bool:
        """Authenticate with the router.

        Returns:
            True if login successful, False otherwise.
        """
        try:
            # Get RSA key and sequence for signature
            auth_info = self._get_auth_info()
            key = auth_info.get("key", [])
            seq = auth_info.get("seq")

            if len(key) != 2 or seq is None:
                raise AuthenticationError("Invalid auth info format")

            logger.debug("Got auth RSA key (length: %d)", len(key[0]))

            # Get password RSA key
            keys_info = self._get_keys_info()
            pwd_key = keys_info.get("password", [])
            if len(pwd_key) == 2:
                logger.debug("Got password RSA key (length: %d)", len(pwd_key[0]))
                self.crypto.set_password_rsa_key(pwd_key[0], pwd_key[1])

            # Set up crypto
            self.crypto.set_rsa_key(key[0], key[1])
            self.crypto.set_sequence(seq)

            # Encrypt password
            sign, data = self.crypto.encrypt_for_login(self.password)
            logger.debug("Generated encrypted credentials")

            # Send login request as form-urlencoded
            url = f"{self.base_url}/cgi-bin/luci/;stok=/login?form=login"
            form_payload = {"sign": sign, "data": data}

            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(
                    url,
                    data=form_payload,
                    headers={
                        "Accept": "application/json, text/javascript, */*; q=0.01",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Cache-Control": "no-cache",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": f"http://{self.host}",
                        "Referer": f"http://{self.host}/",
                        "X-Requested-With": "XMLHttpRequest"
                    }
                )

                logger.debug("Login response status: %d", resp.status_code)

                if resp.status_code == 200:
                    result = resp.json()

                    if result.get("success"):
                        # Response data is encrypted - decrypt it
                        resp_data = result.get("data")
                        if isinstance(resp_data, str):
                            try:
                                decrypted = self.crypto.aes_decrypt(resp_data)
                                dec_data = json.loads(decrypted)
                                self.stok = dec_data.get("stok")
                                logger.debug("Decrypted login response successfully")
                            except Exception as e:
                                logger.warning("Failed to decrypt response: %s", e)
                        elif isinstance(resp_data, dict):
                            self.stok = resp_data.get("stok")

                        # Extract sysauth from cookies
                        cookies = resp.headers.get("set-cookie", "")
                        if "sysauth=" in cookies:
                            match = re.search(r'sysauth=([^;]+)', cookies)
                            if match:
                                self.sysauth = match.group(1)

                        if self.stok or self.sysauth:
                            logger.info("Login successful")
                            return True
                    else:
                        error_code = result.get('errorcode', 'unknown')
                        logger.warning("Login failed with error code: %s", error_code)

            return False

        except AuthenticationError as e:
            logger.error("Authentication error: %s", e)
            return False
        except httpx.RequestError as e:
            logger.error("HTTP request error: %s", e)
            return False
        except Exception as e:
            logger.exception("Unexpected login error: %s", e)
            return False

    def _make_request(
        self,
        endpoint: str,
        payload: Optional[Dict[str, Any]] = None,
        method: str = "read"
    ) -> Dict[str, Any]:
        """Make an authenticated request to the router.

        Args:
            endpoint: API endpoint path.
            payload: Optional request payload.
            method: Operation method (read, write, etc.).

        Returns:
            Response data dictionary.

        Raises:
            RuntimeError: If not authenticated.
            httpx.RequestError: If request fails.
        """
        if not self.stok:
            raise RuntimeError("Not authenticated - call login() first")

        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/{endpoint}"

        # Encrypt payload if needed
        if payload:
            payload["operation"] = method

            if self.crypto.aes_key:
                encrypted = self.crypto.aes_encrypt(json.dumps(payload))
                sign = self.crypto.generate_signature(len(encrypted), include_aes_key=False)
                request_data = {"sign": sign, "data": encrypted}
            else:
                request_data = payload
        else:
            request_data = {"operation": method}

        cookies = {}
        if self.sysauth:
            cookies["sysauth"] = self.sysauth

        with httpx.Client(timeout=self._timeout, cookies=cookies) as client:
            resp = client.post(
                url,
                json=request_data,
                headers={"Content-Type": "application/json"}
            )

            if resp.status_code == 200:
                result = resp.json()
                if result.get("success") and "data" in result:
                    data = result["data"]
                    # Try to decrypt if it's a string (encrypted response)
                    if isinstance(data, str) and self.crypto.aes_key:
                        try:
                            decrypted = self.crypto.aes_decrypt(data)
                            return json.loads(decrypted)
                        except Exception:
                            pass
                    return data if isinstance(data, dict) else {"data": data}
                return result

        raise httpx.RequestError(f"Request failed: {endpoint}")

    def get_status(self) -> Dict[str, Any]:
        """Get router status.

        Returns:
            Dictionary containing router status information.
        """
        return self._make_request("admin/status?form=all")

    def get_devices(self) -> Dict[str, Any]:
        """Get connected devices.

        Returns:
            Dictionary containing device list.
        """
        return self._make_request("admin/status?form=client_list")
