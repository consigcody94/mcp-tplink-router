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

import base64
import hashlib
import os
import secrets
from typing import Optional, Tuple

from Crypto.Cipher import AES, PKCS1_v1_5, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


class BE3600Crypto:
    """Encryption handler for BE3600 routers."""

    SIGNATURE_CHUNK_SIZE = 53

    def __init__(self):
        # RSA key for signature (from /login?form=auth)
        self.rsa_n: Optional[str] = None
        self.rsa_e: Optional[str] = None
        # RSA key for password (from /login?form=keys)
        self.pwd_rsa_n: Optional[str] = None
        self.pwd_rsa_e: Optional[str] = None
        self.sequence: Optional[int] = None
        self.aes_key: Optional[bytes] = None
        self.aes_iv: Optional[bytes] = None
        self.hash: Optional[str] = None

    def set_rsa_key(self, n: str, e: str):
        """Set RSA public key for signature (hex strings)."""
        self.rsa_n = n
        self.rsa_e = e

    def set_password_rsa_key(self, n: str, e: str):
        """Set RSA public key for password encryption (hex strings)."""
        self.pwd_rsa_n = n
        self.pwd_rsa_e = e

    def set_sequence(self, seq: int):
        """Set the sequence number from the router."""
        self.sequence = seq

    def generate_aes_key(self, use_hex: bool = True):
        """Generate random AES key and IV.

        Args:
            use_hex: If True, use 16-char hex strings (library style).
                     If False, use 16-digit numeric strings (original JS style).
        """
        if use_hex:
            # Library style: 8 random bytes → 16 hex chars
            from binascii import b2a_hex
            from Crypto import Random
            self.aes_key = b2a_hex(Random.get_random_bytes(8)).decode()
            self.aes_iv = b2a_hex(Random.get_random_bytes(8)).decode()
        else:
            # Original JS style: 16 random digits
            import random
            self.aes_key = ''.join([str(random.randint(0, 9)) for _ in range(16)])
            self.aes_iv = ''.join([str(random.randint(0, 9)) for _ in range(16)])

    def get_aes_formatted_key(self) -> str:
        """Get AES key in formatted string: k=<digits>&i=<digits>"""
        if not self.aes_key or not self.aes_iv:
            return ""
        # Router uses k= and i= not key= and iv=
        return f"k={self.aes_key}&i={self.aes_iv}"

    def hash_password(self, password: str, username: str = "admin", use_md5: bool = False) -> str:
        """Hash password with username prefix.

        Args:
            password: The password to hash
            username: The username (default: admin)
            use_md5: Use MD5 instead of SHA256 (for older firmware)
        """
        combined = f"{username}{password}"
        if use_md5:
            self.hash = hashlib.md5(combined.encode()).hexdigest()
        else:
            self.hash = hashlib.sha256(combined.encode()).hexdigest()
        return self.hash

    def aes_encrypt(self, data: str) -> str:
        """Encrypt data with AES-CBC and return base64."""
        if not self.aes_key or not self.aes_iv:
            raise ValueError("AES key not generated")

        # Key and IV are UTF-8 strings (16-digit numeric strings)
        key_bytes = self.aes_key.encode('utf-8')
        iv_bytes = self.aes_iv.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        padded = pad(data.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode()

    def aes_decrypt(self, data: str) -> str:
        """Decrypt base64 AES-CBC data."""
        if not self.aes_key or not self.aes_iv:
            raise ValueError("AES key not generated")

        # Key and IV are UTF-8 strings
        key_bytes = self.aes_key.encode('utf-8')
        iv_bytes = self.aes_iv.encode('utf-8')

        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        encrypted = base64.b64decode(data)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode()

    def rsa_encrypt_chunk(self, data: str) -> str:
        """Encrypt a chunk of data with RSA using PKCS1v1.5 and return hex."""
        if not self.rsa_n or not self.rsa_e:
            raise ValueError("RSA key not set")

        # Convert hex strings to integers
        n = int(self.rsa_n, 16)
        e = int(self.rsa_e, 16)

        # Create RSA key
        rsa_key = RSA.construct((n, e))
        cipher = PKCS1_v1_5.new(rsa_key)

        # Encrypt with PKCS1v1.5
        encrypted = cipher.encrypt(data.encode())

        # Pad to key length
        key_len = len(self.rsa_n)
        result = encrypted.hex()
        if len(result) < key_len:
            result = result.zfill(key_len)

        return result

    def generate_signature(self, data_length: int, include_aes_key: bool = True) -> str:
        """Generate the encrypted signature.

        Args:
            data_length: Length of the encrypted data
            include_aes_key: Whether to include AES key in signature (first login)

        Returns:
            RSA-encrypted signature string
        """
        if not self.hash or self.sequence is None:
            raise ValueError("Hash or sequence not set")

        # Build signature payload
        sig_parts = []
        if include_aes_key:
            sig_parts.append(self.get_aes_formatted_key())
        sig_parts.append(f"h={self.hash}")
        sig_parts.append(f"s={self.sequence + data_length}")

        signature = "&".join(sig_parts)
        print(f"DEBUG: Signature before encrypt ({len(signature)} chars): {signature[:100]}...")

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
            password: Plain text password
            use_oaep: Use OAEP padding (True) or PKCS1v1.5 (False)

        Returns:
            Hex string of encrypted password (padded to key length)
        """
        # Use password-specific key if available
        rsa_n = self.pwd_rsa_n or self.rsa_n
        rsa_e = self.pwd_rsa_e or self.rsa_e

        if not rsa_n or not rsa_e:
            raise ValueError("RSA key not set")

        # Convert hex strings to integers
        n = int(rsa_n, 16)
        e = int(rsa_e, 16)

        # Create RSA key
        rsa_key = RSA.construct((n, e))

        if use_oaep:
            cipher = PKCS1_OAEP.new(rsa_key)
        else:
            cipher = PKCS1_v1_5.new(rsa_key)

        # Encrypt
        encrypted = cipher.encrypt(password.encode())

        # Pad to key length (modulus length in hex)
        key_len = len(rsa_n)
        result = encrypted.hex()
        if len(result) < key_len:
            result = result.zfill(key_len)

        return result

    def serialize_payload(self, payload: dict) -> str:
        """Serialize payload as URL-encoded key-value pairs.

        This matches the router's serialize() JavaScript function.
        """
        from urllib.parse import quote
        parts = []
        for key, value in payload.items():
            if value is None:
                continue
            if isinstance(value, bool):
                value = "true" if value else "false"
            elif isinstance(value, (dict, list)):
                import json
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
            password: Plain text password

        Returns:
            Tuple of (sign, data) for the login request
        """
        # Generate fresh AES key
        self.generate_aes_key()
        print(f"DEBUG: AES key={self.aes_key}, IV={self.aes_iv}")
        print(f"DEBUG: AES formatted: {self.get_aes_formatted_key()}")

        # Hash the password (used in signature)
        self.hash_password(password)
        print(f"DEBUG: Password hash: {self.hash}")

        # RSA encrypt the password
        rsa_encrypted_password = self.rsa_encrypt_password(password)
        print(f"DEBUG: RSA encrypted password ({len(rsa_encrypted_password)} chars): {rsa_encrypted_password[:50]}...")

        # Create payload - serialized as URL-encoded format
        payload = {
            "password": rsa_encrypted_password,
            "operation": "login",
            "confirm": True
        }
        serialized = self.serialize_payload(payload)
        print(f"DEBUG: Serialized payload ({len(serialized)} chars): {serialized[:100]}...")

        # AES encrypt the serialized payload
        encrypted_data = self.aes_encrypt(serialized)

        # Generate signature (include AES key for initial login)
        sign = self.generate_signature(len(encrypted_data), include_aes_key=True)

        return sign, encrypted_data


class BE3600Client:
    """HTTP client for BE3600 router with encryption support."""

    def __init__(self, host: str, password: str, username: str = "admin"):
        self.host = host
        self.password = password
        self.username = username
        self.base_url = f"http://{host}"
        self.crypto = BE3600Crypto()
        self.stok: Optional[str] = None
        self.sysauth: Optional[str] = None

    def _get_auth_info(self) -> dict:
        """Get RSA key and sequence from router."""
        import httpx

        url = f"{self.base_url}/cgi-bin/luci/;stok=/login?form=auth&operation=read"
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") and "data" in data:
                    return data["data"]
        raise Exception("Failed to get auth info from router")

    def _get_keys_info(self) -> dict:
        """Get password RSA key from router."""
        import httpx

        url = f"{self.base_url}/cgi-bin/luci/;stok=/login?form=keys&operation=read"
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") and "data" in data:
                    return data["data"]
        raise Exception("Failed to get keys info from router")

    def login(self) -> bool:
        """Authenticate with the router.

        Returns:
            True if login successful, False otherwise
        """
        import httpx
        import json
        import traceback

        try:
            # Get RSA key and sequence for signature
            auth_info = self._get_auth_info()
            key = auth_info.get("key", [])
            seq = auth_info.get("seq")

            if len(key) != 2 or seq is None:
                raise Exception("Invalid auth info format")

            print(f"DEBUG: Got auth RSA key (n={key[0][:20]}..., e={key[1]})")
            print(f"DEBUG: Got sequence: {seq}")

            # Get password RSA key
            keys_info = self._get_keys_info()
            pwd_key = keys_info.get("password", [])
            if len(pwd_key) == 2:
                print(f"DEBUG: Got password RSA key (n={pwd_key[0][:20]}..., e={pwd_key[1]})")
                self.crypto.set_password_rsa_key(pwd_key[0], pwd_key[1])

            # Set up crypto
            self.crypto.set_rsa_key(key[0], key[1])
            self.crypto.set_sequence(seq)

            # Encrypt password
            sign, data = self.crypto.encrypt_for_login(self.password)
            print(f"DEBUG: Generated sign ({len(sign)} chars): {sign[:50]}...")
            print(f"DEBUG: Generated data ({len(data)} chars): {data[:50]}...")

            # Send login request as form-urlencoded (not JSON!)
            url = f"{self.base_url}/cgi-bin/luci/;stok=/login?form=login"
            # Use httpx's built-in form encoding
            form_payload = {
                "sign": sign,
                "data": data
            }
            print(f"DEBUG: Sending to URL: {url}")
            print(f"DEBUG: Form data keys: sign={len(sign)} chars, data={len(data)} chars")

            with httpx.Client(timeout=15.0) as client:
                resp = client.post(
                    url,
                    data=form_payload,  # httpx encodes as form-urlencoded
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

                print(f"DEBUG: Response status: {resp.status_code}")
                print(f"DEBUG: Response body: {resp.text[:500]}")
                print(f"DEBUG: Response cookies: {dict(resp.cookies)}")
                print(f"DEBUG: Response headers set-cookie: {resp.headers.get('set-cookie', 'none')}")

                if resp.status_code == 200:
                    result = resp.json()
                    print(f"DEBUG: Response JSON: {json.dumps(result)[:200]}...")

                    if result.get("success"):
                        # Response data is encrypted - decrypt it
                        resp_data = result.get("data")
                        if isinstance(resp_data, str):
                            try:
                                decrypted = self.crypto.aes_decrypt(resp_data)
                                print(f"DEBUG: Decrypted response: {decrypted}")
                                dec_data = json.loads(decrypted)
                                self.stok = dec_data.get("stok")
                            except Exception as e:
                                print(f"DEBUG: Decrypt error: {e}")
                        elif isinstance(resp_data, dict):
                            self.stok = resp_data.get("stok")

                        # Extract sysauth from cookies
                        cookies = resp.headers.get("set-cookie", "")
                        if "sysauth=" in cookies:
                            import re
                            match = re.search(r'sysauth=([^;]+)', cookies)
                            if match:
                                self.sysauth = match.group(1)

                        print(f"DEBUG: STOK: {self.stok}")
                        print(f"DEBUG: Sysauth: {self.sysauth}")
                        return self.stok is not None or self.sysauth is not None
                    else:
                        print(f"DEBUG: Login failed - success=false")
                        print(f"DEBUG: Error: {result.get('errorcode', 'unknown')}")

            return False

        except Exception as e:
            print(f"Login error: {e}")
            traceback.print_exc()
            return False

    def _make_request(self, endpoint: str, payload: dict = None, method: str = "read") -> dict:
        """Make an authenticated request to the router."""
        import httpx

        if not self.stok:
            raise Exception("Not authenticated")

        url = f"{self.base_url}/cgi-bin/luci/;stok={self.stok}/{endpoint}"

        # Encrypt payload if needed
        if payload:
            # Add operation
            payload["operation"] = method

            # Encrypt for non-login requests
            if self.crypto.aes_key:
                import json
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

        with httpx.Client(timeout=15.0, cookies=cookies) as client:
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
                            import json
                            decrypted = self.crypto.aes_decrypt(data)
                            return json.loads(decrypted)
                        except Exception:
                            pass
                    return data if isinstance(data, dict) else {"data": data}
                return result

        raise Exception(f"Request failed: {endpoint}")

    def get_status(self) -> dict:
        """Get router status."""
        return self._make_request("admin/status?form=all")

    def get_devices(self) -> dict:
        """Get connected devices."""
        return self._make_request("admin/status?form=client_list")
