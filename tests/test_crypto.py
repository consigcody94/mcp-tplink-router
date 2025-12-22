"""Tests for the BE3600 cryptography module."""

import pytest

from mcp_tplink_router.be3600_crypto import (
    AESKeyPair,
    BE3600Crypto,
    CryptoError,
    KeyNotSetError,
    RSAKeyPair,
)


class TestRSAKeyPair:
    """Tests for RSAKeyPair dataclass."""

    def test_creation(self) -> None:
        """Test RSA key pair creation."""
        key = RSAKeyPair(n="abc123", e="10001")
        assert key.n == "abc123"
        assert key.e == "10001"

    def test_key_length(self) -> None:
        """Test key length property."""
        key = RSAKeyPair(n="a" * 256, e="10001")
        assert key.key_length == 256


class TestAESKeyPair:
    """Tests for AESKeyPair dataclass."""

    def test_creation(self) -> None:
        """Test AES key pair creation."""
        key = AESKeyPair(key="0123456789abcdef", iv="fedcba9876543210")
        assert key.key == "0123456789abcdef"
        assert key.iv == "fedcba9876543210"

    def test_formatted(self) -> None:
        """Test formatted output."""
        key = AESKeyPair(key="mykey123456789ab", iv="myiv0987654321cd")
        assert key.formatted() == "k=mykey123456789ab&i=myiv0987654321cd"


class TestBE3600Crypto:
    """Tests for BE3600Crypto class."""

    def test_init(self) -> None:
        """Test crypto handler initialization."""
        crypto = BE3600Crypto()
        assert crypto.rsa_n is None
        assert crypto.rsa_e is None
        assert crypto.aes_key is None
        assert crypto.aes_iv is None
        assert crypto.hash is None
        assert crypto.sequence is None

    def test_set_rsa_key(self) -> None:
        """Test setting RSA key."""
        crypto = BE3600Crypto()
        crypto.set_rsa_key("abc123", "10001")
        assert crypto.rsa_n == "abc123"
        assert crypto.rsa_e == "10001"

    def test_set_password_rsa_key(self) -> None:
        """Test setting password RSA key."""
        crypto = BE3600Crypto()
        crypto.set_password_rsa_key("def456", "10001")
        assert crypto.pwd_rsa_n == "def456"
        assert crypto.pwd_rsa_e == "10001"

    def test_set_sequence(self) -> None:
        """Test setting sequence number."""
        crypto = BE3600Crypto()
        crypto.set_sequence(12345)
        assert crypto.sequence == 12345

    def test_generate_aes_key_hex(self) -> None:
        """Test AES key generation with hex format."""
        crypto = BE3600Crypto()
        crypto.generate_aes_key(use_hex=True)
        assert crypto.aes_key is not None
        assert crypto.aes_iv is not None
        assert len(crypto.aes_key) == 16
        assert len(crypto.aes_iv) == 16

    def test_generate_aes_key_numeric(self) -> None:
        """Test AES key generation with numeric format."""
        crypto = BE3600Crypto()
        crypto.generate_aes_key(use_hex=False)
        assert crypto.aes_key is not None
        assert crypto.aes_iv is not None
        assert len(crypto.aes_key) == 16
        assert len(crypto.aes_iv) == 16
        # Should be all digits
        assert crypto.aes_key.isdigit()
        assert crypto.aes_iv.isdigit()

    def test_get_aes_formatted_key_empty(self) -> None:
        """Test formatted key when not set."""
        crypto = BE3600Crypto()
        assert crypto.get_aes_formatted_key() == ""

    def test_get_aes_formatted_key(self) -> None:
        """Test formatted key when set."""
        crypto = BE3600Crypto()
        crypto.generate_aes_key()
        formatted = crypto.get_aes_formatted_key()
        assert formatted.startswith("k=")
        assert "&i=" in formatted

    def test_hash_password_sha256(self) -> None:
        """Test password hashing with SHA256."""
        crypto = BE3600Crypto()
        result = crypto.hash_password("mypassword", "admin")
        assert crypto.hash == result
        assert len(result) == 64  # SHA256 hex digest length

    def test_hash_password_md5(self) -> None:
        """Test password hashing with MD5."""
        crypto = BE3600Crypto()
        result = crypto.hash_password("mypassword", "admin", use_md5=True)
        assert crypto.hash == result
        assert len(result) == 32  # MD5 hex digest length

    def test_aes_encrypt_decrypt_roundtrip(self) -> None:
        """Test AES encryption and decryption roundtrip."""
        crypto = BE3600Crypto()
        crypto.generate_aes_key()

        plaintext = "Hello, World! This is a test message."
        encrypted = crypto.aes_encrypt(plaintext)
        decrypted = crypto.aes_decrypt(encrypted)

        assert decrypted == plaintext

    def test_aes_encrypt_no_key(self) -> None:
        """Test AES encryption without key raises error."""
        crypto = BE3600Crypto()
        with pytest.raises(KeyNotSetError):
            crypto.aes_encrypt("test")

    def test_aes_decrypt_no_key(self) -> None:
        """Test AES decryption without key raises error."""
        crypto = BE3600Crypto()
        with pytest.raises(KeyNotSetError):
            crypto.aes_decrypt("dGVzdA==")

    def test_rsa_encrypt_chunk_no_key(self) -> None:
        """Test RSA encryption without key raises error."""
        crypto = BE3600Crypto()
        with pytest.raises(KeyNotSetError):
            crypto.rsa_encrypt_chunk("test")

    def test_generate_signature_no_hash(self) -> None:
        """Test signature generation without hash raises error."""
        crypto = BE3600Crypto()
        crypto.set_sequence(1000)
        crypto.generate_aes_key()
        with pytest.raises(KeyNotSetError, match="Password hash not set"):
            crypto.generate_signature(100)

    def test_generate_signature_no_sequence(self) -> None:
        """Test signature generation without sequence raises error."""
        crypto = BE3600Crypto()
        crypto.hash_password("test")
        crypto.generate_aes_key()
        with pytest.raises(KeyNotSetError, match="Sequence not set"):
            crypto.generate_signature(100)

    def test_serialize_payload_simple(self) -> None:
        """Test simple payload serialization."""
        crypto = BE3600Crypto()
        payload = {"key1": "value1", "key2": "value2"}
        result = crypto.serialize_payload(payload)
        assert "key1=value1" in result
        assert "key2=value2" in result
        assert "&" in result

    def test_serialize_payload_boolean(self) -> None:
        """Test payload serialization with booleans."""
        crypto = BE3600Crypto()
        payload = {"enabled": True, "disabled": False}
        result = crypto.serialize_payload(payload)
        assert "enabled=true" in result
        assert "disabled=false" in result

    def test_serialize_payload_dict(self) -> None:
        """Test payload serialization with nested dict."""
        crypto = BE3600Crypto()
        payload = {"data": {"nested": "value"}}
        result = crypto.serialize_payload(payload)
        assert "data=" in result

    def test_serialize_payload_none_values(self) -> None:
        """Test payload serialization skips None values."""
        crypto = BE3600Crypto()
        payload = {"key1": "value1", "key2": None}
        result = crypto.serialize_payload(payload)
        assert "key1=value1" in result
        assert "key2" not in result

    def test_rsa_encrypt_password_no_key(self) -> None:
        """Test RSA password encryption without key raises error."""
        crypto = BE3600Crypto()
        with pytest.raises(KeyNotSetError):
            crypto.rsa_encrypt_password("password")


class TestCryptoExceptions:
    """Tests for crypto exception classes."""

    def test_crypto_error_base(self) -> None:
        """Test CryptoError is base exception."""
        with pytest.raises(CryptoError):
            raise CryptoError("test error")

    def test_key_not_set_error(self) -> None:
        """Test KeyNotSetError inherits from CryptoError."""
        error = KeyNotSetError("key not set")
        assert isinstance(error, CryptoError)
