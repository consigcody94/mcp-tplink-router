"""Tests for the TPLinkClient module."""

import pytest

from mcp_tplink_router.tplink_client import (
    MIN_ENCRYPTED_PASSWORD_LENGTH,
    TPLinkClient,
)


class TestTPLinkClient:
    """Tests for TPLinkClient class."""

    def test_init_defaults(self) -> None:
        """Test client initialization with defaults."""
        client = TPLinkClient("192.168.0.1")
        assert client.host == "192.168.0.1"
        assert client.username == "admin"
        assert client.password == ""
        assert client.base_url == "http://192.168.0.1"

    def test_init_with_credentials(self) -> None:
        """Test client initialization with credentials."""
        client = TPLinkClient(
            host="10.0.0.1",
            username="testuser",
            password="testpass"
        )
        assert client.host == "10.0.0.1"
        assert client.username == "testuser"
        assert client.password == "testpass"

    def test_is_authenticated_false_initially(self) -> None:
        """Test is_authenticated is False initially."""
        client = TPLinkClient("192.168.0.1")
        assert client.is_authenticated is False

    def test_uses_encrypted_password_short(self) -> None:
        """Test uses_encrypted_password with short password."""
        client = TPLinkClient("192.168.0.1", password="short")
        assert client.uses_encrypted_password is False

    def test_uses_encrypted_password_long(self) -> None:
        """Test uses_encrypted_password with long password."""
        long_password = "a" * MIN_ENCRYPTED_PASSWORD_LENGTH
        client = TPLinkClient("192.168.0.1", password=long_password)
        assert client.uses_encrypted_password is True

    def test_get_status_not_authenticated(self) -> None:
        """Test get_status returns error when not authenticated."""
        client = TPLinkClient("192.168.0.1")
        result = client.get_status()
        assert result["authenticated"] is False
        assert "message" in result

    def test_get_connected_devices_not_authenticated(self) -> None:
        """Test get_connected_devices returns error when not authenticated."""
        client = TPLinkClient("192.168.0.1")
        result = client.get_connected_devices()
        assert len(result) == 1
        assert "error" in result[0]

    def test_get_port_forwarding_not_authenticated(self) -> None:
        """Test get_port_forwarding returns error when not authenticated."""
        client = TPLinkClient("192.168.0.1")
        result = client.get_port_forwarding()
        assert len(result) == 1
        assert "error" in result[0]

    def test_add_port_forwarding_not_authenticated(self) -> None:
        """Test add_port_forwarding returns error when not authenticated."""
        client = TPLinkClient("192.168.0.1")
        result = client.add_port_forwarding(
            name="Test",
            external_port=80,
            internal_ip="192.168.0.10",
            internal_port=80
        )
        assert result["success"] is False
        assert "error" in result

    def test_delete_port_forwarding_not_authenticated(self) -> None:
        """Test delete_port_forwarding returns error when not authenticated."""
        client = TPLinkClient("192.168.0.1")
        result = client.delete_port_forwarding("Test")
        assert result["success"] is False
        assert "error" in result

    def test_get_dhcp_reservations_not_authenticated(self) -> None:
        """Test get_dhcp_reservations returns error when not authenticated."""
        client = TPLinkClient("192.168.0.1")
        result = client.get_dhcp_reservations()
        assert len(result) == 1
        assert "error" in result[0]

    def test_add_dhcp_reservation_not_authenticated(self) -> None:
        """Test add_dhcp_reservation returns error when not authenticated."""
        client = TPLinkClient("192.168.0.1")
        result = client.add_dhcp_reservation(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.0.100"
        )
        assert result["success"] is False
        assert "error" in result

    def test_delete_dhcp_reservation_not_authenticated(self) -> None:
        """Test delete_dhcp_reservation returns error when not authenticated."""
        client = TPLinkClient("192.168.0.1")
        result = client.delete_dhcp_reservation("AA:BB:CC:DD:EE:FF")
        assert result["success"] is False
        assert "error" in result

    def test_reboot_not_authenticated(self) -> None:
        """Test reboot returns error when not authenticated."""
        client = TPLinkClient("192.168.0.1")
        result = client.reboot()
        assert result["success"] is False
        assert "error" in result

    def test_get_firmware_not_authenticated(self) -> None:
        """Test get_firmware returns info when not authenticated."""
        client = TPLinkClient("192.168.0.1")
        result = client.get_firmware()
        assert result["authenticated"] is False

    def test_get_diagnostics(self) -> None:
        """Test get_diagnostics returns diagnostic info."""
        client = TPLinkClient(
            host="192.168.0.1",
            username="admin",
            password="test"
        )
        result = client.get_diagnostics()
        assert result["host"] == "192.168.0.1"
        assert result["username"] == "admin"
        assert result["authenticated"] is False
        assert result["password_length"] == 4
        assert result["uses_encrypted_password"] is False
        assert "help" in result  # Help message for short passwords

    def test_get_diagnostics_no_help_for_long_password(self) -> None:
        """Test get_diagnostics doesn't show help for long passwords."""
        long_password = "a" * MIN_ENCRYPTED_PASSWORD_LENGTH
        client = TPLinkClient("192.168.0.1", password=long_password)
        result = client.get_diagnostics()
        assert result["uses_encrypted_password"] is True
        assert "help" not in result

    def test_logout_when_not_connected(self) -> None:
        """Test logout doesn't raise when not connected."""
        client = TPLinkClient("192.168.0.1")
        # Should not raise
        client.logout()
        assert client._client is None
