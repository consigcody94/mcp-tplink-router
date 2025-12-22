"""Tests for data classes."""

import pytest

from mcp_tplink_router.be3600_playwright import (
    DeviceInfo,
    PortForwardingRule,
    TimeoutConfig,
)
from mcp_tplink_router.tplink_client import (
    DHCPReservation,
    RouterInfo,
)


class TestTimeoutConfig:
    """Tests for TimeoutConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default timeout values."""
        config = TimeoutConfig()
        assert config.page_load == 2000
        assert config.login_wait == 3000
        assert config.navigation == 1500
        assert config.short_wait == 500
        assert config.element_click == 5000
        assert config.network_idle == 3000

    def test_custom_values(self) -> None:
        """Test custom timeout values."""
        config = TimeoutConfig(page_load=5000, login_wait=10000)
        assert config.page_load == 5000
        assert config.login_wait == 10000

    def test_from_dict(self) -> None:
        """Test creating config from dictionary."""
        config = TimeoutConfig.from_dict({
            "page_load": 4000,
            "navigation": 2000,
            "unknown_key": 9999,  # Should be ignored
        })
        assert config.page_load == 4000
        assert config.navigation == 2000
        assert config.login_wait == 3000  # Default


class TestDeviceInfo:
    """Tests for DeviceInfo dataclass."""

    def test_default_values(self) -> None:
        """Test default values are None."""
        device = DeviceInfo()
        assert device.name is None
        assert device.ip is None
        assert device.mac is None
        assert device.raw_text is None

    def test_with_values(self) -> None:
        """Test with actual values."""
        device = DeviceInfo(
            name="My Phone",
            ip="192.168.0.100",
            mac="AA:BB:CC:DD:EE:FF"
        )
        assert device.name == "My Phone"
        assert device.ip == "192.168.0.100"
        assert device.mac == "AA:BB:CC:DD:EE:FF"

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        device = DeviceInfo(
            name="Laptop",
            ip="192.168.0.50",
            mac="11:22:33:44:55:66"
        )
        result = device.to_dict()
        assert result == {
            "name": "Laptop",
            "ip": "192.168.0.50",
            "mac": "11:22:33:44:55:66",
        }

    def test_to_dict_excludes_none(self) -> None:
        """Test to_dict excludes None values."""
        device = DeviceInfo(name="Test")
        result = device.to_dict()
        assert "name" in result
        assert "ip" not in result
        assert "mac" not in result


class TestPortForwardingRule:
    """Tests for PortForwardingRule dataclass."""

    def test_default_values(self) -> None:
        """Test default values are None."""
        rule = PortForwardingRule()
        assert rule.name is None
        assert rule.internal_ip is None
        assert rule.external_port is None
        assert rule.internal_port is None
        assert rule.protocol is None
        assert rule.status is None

    def test_with_values(self) -> None:
        """Test with actual values."""
        rule = PortForwardingRule(
            name="SSH",
            internal_ip="192.168.0.10",
            external_port="22",
            internal_port="22",
            protocol="TCP",
            status="Enabled"
        )
        assert rule.name == "SSH"
        assert rule.external_port == "22"
        assert rule.protocol == "TCP"

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        rule = PortForwardingRule(
            name="HTTP",
            internal_ip="192.168.0.20",
            external_port="80",
            protocol="TCP"
        )
        result = rule.to_dict()
        assert result["name"] == "HTTP"
        assert result["external_port"] == "80"
        assert "internal_port" not in result  # None excluded


class TestRouterInfo:
    """Tests for RouterInfo dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        info = RouterInfo(host="192.168.0.1")
        assert info.host == "192.168.0.1"
        assert info.reachable is False
        assert info.firmware is None
        assert info.mode is None
        assert info.error is None

    def test_with_values(self) -> None:
        """Test with actual values."""
        info = RouterInfo(
            host="10.0.0.1",
            reachable=True,
            firmware="1.1.0",
            mode="router"
        )
        assert info.host == "10.0.0.1"
        assert info.reachable is True
        assert info.firmware == "1.1.0"
        assert info.mode == "router"

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        info = RouterInfo(
            host="192.168.1.1",
            reachable=True,
            firmware="2.0.0"
        )
        result = info.to_dict()
        assert result["host"] == "192.168.1.1"
        assert result["reachable"] is True
        assert result["firmware"] == "2.0.0"
        assert "mode" not in result  # None excluded
        assert "error" not in result  # None excluded


class TestDHCPReservation:
    """Tests for DHCPReservation dataclass."""

    def test_required_fields(self) -> None:
        """Test with required fields only."""
        reservation = DHCPReservation(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.0.100"
        )
        assert reservation.mac == "AA:BB:CC:DD:EE:FF"
        assert reservation.ip == "192.168.0.100"
        assert reservation.hostname is None
        assert reservation.enabled is True  # Default

    def test_all_fields(self) -> None:
        """Test with all fields."""
        reservation = DHCPReservation(
            mac="11:22:33:44:55:66",
            ip="192.168.0.50",
            hostname="my-server",
            enabled=False
        )
        assert reservation.mac == "11:22:33:44:55:66"
        assert reservation.hostname == "my-server"
        assert reservation.enabled is False

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        reservation = DHCPReservation(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.0.100",
            hostname="test-device",
            enabled=True
        )
        result = reservation.to_dict()
        assert result == {
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.168.0.100",
            "hostname": "test-device",
            "enabled": True,
        }
