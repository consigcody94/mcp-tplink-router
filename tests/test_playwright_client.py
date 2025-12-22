"""Tests for the BE3600 Playwright client module."""

import pytest

from mcp_tplink_router.be3600_playwright import (
    BE3600PlaywrightClient,
    TimeoutConfig,
)


class TestBE3600PlaywrightClient:
    """Tests for BE3600PlaywrightClient class."""

    def test_init_defaults(self) -> None:
        """Test client initialization with defaults."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        assert client.host == "192.168.0.1"
        assert client.password == "password"
        assert client.username == "admin"
        assert client.base_url == "http://192.168.0.1"
        assert client.stok is None
        assert client.sysauth is None
        assert client._headless is True
        assert client._ignore_https_errors is True

    def test_init_with_username(self) -> None:
        """Test client initialization with custom username."""
        client = BE3600PlaywrightClient(
            "192.168.0.1",
            "password",
            username="testuser"
        )
        assert client.username == "testuser"

    def test_init_with_headless_false(self) -> None:
        """Test client initialization with headless=False."""
        client = BE3600PlaywrightClient(
            "192.168.0.1",
            "password",
            headless=False
        )
        assert client._headless is False

    def test_init_with_custom_timeouts(self) -> None:
        """Test client initialization with custom timeouts."""
        timeouts = TimeoutConfig(page_load=5000, login_wait=10000)
        client = BE3600PlaywrightClient(
            "192.168.0.1",
            "password",
            timeouts=timeouts
        )
        assert client._timeouts.page_load == 5000
        assert client._timeouts.login_wait == 10000

    def test_context_manager_entry(self) -> None:
        """Test context manager entry."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        with client as c:
            assert c is client

    def test_escape_js_string_basic(self) -> None:
        """Test basic JavaScript string escaping."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        assert client._escape_js_string("hello") == "hello"

    def test_escape_js_string_quotes(self) -> None:
        """Test escaping quotes."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        assert client._escape_js_string("it's") == "it\\'s"
        assert client._escape_js_string('say "hi"') == 'say \\"hi\\"'

    def test_escape_js_string_backslash(self) -> None:
        """Test escaping backslashes."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        assert client._escape_js_string("path\\to") == "path\\\\to"

    def test_escape_js_string_newlines(self) -> None:
        """Test escaping newlines."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        assert client._escape_js_string("line1\nline2") == "line1\\nline2"
        assert client._escape_js_string("line1\rline2") == "line1\\rline2"

    def test_escape_js_string_script_tag(self) -> None:
        """Test escaping script closing tag."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        result = client._escape_js_string("test</script>test")
        assert "<\\/" in result

    def test_ensure_logged_in_raises_when_not_logged_in(self) -> None:
        """Test _ensure_logged_in raises RuntimeError when not logged in."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        with pytest.raises(RuntimeError, match="Not logged in"):
            client._ensure_logged_in()

    def test_navigate_to_raises_when_not_logged_in(self) -> None:
        """Test _navigate_to raises RuntimeError when not logged in."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        with pytest.raises(RuntimeError, match="Not logged in"):
            client._navigate_to("Network Map")

    def test_get_status_raises_when_not_logged_in(self) -> None:
        """Test get_status raises RuntimeError when not logged in."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        with pytest.raises(RuntimeError, match="Not logged in"):
            client.get_status()

    def test_get_devices_raises_when_not_logged_in(self) -> None:
        """Test get_devices raises RuntimeError when not logged in."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        with pytest.raises(RuntimeError, match="Not logged in"):
            client.get_devices()

    def test_get_port_forwarding_raises_when_not_logged_in(self) -> None:
        """Test get_port_forwarding raises RuntimeError when not logged in."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        with pytest.raises(RuntimeError, match="Not logged in"):
            client.get_port_forwarding()

    def test_add_port_forward_raises_when_not_logged_in(self) -> None:
        """Test add_port_forward raises RuntimeError when not logged in."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        with pytest.raises(RuntimeError, match="Not logged in"):
            client.add_port_forward(
                name="Test",
                external_port="80",
                internal_ip="192.168.0.10"
            )

    def test_get_dhcp_settings_raises_when_not_logged_in(self) -> None:
        """Test get_dhcp_settings raises RuntimeError when not logged in."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        with pytest.raises(RuntimeError, match="Not logged in"):
            client.get_dhcp_settings()

    def test_take_screenshot_returns_none_when_not_logged_in(self) -> None:
        """Test take_screenshot returns None when not logged in."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        result = client.take_screenshot()
        assert result is None

    def test_click_element_returns_false_when_not_logged_in(self) -> None:
        """Test _click_element returns False when not logged in."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        result = client._click_element("Test")
        assert result is False

    def test_close_when_not_connected(self) -> None:
        """Test close doesn't raise when not connected."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        # Should not raise
        client.close()
        assert client.stok is None
        assert client.sysauth is None
        assert client._page is None
        assert client._browser is None

    def test_logout_is_alias_for_close(self) -> None:
        """Test logout is an alias for close."""
        client = BE3600PlaywrightClient("192.168.0.1", "password")
        # Should not raise
        client.logout()
        assert client.stok is None
        assert client.sysauth is None
