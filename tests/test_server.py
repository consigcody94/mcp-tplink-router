"""Tests for the MCP server module."""

import os
from unittest.mock import patch

import pytest

from mcp_tplink_router.server import (
    ClientConfig,
    ClientManager,
    _get_tool_definitions,
    get_client_manager,
)


class TestClientConfig:
    """Tests for ClientConfig dataclass."""

    def test_creation(self) -> None:
        """Test config creation with values."""
        config = ClientConfig(
            host="192.168.0.1",
            username="admin",
            password="secret"
        )
        assert config.host == "192.168.0.1"
        assert config.username == "admin"
        assert config.password == "secret"

    def test_from_env_defaults(self) -> None:
        """Test from_env with no environment variables."""
        with patch.dict(os.environ, {}, clear=True):
            config = ClientConfig.from_env()
            assert config.host == "10.13.37.1"
            assert config.username == "admin"
            assert config.password == ""

    def test_from_env_with_values(self) -> None:
        """Test from_env with environment variables set."""
        env_vars = {
            "TPLINK_HOST": "192.168.1.1",
            "TPLINK_USERNAME": "testuser",
            "TPLINK_PASSWORD": "testpass",
        }
        with patch.dict(os.environ, env_vars, clear=True):
            config = ClientConfig.from_env()
            assert config.host == "192.168.1.1"
            assert config.username == "testuser"
            assert config.password == "testpass"


class TestClientManager:
    """Tests for ClientManager class."""

    def test_init_default_config(self) -> None:
        """Test manager initialization with default config."""
        manager = ClientManager()
        assert manager.config is not None
        assert manager._client is None

    def test_init_custom_config(self) -> None:
        """Test manager initialization with custom config."""
        config = ClientConfig(
            host="10.0.0.1",
            username="test",
            password="pass"
        )
        manager = ClientManager(config)
        assert manager.config.host == "10.0.0.1"
        assert manager.config.username == "test"

    @pytest.mark.asyncio
    async def test_get_client_creates_client(self) -> None:
        """Test get_client creates a client on first call."""
        config = ClientConfig(
            host="192.168.0.1",
            username="admin",
            password="test"
        )
        manager = ClientManager(config)
        client = await manager.get_client()
        assert client is not None
        assert client.host == "192.168.0.1"

    @pytest.mark.asyncio
    async def test_get_client_reuses_client(self) -> None:
        """Test get_client reuses existing client."""
        config = ClientConfig(
            host="192.168.0.1",
            username="admin",
            password="test"
        )
        manager = ClientManager(config)
        client1 = await manager.get_client()
        client2 = await manager.get_client()
        assert client1 is client2

    @pytest.mark.asyncio
    async def test_reset_client(self) -> None:
        """Test reset_client clears the client."""
        config = ClientConfig(
            host="192.168.0.1",
            username="admin",
            password="test"
        )
        manager = ClientManager(config)
        await manager.get_client()
        assert manager._client is not None

        await manager.reset_client()
        assert manager._client is None

    @pytest.mark.asyncio
    async def test_reset_client_when_no_client(self) -> None:
        """Test reset_client when no client exists."""
        manager = ClientManager()
        # Should not raise
        await manager.reset_client()
        assert manager._client is None


class TestGetClientManager:
    """Tests for get_client_manager function."""

    def test_returns_manager(self) -> None:
        """Test get_client_manager returns a manager."""
        manager = get_client_manager()
        assert isinstance(manager, ClientManager)

    def test_returns_same_manager(self) -> None:
        """Test get_client_manager returns same instance."""
        manager1 = get_client_manager()
        manager2 = get_client_manager()
        assert manager1 is manager2


class TestToolDefinitions:
    """Tests for tool definitions."""

    def test_get_tool_definitions_returns_list(self) -> None:
        """Test _get_tool_definitions returns a list."""
        tools = _get_tool_definitions()
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_all_tools_have_name(self) -> None:
        """Test all tools have a name."""
        tools = _get_tool_definitions()
        for tool in tools:
            assert tool.name is not None
            assert len(tool.name) > 0

    def test_all_tools_have_description(self) -> None:
        """Test all tools have a description."""
        tools = _get_tool_definitions()
        for tool in tools:
            assert tool.description is not None
            assert len(tool.description) > 0

    def test_all_tools_have_input_schema(self) -> None:
        """Test all tools have an input schema."""
        tools = _get_tool_definitions()
        for tool in tools:
            assert tool.inputSchema is not None
            assert "type" in tool.inputSchema
            assert tool.inputSchema["type"] == "object"

    def test_expected_tools_exist(self) -> None:
        """Test expected tools are defined."""
        tools = _get_tool_definitions()
        tool_names = {tool.name for tool in tools}

        expected_tools = {
            "router_status",
            "list_port_forwarding",
            "add_port_forwarding",
            "delete_port_forwarding",
            "list_dhcp_reservations",
            "add_dhcp_reservation",
            "delete_dhcp_reservation",
            "list_connected_devices",
            "reboot_router",
            "router_diagnostics",
            "router_firmware",
        }

        assert expected_tools.issubset(tool_names)
