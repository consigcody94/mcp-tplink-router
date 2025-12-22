"""MCP Server for TP-Link Router Management.

This module provides an MCP (Model Context Protocol) server for managing
TP-Link routers through AI assistants. It exposes router management
functionality as MCP tools.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, List, Optional

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .tplink_client import TPLinkClient

# Load environment variables
load_dotenv()

# Configure module logger
logger = logging.getLogger(__name__)


@dataclass
class ClientConfig:
    """Configuration for the TP-Link client."""

    host: str
    username: str
    password: str

    @classmethod
    def from_env(cls) -> ClientConfig:
        """Create configuration from environment variables.

        Returns:
            ClientConfig with values from environment.
        """
        return cls(
            host=os.getenv("TPLINK_HOST", "10.13.37.1"),
            username=os.getenv("TPLINK_USERNAME", "admin"),
            password=os.getenv("TPLINK_PASSWORD", ""),
        )


class ClientManager:
    """Manages the TP-Link client lifecycle.

    This class provides thread-safe access to a shared TPLinkClient instance,
    with lazy initialization on first use.

    Attributes:
        config: Client configuration.
    """

    def __init__(self, config: Optional[ClientConfig] = None) -> None:
        """Initialize the client manager.

        Args:
            config: Optional client configuration. If not provided,
                    configuration is loaded from environment variables.
        """
        self._config = config or ClientConfig.from_env()
        self._client: Optional[TPLinkClient] = None
        self._lock = asyncio.Lock()

    @property
    def config(self) -> ClientConfig:
        """Get the client configuration."""
        return self._config

    async def get_client(self) -> TPLinkClient:
        """Get or create the TP-Link client.

        This method is thread-safe and will only create one client instance.

        Returns:
            Configured TPLinkClient instance.
        """
        async with self._lock:
            if self._client is None:
                logger.debug("Creating new TPLinkClient for %s", self._config.host)
                self._client = TPLinkClient(
                    host=self._config.host,
                    username=self._config.username,
                    password=self._config.password,
                )
            return self._client

    async def reset_client(self) -> None:
        """Reset the client, forcing re-authentication on next use."""
        async with self._lock:
            if self._client:
                self._client.logout()
                self._client = None
            logger.debug("Client reset")


# Global client manager instance
_client_manager = ClientManager()


def get_client_manager() -> ClientManager:
    """Get the global client manager.

    Returns:
        The global ClientManager instance.
    """
    return _client_manager


# Initialize MCP server
server = Server("mcp-tplink-router")


def _get_tool_definitions() -> List[Tool]:
    """Get the list of available tool definitions.

    Returns:
        List of Tool definitions for the MCP server.
    """
    return [
        Tool(
            name="router_status",
            description="Get router status including WAN info and connected clients",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="list_port_forwarding",
            description="List all port forwarding rules configured on the router",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="add_port_forwarding",
            description="Add a new port forwarding rule",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name for the port forwarding rule"
                    },
                    "external_port": {
                        "type": "integer",
                        "description": "External port number"
                    },
                    "internal_ip": {
                        "type": "string",
                        "description": "Internal IP address to forward to"
                    },
                    "internal_port": {
                        "type": "integer",
                        "description": "Internal port number (defaults to external_port if not specified)"
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Protocol: TCP, UDP, or TCP/UDP (default)",
                        "enum": ["TCP", "UDP", "TCP/UDP"]
                    }
                },
                "required": ["name", "external_port", "internal_ip"]
            }
        ),
        Tool(
            name="delete_port_forwarding",
            description="Delete a port forwarding rule by name",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Name of the port forwarding rule to delete"
                    }
                },
                "required": ["name"]
            }
        ),
        Tool(
            name="list_dhcp_reservations",
            description="List all DHCP address reservations",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="add_dhcp_reservation",
            description="Add a DHCP reservation (static IP) for a device",
            inputSchema={
                "type": "object",
                "properties": {
                    "mac": {
                        "type": "string",
                        "description": "MAC address of the device"
                    },
                    "ip": {
                        "type": "string",
                        "description": "IP address to reserve"
                    },
                    "name": {
                        "type": "string",
                        "description": "Optional name for the reservation"
                    }
                },
                "required": ["mac", "ip"]
            }
        ),
        Tool(
            name="delete_dhcp_reservation",
            description="Delete a DHCP reservation by MAC address",
            inputSchema={
                "type": "object",
                "properties": {
                    "mac": {
                        "type": "string",
                        "description": "MAC address of the reservation to delete"
                    }
                },
                "required": ["mac"]
            }
        ),
        Tool(
            name="list_connected_devices",
            description="List all devices currently connected to the router",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="reboot_router",
            description="Reboot the router (use with caution!)",
            inputSchema={
                "type": "object",
                "properties": {
                    "confirm": {
                        "type": "boolean",
                        "description": "Must be true to confirm reboot"
                    }
                },
                "required": ["confirm"]
            }
        ),
        Tool(
            name="router_diagnostics",
            description="Get diagnostic information about router connection and authentication status",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="router_firmware",
            description="Get router firmware and hardware information",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]


async def _handle_tool_call(
    client: TPLinkClient,
    name: str,
    arguments: Dict[str, Any]
) -> Any:
    """Handle a tool call and return the result.

    Args:
        client: The TPLinkClient instance.
        name: The tool name.
        arguments: The tool arguments.

    Returns:
        The result of the tool call.

    Raises:
        ValueError: If the tool name is unknown.
    """
    if name == "router_status":
        return client.get_status()

    elif name == "list_port_forwarding":
        return client.get_port_forwarding()

    elif name == "add_port_forwarding":
        return client.add_port_forwarding(
            name=arguments["name"],
            external_port=arguments["external_port"],
            internal_ip=arguments["internal_ip"],
            internal_port=arguments.get("internal_port", arguments["external_port"]),
            protocol=arguments.get("protocol", "TCP/UDP")
        )

    elif name == "delete_port_forwarding":
        return client.delete_port_forwarding(arguments["name"])

    elif name == "list_dhcp_reservations":
        return client.get_dhcp_reservations()

    elif name == "add_dhcp_reservation":
        return client.add_dhcp_reservation(
            mac=arguments["mac"],
            ip=arguments["ip"],
            name=arguments.get("name", "")
        )

    elif name == "delete_dhcp_reservation":
        return client.delete_dhcp_reservation(arguments["mac"])

    elif name == "list_connected_devices":
        return client.get_connected_devices()

    elif name == "reboot_router":
        if arguments.get("confirm"):
            return client.reboot()
        else:
            return {"error": "Reboot not confirmed. Set confirm=true to proceed."}

    elif name == "router_diagnostics":
        return client.get_diagnostics()

    elif name == "router_firmware":
        return client.get_firmware()

    else:
        raise ValueError(f"Unknown tool: {name}")


@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools.

    Returns:
        List of available Tool definitions.
    """
    return _get_tool_definitions()


@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls.

    Args:
        name: The tool name to call.
        arguments: The arguments for the tool.

    Returns:
        List containing a single TextContent with the JSON result.
    """
    manager = get_client_manager()
    client = await manager.get_client()

    try:
        result = await asyncio.to_thread(_handle_tool_call, client, name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except ValueError as e:
        logger.warning("Invalid tool call: %s", e)
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]
    except Exception as e:
        logger.exception("Tool call error for %s: %s", name, e)
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]


def main() -> None:
    """Main entry point for the MCP server."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    async def run() -> None:
        """Run the MCP server."""
        logger.info("Starting MCP TP-Link Router server")
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options()
            )

    asyncio.run(run())


if __name__ == "__main__":
    main()
