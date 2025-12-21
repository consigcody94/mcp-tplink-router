"""MCP Server for TP-Link Router Management."""

import os
import json
import asyncio
from typing import Any
from dotenv import load_dotenv

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .tplink_client import TPLinkClient

# Load environment variables
load_dotenv()

# Initialize MCP server
server = Server("mcp-tplink-router")

# Router client (initialized on first use)
_client: TPLinkClient | None = None


def get_client() -> TPLinkClient:
    """Get or create the TP-Link client."""
    global _client
    if _client is None:
        host = os.getenv("TPLINK_HOST", "10.13.37.1")
        username = os.getenv("TPLINK_USERNAME", "admin")
        password = os.getenv("TPLINK_PASSWORD", "")
        _client = TPLinkClient(host, username, password)
    return _client


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
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


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    client = get_client()

    try:
        if name == "router_status":
            result = client.get_status()

        elif name == "list_port_forwarding":
            result = client.get_port_forwarding()

        elif name == "add_port_forwarding":
            result = client.add_port_forwarding(
                name=arguments["name"],
                external_port=arguments["external_port"],
                internal_ip=arguments["internal_ip"],
                internal_port=arguments.get("internal_port", arguments["external_port"]),
                protocol=arguments.get("protocol", "TCP/UDP")
            )

        elif name == "delete_port_forwarding":
            result = client.delete_port_forwarding(arguments["name"])

        elif name == "list_dhcp_reservations":
            result = client.get_dhcp_reservations()

        elif name == "add_dhcp_reservation":
            result = client.add_dhcp_reservation(
                mac=arguments["mac"],
                ip=arguments["ip"],
                name=arguments.get("name", "")
            )

        elif name == "delete_dhcp_reservation":
            result = client.delete_dhcp_reservation(arguments["mac"])

        elif name == "list_connected_devices":
            result = client.get_connected_devices()

        elif name == "reboot_router":
            if arguments.get("confirm"):
                result = client.reboot()
            else:
                result = {"error": "Reboot not confirmed. Set confirm=true to proceed."}

        elif name == "router_diagnostics":
            result = client.get_diagnostics()

        elif name == "router_firmware":
            result = client.get_firmware()

        else:
            result = {"error": f"Unknown tool: {name}"}

        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]


def main():
    """Main entry point."""
    async def run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(run())


if __name__ == "__main__":
    main()
