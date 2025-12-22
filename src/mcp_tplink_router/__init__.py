"""MCP server for TP-Link router management.

This package provides tools for automating TP-Link BE3600 routers using
browser automation (Playwright) and the MCP (Model Context Protocol) for
AI assistant integration.

Example usage:
    >>> from mcp_tplink_router import TPLinkClient
    >>> client = TPLinkClient('192.168.0.1', password='my_password')
    >>> if client.login():
    ...     devices = client.get_connected_devices()
    ...     print(f"Found {len(devices)} devices")

For MCP server usage, run:
    $ mcp-tplink-router
"""

from .be3600_crypto import (
    AESKeyPair,
    AuthenticationError,
    BE3600Client,
    BE3600Crypto,
    CryptoError,
    KeyNotSetError,
    RSAKeyPair,
)
from .be3600_playwright import (
    BE3600PlaywrightClient,
    DeviceInfo,
    PortForwardingRule,
    TimeoutConfig,
)
from .server import ClientConfig, ClientManager, get_client_manager, main
from .tplink_client import (
    DHCPReservation,
    RouterInfo,
    TPLinkClient,
)

__version__ = "0.1.0"

__all__ = [
    # Main entry point
    "main",
    # High-level clients
    "TPLinkClient",
    "BE3600PlaywrightClient",
    "BE3600Client",
    # Server components
    "ClientConfig",
    "ClientManager",
    "get_client_manager",
    # Crypto
    "BE3600Crypto",
    "RSAKeyPair",
    "AESKeyPair",
    # Data classes
    "DeviceInfo",
    "PortForwardingRule",
    "RouterInfo",
    "DHCPReservation",
    "TimeoutConfig",
    # Exceptions
    "CryptoError",
    "KeyNotSetError",
    "AuthenticationError",
]
