"""TP-Link Router API Client with multiple authentication approaches.

For BE3600 and similar routers with new firmware, you need to use the
web-encrypted password instead of the plain text password.

To get the web-encrypted password:
1. Open router login page in browser (http://10.13.37.1)
2. Open browser developer tools (F12) -> Network tab
3. Enter your password and click Login
4. Find the POST request to login?form=login
5. In the request payload, copy the long encrypted "password" value
6. Use that value as TPLINK_PASSWORD in your .env file
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type

import httpx
from tplinkrouterc6u import (
    TPLinkMRClient,
    TPLinkMRClientGCM,
    TPLinkXDRClient,
    TplinkRouterProvider,
)
from tplinkrouterc6u.client.c5400x import TplinkC5400XRouter
from tplinkrouterc6u.common.exception import ClientException

# Configure module logger
logger = logging.getLogger(__name__)

# Minimum password length for web-encrypted passwords
MIN_ENCRYPTED_PASSWORD_LENGTH = 200


@dataclass
class RouterInfo:
    """Information about the router."""

    host: str
    reachable: bool = False
    firmware: Optional[str] = None
    mode: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class DeviceInfo:
    """Information about a connected device."""

    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    connection: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "connection": self.connection,
        }


@dataclass
class DHCPReservation:
    """DHCP address reservation."""

    mac: str
    ip: str
    hostname: Optional[str] = None
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "enabled": self.enabled,
        }


class TPLinkClient:
    """Client for TP-Link router API with multiple authentication strategies.

    For BE3600 routers with new firmware, use the web-encrypted password.
    The password should be 200+ characters if properly encrypted.

    Attributes:
        host: Router IP address or hostname.
        username: Router admin username.
        password: Router admin password (may be encrypted).

    Example:
        >>> client = TPLinkClient('192.168.0.1', password='my_password')
        >>> if client.login():
        ...     devices = client.get_connected_devices()
        ...     print(f"Found {len(devices)} devices")
    """

    def __init__(
        self,
        host: str,
        username: str = "admin",
        password: str = "",
        *,
        timeout: float = 10.0,
    ) -> None:
        """Initialize the TP-Link router client.

        Args:
            host: Router IP address or hostname.
            username: Router admin username (default: admin).
            password: Router admin password.
            timeout: HTTP request timeout in seconds.
        """
        self.host = host
        self.username = username
        self.password = password
        self.base_url = f"http://{host}"
        self._timeout = timeout
        self._client: Any = None
        self._client_type: Optional[str] = None
        self._last_error: Optional[str] = None
        self._router_info: Optional[RouterInfo] = None
        self._stok: Optional[str] = None
        self._sysauth: Optional[str] = None

    @property
    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        return self._client is not None or self._stok is not None

    @property
    def uses_encrypted_password(self) -> bool:
        """Check if password appears to be web-encrypted."""
        return len(self.password) >= MIN_ENCRYPTED_PASSWORD_LENGTH

    def _get_router_info(self) -> RouterInfo:
        """Get basic router information without authentication.

        Returns:
            RouterInfo object with basic router details.
        """
        info = RouterInfo(host=self.host)
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.get(f"{self.base_url}/webpages/index.html")
                if resp.status_code == 200:
                    info.reachable = True
                    # Extract version from meta tag
                    match = re.search(r'name="version"\s+content="([^"]+)"', resp.text)
                    if match:
                        info.firmware = match.group(1)

                    # Try sysmode endpoint
                    resp = client.post(
                        f"{self.base_url}/cgi-bin/luci/;stok=/login?form=sysmode",
                        headers={"Content-Type": "application/json"},
                        json={"operation": "read"}
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("success"):
                            info.mode = data.get("data", {}).get("mode", "unknown")
        except httpx.TimeoutException:
            info.error = "Connection timed out"
            logger.warning("Router connection timed out: %s", self.host)
        except httpx.RequestError as e:
            info.error = str(e)
            logger.warning("Router connection error: %s", e)
        except Exception as e:
            info.error = str(e)
            logger.exception("Unexpected error getting router info: %s", e)
        return info

    def _try_be3600_login(self) -> bool:
        """Try BE3600-style login with web-encrypted password.

        Returns:
            True if login successful, False otherwise.
        """
        if not self.uses_encrypted_password:
            self._last_error = "Password too short for BE3600 login. Use web-encrypted password."
            logger.debug("Password too short for BE3600 login")
            return False

        try:
            client = TplinkC5400XRouter(self.base_url, self.password, self.username)
            client.authorize()
            self._client = client
            self._client_type = "TplinkC5400XRouter (BE3600 compatible)"
            logger.info("BE3600 login successful")
            return True
        except ClientException as e:
            self._last_error = f"BE3600 login failed: {e}"
            logger.debug("BE3600 login failed: %s", e)
            return False
        except Exception as e:
            self._last_error = f"BE3600 login failed: {e}"
            logger.debug("BE3600 login failed with unexpected error: %s", e)
            return False

    def _try_direct_login(self) -> bool:
        """Try direct LuCI-style login (for routers with plain password support).

        Returns:
            True if login successful, False otherwise.
        """
        try:
            with httpx.Client(timeout=self._timeout) as client:
                resp = client.post(
                    f"{self.base_url}/cgi-bin/luci/;stok=/login?form=login",
                    params={
                        "operation": "login",
                        "username": self.username,
                        "password": self.password
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("success") and data.get("data", {}).get("stok"):
                        self._stok = data["data"]["stok"]
                        # Extract sysauth from cookies
                        set_cookie = resp.headers.get("set-cookie", "")
                        if "sysauth" in set_cookie:
                            match = re.search(r'sysauth=([^;]+)', set_cookie)
                            if match:
                                self._sysauth = match.group(1)
                        self._client_type = "Direct LuCI login"
                        logger.info("Direct LuCI login successful")
                        return True
        except httpx.TimeoutException:
            self._last_error = "Direct login timed out"
            logger.debug("Direct login timed out")
        except httpx.RequestError as e:
            self._last_error = f"Direct login failed: {e}"
            logger.debug("Direct login failed: %s", e)
        except Exception as e:
            self._last_error = f"Direct login failed: {e}"
            logger.debug("Direct login failed with unexpected error: %s", e)
        return False

    def login(self) -> bool:
        """Login to the router using multiple strategies.

        Tries several authentication methods in order:
        1. BE3600-style with web-encrypted password (if password is long)
        2. tplinkrouterc6u library with auto-detection
        3. Explicit client types (MRClientGCM, MRClient, XDRClient)
        4. Direct LuCI-style login

        Returns:
            True if any login method succeeds, False otherwise.
        """
        # First, get router info
        self._router_info = self._get_router_info()

        if not self._router_info.reachable:
            self._last_error = "Router not reachable"
            logger.error("Router not reachable at %s", self.host)
            return False

        # Strategy 1: If password is long (web-encrypted), try BE3600 style
        if self.uses_encrypted_password:
            if self._try_be3600_login():
                return True

        # Strategy 2: Try tplinkrouterc6u library with auto-detection
        try:
            client = TplinkRouterProvider.get_client(self.base_url, self.password)
            client.authorize()
            self._client = client
            self._client_type = type(client).__name__
            logger.info("Login successful via TplinkRouterProvider (%s)", self._client_type)
            return True
        except ClientException as e:
            self._last_error = f"TplinkRouterProvider failed: {e}"
            logger.debug("TplinkRouterProvider failed: %s", e)

        # Strategy 3: Try different client types explicitly
        client_classes: List[Type[Any]] = [
            TPLinkMRClientGCM,
            TPLinkMRClient,
            TPLinkXDRClient,
        ]

        for ClientClass in client_classes:
            try:
                client = ClientClass(self.base_url, self.password, self.username)
                client.authorize()
                self._client = client
                self._client_type = ClientClass.__name__
                logger.info("Login successful via %s", self._client_type)
                return True
            except ClientException as e:
                self._last_error = f"{ClientClass.__name__} failed: {e}"
                logger.debug("%s failed: %s", ClientClass.__name__, e)
            except Exception as e:
                self._last_error = f"{ClientClass.__name__} failed: {e}"
                logger.debug("%s failed with unexpected error: %s", ClientClass.__name__, e)

        # Strategy 4: Try direct LuCI login
        if self._try_direct_login():
            return True

        # If all strategies fail, provide helpful error message
        if not self.uses_encrypted_password:
            self._last_error = (
                "Authentication failed. For BE3600 with new firmware, you need the web-encrypted password. "
                "See the documentation for how to extract it from your browser's network tab."
            )
        logger.error("All authentication strategies failed for %s", self.host)
        return False

    def get_status(self) -> Dict[str, Any]:
        """Get router status information.

        Returns:
            Dictionary with status info, or error details if not authenticated.
        """
        if not self._client:
            return {
                "authenticated": False,
                "router_info": self._router_info.to_dict() if self._router_info else None,
                "last_error": self._last_error,
                "message": "Authentication failed. The BE3600 firmware may require updated library support."
            }

        try:
            status = self._client.get_status()
            return {
                "authenticated": True,
                "client_type": self._client_type,
                "wan_ip": str(status.wan_ipv4_addr) if status.wan_ipv4_addr else None,
                "lan_ip": str(status.lan_ipv4_addr) if status.lan_ipv4_addr else None,
                "wifi_2g_enabled": status.wifi_2g_enable,
                "wifi_5g_enabled": status.wifi_5g_enable,
                "connected_devices": len(status.devices),
                "wired_clients": status.wired_total,
                "wifi_clients": status.wifi_clients_total,
            }
        except AttributeError as e:
            logger.warning("Status attribute error: %s", e)
            return {"error": f"Status format error: {e}"}
        except Exception as e:
            logger.error("Error getting status: %s", e)
            return {"error": str(e)}

    def get_connected_devices(self) -> List[Dict[str, Any]]:
        """Get list of connected devices.

        Returns:
            List of device dictionaries, or error dictionary if failed.
        """
        if not self._client:
            return [{"error": "Not authenticated", "last_error": self._last_error}]

        try:
            status = self._client.get_status()
            devices: List[Dict[str, Any]] = []
            for dev in status.devices:
                device_info = DeviceInfo(
                    mac=str(dev.macaddr),
                    ip=str(dev.ipaddr) if dev.ipaddr else None,
                    hostname=dev.hostname,
                    connection=dev.type.name if hasattr(dev.type, 'name') else str(dev.type),
                )
                devices.append(device_info.to_dict())
            return devices
        except AttributeError as e:
            logger.warning("Device list attribute error: %s", e)
            return [{"error": f"Device format error: {e}"}]
        except Exception as e:
            logger.error("Error getting connected devices: %s", e)
            return [{"error": str(e)}]

    def get_port_forwarding(self) -> List[Dict[str, Any]]:
        """Get current port forwarding rules.

        Returns:
            List of port forwarding rules, or error if not supported.
        """
        if not self._client:
            return [{"error": "Not authenticated - port forwarding not available"}]

        # Note: tplinkrouterc6u doesn't have built-in port forwarding support
        return [{"error": "Port forwarding not supported by this client library"}]

    def add_port_forwarding(
        self,
        name: str,
        external_port: int,
        internal_ip: str,
        internal_port: int,
        protocol: str = "TCP/UDP"
    ) -> Dict[str, Any]:
        """Add a port forwarding rule.

        Args:
            name: Name for the rule.
            external_port: External port number.
            internal_ip: Internal IP address.
            internal_port: Internal port number.
            protocol: Protocol (TCP, UDP, or TCP/UDP).

        Returns:
            Result dictionary with success status.
        """
        if not self._client:
            return {"success": False, "error": "Not authenticated"}

        return {"success": False, "error": "Port forwarding not supported by this client library"}

    def delete_port_forwarding(self, name: str) -> Dict[str, Any]:
        """Delete a port forwarding rule by name.

        Args:
            name: Name of the rule to delete.

        Returns:
            Result dictionary with success status.
        """
        if not self._client:
            return {"success": False, "error": "Not authenticated"}

        return {"success": False, "error": "Port forwarding not supported by this client library"}

    def get_dhcp_reservations(self) -> List[Dict[str, Any]]:
        """Get DHCP address reservations.

        Returns:
            List of DHCP reservations, or error if failed.
        """
        if not self._client:
            return [{"error": "Not authenticated"}]

        try:
            reservations = self._client.get_ipv4_reservations()
            result: List[Dict[str, Any]] = []
            for r in reservations:
                reservation = DHCPReservation(
                    mac=str(r.macaddr),
                    ip=str(r.ipaddr),
                    hostname=r.hostname,
                    enabled=r.enabled,
                )
                result.append(reservation.to_dict())
            return result
        except AttributeError as e:
            logger.warning("DHCP reservations attribute error: %s", e)
            return [{"error": f"DHCP format error: {e}"}]
        except Exception as e:
            logger.error("Error getting DHCP reservations: %s", e)
            return [{"error": str(e)}]

    def add_dhcp_reservation(
        self,
        mac: str,
        ip: str,
        name: str = ""
    ) -> Dict[str, Any]:
        """Add a DHCP reservation.

        Args:
            mac: MAC address of the device.
            ip: IP address to reserve.
            name: Optional name for the reservation.

        Returns:
            Result dictionary with success status.
        """
        if not self._client:
            return {"success": False, "error": "Not authenticated"}

        return {"success": False, "error": "DHCP reservation add not supported by this client library"}

    def delete_dhcp_reservation(self, mac: str) -> Dict[str, Any]:
        """Delete a DHCP reservation by MAC address.

        Args:
            mac: MAC address of the reservation to delete.

        Returns:
            Result dictionary with success status.
        """
        if not self._client:
            return {"success": False, "error": "Not authenticated"}

        return {"success": False, "error": "DHCP reservation delete not supported by this client library"}

    def reboot(self) -> Dict[str, Any]:
        """Reboot the router.

        Returns:
            Result dictionary with success status.
        """
        if not self._client:
            return {"success": False, "error": "Not authenticated"}

        try:
            self._client.reboot()
            logger.info("Router reboot initiated")
            return {"success": True, "message": "Reboot initiated"}
        except Exception as e:
            logger.error("Error rebooting router: %s", e)
            return {"success": False, "error": str(e)}

    def get_firmware(self) -> Dict[str, Any]:
        """Get firmware information.

        Returns:
            Dictionary with firmware details.
        """
        if not self._client:
            return {
                "authenticated": False,
                "router_info": self._router_info.to_dict() if self._router_info else None,
            }

        try:
            fw = self._client.get_firmware()
            return {
                "hardware_version": fw.hardware_version,
                "model": fw.model,
                "firmware_version": fw.firmware_version,
            }
        except AttributeError as e:
            logger.warning("Firmware info attribute error: %s", e)
            return {"error": f"Firmware format error: {e}"}
        except Exception as e:
            logger.error("Error getting firmware info: %s", e)
            return {"error": str(e)}

    def get_diagnostics(self) -> Dict[str, Any]:
        """Get diagnostic information about the connection.

        Returns:
            Dictionary with diagnostic details and help messages.
        """
        diag: Dict[str, Any] = {
            "host": self.host,
            "username": self.username,
            "authenticated": self.is_authenticated,
            "client_type": self._client_type,
            "router_info": self._router_info.to_dict() if self._router_info else None,
            "last_error": self._last_error,
            "password_length": len(self.password),
            "uses_encrypted_password": self.uses_encrypted_password,
        }

        # Add helpful message for BE3600 users
        if not diag["authenticated"] and not self.uses_encrypted_password:
            diag["help"] = (
                "For TP-Link BE3600 with new firmware, you need the web-encrypted password. "
                "Steps to get it: "
                "1) Open http://10.13.37.1 in your browser. "
                "2) Open DevTools (F12) -> Network tab. "
                "3) Enter your password and click Login. "
                "4) Find the POST request to 'login?form=login'. "
                "5) Copy the encrypted 'password' value from the request. "
                "6) Set TPLINK_PASSWORD to this value in your .env file."
            )

        return diag

    def logout(self) -> None:
        """Logout from the router and clean up resources."""
        if self._client:
            try:
                self._client.logout()
                logger.debug("Logged out from router")
            except Exception as e:
                logger.debug("Error during logout: %s", e)
        self._client = None
        self._client_type = None
        self._stok = None
        self._sysauth = None
