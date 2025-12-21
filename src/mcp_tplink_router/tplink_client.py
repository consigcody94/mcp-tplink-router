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

import hashlib
import httpx
import re
from typing import Any, Optional
from tplinkrouterc6u import (
    TplinkRouterProvider,
    TPLinkMRClient,
    TPLinkMRClientGCM,
    TPLinkXDRClient,
)
from tplinkrouterc6u.client.c5400x import TplinkC5400XRouter
from tplinkrouterc6u.common.exception import ClientException


class TPLinkClient:
    """Client for TP-Link router API with multiple authentication strategies.

    For BE3600 routers with new firmware, use the web-encrypted password.
    The password should be 200+ characters if properly encrypted.
    """

    def __init__(self, host: str, username: str = "admin", password: str = ""):
        self.host = host
        self.username = username
        self.password = password
        self.base_url = f"http://{host}"
        self._client = None
        self._client_type = None
        self._last_error = None
        self._router_info = None
        self._stok = None
        self._sysauth = None

    def _get_router_info(self) -> dict:
        """Get basic router information without authentication."""
        info = {"host": self.host, "reachable": False}
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.get(f"{self.base_url}/webpages/index.html")
                if resp.status_code == 200:
                    info["reachable"] = True
                    # Extract version from meta tag
                    import re
                    match = re.search(r'name="version"\s+content="([^"]+)"', resp.text)
                    if match:
                        info["firmware"] = match.group(1)

                    # Try sysmode endpoint
                    resp = client.post(
                        f"{self.base_url}/cgi-bin/luci/;stok=/login?form=sysmode",
                        headers={"Content-Type": "application/json"},
                        json={"operation": "read"}
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("success"):
                            info["mode"] = data.get("data", {}).get("mode", "unknown")
        except Exception as e:
            info["error"] = str(e)
        return info

    def _try_be3600_login(self) -> bool:
        """Try BE3600-style login with web-encrypted password."""
        # This requires a web-encrypted password (200+ chars)
        if len(self.password) < 200:
            self._last_error = "Password too short for BE3600 login. Use web-encrypted password."
            return False

        try:
            # Use C5400X client which works with BE3600 web-encrypted passwords
            client = TplinkC5400XRouter(self.base_url, self.password, self.username)
            client.authorize()
            self._client = client
            self._client_type = "TplinkC5400XRouter (BE3600 compatible)"
            return True
        except Exception as e:
            self._last_error = f"BE3600 login failed: {e}"
            return False

    def _try_direct_login(self) -> bool:
        """Try direct LuCI-style login (for routers with plain password support)."""
        try:
            with httpx.Client(timeout=15.0) as client:
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
                        if "sysauth" in resp.headers.get("set-cookie", ""):
                            match = re.search(r'sysauth=([^;]+)', resp.headers.get("set-cookie", ""))
                            if match:
                                self._sysauth = match.group(1)
                        self._client_type = "Direct LuCI login"
                        return True
        except Exception as e:
            self._last_error = f"Direct login failed: {e}"
        return False

    def login(self) -> bool:
        """Login to the router using multiple strategies."""
        # First, get router info
        self._router_info = self._get_router_info()

        if not self._router_info.get("reachable"):
            self._last_error = "Router not reachable"
            return False

        # Strategy 1: If password is long (web-encrypted), try BE3600 style
        if len(self.password) >= 200:
            if self._try_be3600_login():
                return True

        # Strategy 2: Try tplinkrouterc6u library with auto-detection
        try:
            client = TplinkRouterProvider.get_client(self.base_url, self.password)
            client.authorize()
            self._client = client
            self._client_type = type(client).__name__
            return True
        except ClientException as e:
            self._last_error = f"TplinkRouterProvider failed: {e}"

        # Strategy 3: Try different client types explicitly
        client_classes = [
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
                return True
            except Exception as e:
                self._last_error = f"{ClientClass.__name__} failed: {e}"
                continue

        # Strategy 4: Try direct LuCI login
        if self._try_direct_login():
            return True

        # If all strategies fail, provide helpful error message
        if len(self.password) < 200:
            self._last_error = (
                "Authentication failed. For BE3600 with new firmware, you need the web-encrypted password. "
                "See the documentation for how to extract it from your browser's network tab."
            )
        return False

    def get_status(self) -> dict:
        """Get router status information."""
        if not self._client:
            # Return what we can get without authentication
            return {
                "authenticated": False,
                "router_info": self._router_info,
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
        except Exception as e:
            return {"error": str(e)}

    def get_connected_devices(self) -> list:
        """Get list of connected devices."""
        if not self._client:
            return [{"error": "Not authenticated", "last_error": self._last_error}]

        try:
            status = self._client.get_status()
            devices = []
            for dev in status.devices:
                devices.append({
                    "mac": str(dev.macaddr),
                    "ip": str(dev.ipaddr) if dev.ipaddr else None,
                    "hostname": dev.hostname,
                    "connection": dev.type.name if hasattr(dev.type, 'name') else str(dev.type),
                })
            return devices
        except Exception as e:
            return [{"error": str(e)}]

    def get_port_forwarding(self) -> list:
        """Get current port forwarding rules."""
        if not self._client:
            return [{"error": "Not authenticated - port forwarding not available"}]

        # Note: tplinkrouterc6u doesn't have built-in port forwarding support
        # This would require direct API calls
        return [{"error": "Port forwarding not supported by this client library"}]

    def add_port_forwarding(
        self,
        name: str,
        external_port: int,
        internal_ip: str,
        internal_port: int,
        protocol: str = "TCP/UDP"
    ) -> dict:
        """Add a port forwarding rule."""
        if not self._client:
            return {"success": False, "error": "Not authenticated"}

        return {"success": False, "error": "Port forwarding not supported by this client library"}

    def delete_port_forwarding(self, name: str) -> dict:
        """Delete a port forwarding rule by name."""
        if not self._client:
            return {"success": False, "error": "Not authenticated"}

        return {"success": False, "error": "Port forwarding not supported by this client library"}

    def get_dhcp_reservations(self) -> list:
        """Get DHCP address reservations."""
        if not self._client:
            return [{"error": "Not authenticated"}]

        try:
            reservations = self._client.get_ipv4_reservations()
            return [
                {
                    "mac": str(r.macaddr),
                    "ip": str(r.ipaddr),
                    "hostname": r.hostname,
                    "enabled": r.enabled,
                }
                for r in reservations
            ]
        except Exception as e:
            return [{"error": str(e)}]

    def add_dhcp_reservation(self, mac: str, ip: str, name: str = "") -> dict:
        """Add a DHCP reservation."""
        if not self._client:
            return {"success": False, "error": "Not authenticated"}

        return {"success": False, "error": "DHCP reservation add not supported by this client library"}

    def delete_dhcp_reservation(self, mac: str) -> dict:
        """Delete a DHCP reservation by MAC address."""
        if not self._client:
            return {"success": False, "error": "Not authenticated"}

        return {"success": False, "error": "DHCP reservation delete not supported by this client library"}

    def reboot(self) -> dict:
        """Reboot the router."""
        if not self._client:
            return {"success": False, "error": "Not authenticated"}

        try:
            self._client.reboot()
            return {"success": True, "message": "Reboot initiated"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_firmware(self) -> dict:
        """Get firmware information."""
        if not self._client:
            return {
                "authenticated": False,
                "router_info": self._router_info,
            }

        try:
            fw = self._client.get_firmware()
            return {
                "hardware_version": fw.hardware_version,
                "model": fw.model,
                "firmware_version": fw.firmware_version,
            }
        except Exception as e:
            return {"error": str(e)}

    def get_diagnostics(self) -> dict:
        """Get diagnostic information about the connection."""
        diag = {
            "host": self.host,
            "username": self.username,
            "authenticated": self._client is not None or self._stok is not None,
            "client_type": self._client_type,
            "router_info": self._router_info,
            "last_error": self._last_error,
            "password_length": len(self.password),
            "uses_encrypted_password": len(self.password) >= 200,
        }

        # Add helpful message for BE3600 users
        if not diag["authenticated"] and diag["password_length"] < 200:
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

    def logout(self):
        """Logout from the router."""
        if self._client:
            try:
                self._client.logout()
            except Exception:
                pass
        self._client = None
