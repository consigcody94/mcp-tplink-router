"""BE3600 Router Client using Playwright for all operations.

This module uses browser automation to handle the complex encryption
scheme of BE3600 routers. All operations are performed through the
browser's UI automation.
"""

from __future__ import annotations

import json
import logging
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional

from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    sync_playwright,
    TimeoutError as PlaywrightTimeoutError,
    Error as PlaywrightError,
)

# Configure module logger
logger = logging.getLogger(__name__)


@dataclass
class TimeoutConfig:
    """Configuration for various timeout values in milliseconds."""

    page_load: int = 2000
    login_wait: int = 3000
    navigation: int = 1500
    short_wait: int = 500
    element_click: int = 5000
    network_idle: int = 3000

    @classmethod
    def from_dict(cls, config: Dict[str, int]) -> TimeoutConfig:
        """Create TimeoutConfig from a dictionary."""
        return cls(**{k: v for k, v in config.items() if hasattr(cls, k)})


@dataclass
class DeviceInfo:
    """Information about a connected device."""

    name: Optional[str] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    raw_text: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class PortForwardingRule:
    """A port forwarding rule configuration."""

    name: Optional[str] = None
    internal_ip: Optional[str] = None
    external_port: Optional[str] = None
    internal_port: Optional[str] = None
    protocol: Optional[str] = None
    status: Optional[str] = None
    raw_text: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


class BE3600PlaywrightClient:
    """HTTP client for BE3600 router using Playwright for all operations.

    Since the router uses encrypted requests/responses, we let the browser
    handle all operations through its native JavaScript.

    Attributes:
        host: The router's IP address or hostname.
        password: The router's admin password.
        username: The router's admin username (default: 'admin').
        stok: Session token obtained after login.
        sysauth: System authentication cookie value.

    Example:
        >>> with BE3600PlaywrightClient('192.168.0.1', 'password') as client:
        ...     if client.login():
        ...         devices = client.get_devices()
        ...         print(f"Found {len(devices)} devices")
    """

    def __init__(
        self,
        host: str,
        password: str,
        username: str = "admin",
        *,
        headless: bool = True,
        ignore_https_errors: bool = True,
        timeouts: Optional[TimeoutConfig] = None,
    ) -> None:
        """Initialize the BE3600 Playwright client.

        Args:
            host: Router IP address or hostname.
            password: Router admin password.
            username: Router admin username.
            headless: Run browser in headless mode.
            ignore_https_errors: Ignore HTTPS certificate errors.
                Note: This is required for routers with self-signed certificates
                but reduces security. Use only on trusted networks.
            timeouts: Custom timeout configuration.
        """
        self.host = host
        self.password = password
        self.username = username
        self.base_url = f"http://{host}"
        self.stok: Optional[str] = None
        self.sysauth: Optional[str] = None

        self._headless = headless
        self._ignore_https_errors = ignore_https_errors
        self._timeouts = timeouts or TimeoutConfig()

        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._playwright: Optional[Playwright] = None
        self._is_logged_in = False

    def __enter__(self) -> BE3600PlaywrightClient:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit - ensures cleanup."""
        self.close()

    def close(self) -> None:
        """Close all browser resources and clean up session."""
        try:
            if self._page and not self._page.is_closed():
                self._page.close()
        except PlaywrightError as e:
            logger.debug("Error closing page: %s", e)

        try:
            if self._context:
                self._context.close()
        except PlaywrightError as e:
            logger.debug("Error closing context: %s", e)

        try:
            if self._browser:
                self._browser.close()
        except PlaywrightError as e:
            logger.debug("Error closing browser: %s", e)

        try:
            if self._playwright:
                self._playwright.stop()
        except PlaywrightError as e:
            logger.debug("Error stopping playwright: %s", e)

        self.stok = None
        self.sysauth = None
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None
        self._is_logged_in = False

    def logout(self) -> None:
        """Close browser and clean up. Alias for close()."""
        self.close()

    def login(self) -> bool:
        """Authenticate with the router using browser automation.

        Returns:
            True if login was successful, False otherwise.

        Raises:
            PlaywrightError: If browser automation fails critically.
        """
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=self._headless)
            self._context = self._browser.new_context(
                ignore_https_errors=self._ignore_https_errors,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )

            page = self._context.new_page()

            # Capture stok from network traffic
            def capture_stok(request: Any) -> None:
                if "stok=" in request.url and "/stok=" not in request.url:
                    match = re.search(r';stok=([^/]+)', request.url)
                    if match and match.group(1):
                        self.stok = match.group(1)
                        logger.debug("Captured STOK from request")

            page.on("request", capture_stok)

            # Navigate to router
            logger.info("Navigating to router at %s", self.base_url)
            page.goto(f"{self.base_url}/", wait_until="domcontentloaded")
            page.wait_for_timeout(self._timeouts.page_load)
            page.wait_for_load_state("networkidle")

            # Find and fill password field
            password_field = page.query_selector('input[type="password"]')
            if not password_field:
                logger.error("Could not find password field on login page")
                return False

            password_field.fill(self.password)
            page.wait_for_timeout(self._timeouts.short_wait)

            # Find and click login button
            login_button = (
                page.query_selector('button[type="submit"]') or
                page.query_selector('button:has-text("Login")') or
                page.query_selector('button:has-text("Log In")') or
                page.query_selector('.login-btn') or
                page.query_selector('button')
            )

            if not login_button:
                logger.error("Could not find login button on login page")
                return False

            login_button.click()
            page.wait_for_timeout(self._timeouts.login_wait)
            page.wait_for_load_state("networkidle")

            # Get sysauth cookie
            cookies = self._context.cookies()
            for cookie in cookies:
                if cookie['name'] == 'sysauth':
                    self.sysauth = cookie['value']
                    logger.debug("Captured sysauth cookie")
                    break

            self._page = page
            self._is_logged_in = bool(self.stok and self.sysauth)

            if self._is_logged_in:
                logger.info("Login successful")
            else:
                logger.warning("Login incomplete - stok=%s, sysauth=%s",
                               bool(self.stok), bool(self.sysauth))

            return self._is_logged_in

        except PlaywrightTimeoutError as e:
            logger.error("Login timeout: %s", e)
            return False
        except PlaywrightError as e:
            logger.error("Login error: %s", e)
            return False
        except Exception as e:
            logger.exception("Unexpected login error: %s", e)
            return False

    def _escape_js_string(self, value: str) -> str:
        """Safely escape a string for use in JavaScript.

        Args:
            value: The string to escape.

        Returns:
            The escaped string safe for JavaScript string literals.
        """
        # Escape backslashes first, then other special characters
        escaped = value.replace('\\', '\\\\')
        escaped = escaped.replace("'", "\\'")
        escaped = escaped.replace('"', '\\"')
        escaped = escaped.replace('\n', '\\n')
        escaped = escaped.replace('\r', '\\r')
        escaped = escaped.replace('\t', '\\t')
        escaped = escaped.replace('</', '<\\/')  # Prevent script injection
        return escaped

    def _click_element(self, text: str, timeout: Optional[int] = None) -> bool:
        """Click an element by text using JavaScript for reliability.

        Args:
            text: The exact text content of the element to click.
            timeout: Optional timeout in milliseconds.

        Returns:
            True if element was found and clicked, False otherwise.
        """
        if not self._page:
            logger.warning("Cannot click element - not logged in")
            return False

        timeout = timeout or self._timeouts.element_click
        safe_text = self._escape_js_string(text)

        try:
            result = self._page.evaluate(
                """(searchText) => {
                    const elements = Array.from(document.querySelectorAll('*'));
                    const matches = elements.filter(el =>
                        el.textContent.trim() === searchText &&
                        el.tagName !== 'SCRIPT' &&
                        el.offsetParent !== null
                    );

                    for (const el of matches) {
                        el.click();
                        return true;
                    }
                    return false;
                }""",
                safe_text
            )
            return bool(result)
        except PlaywrightTimeoutError:
            logger.debug("Timeout clicking element with text: %s", text)
            return False
        except PlaywrightError as e:
            logger.debug("Error clicking element with text '%s': %s", text, e)
            return False

    def _navigate_to(
        self,
        menu_text: str,
        submenu_text: Optional[str] = None,
        wait_time: Optional[int] = None
    ) -> None:
        """Navigate to a specific page in the router UI by clicking menu items.

        Args:
            menu_text: The main menu item text to click.
            submenu_text: Optional submenu item text to click.
            wait_time: Optional wait time after navigation in milliseconds.

        Raises:
            RuntimeError: If not logged in.
        """
        if not self._page:
            raise RuntimeError("Not logged in - call login() first")

        wait_time = wait_time or self._timeouts.navigation

        try:
            # Click main menu using JavaScript (more reliable for this UI)
            if self._click_element(menu_text):
                self._page.wait_for_timeout(self._timeouts.navigation)
                self._page.wait_for_load_state("networkidle")
                logger.debug("Clicked menu: %s", menu_text)

            # Click submenu if specified
            if submenu_text:
                self._page.wait_for_timeout(self._timeouts.short_wait)
                if self._click_element(submenu_text):
                    self._page.wait_for_timeout(self._timeouts.navigation)
                    self._page.wait_for_load_state("networkidle")
                    logger.debug("Clicked submenu: %s", submenu_text)

            self._page.wait_for_timeout(wait_time)

        except PlaywrightTimeoutError as e:
            logger.warning("Navigation timeout for menu '%s': %s", menu_text, e)
        except PlaywrightError as e:
            logger.warning("Navigation error for menu '%s': %s", menu_text, e)

    def _ensure_logged_in(self) -> None:
        """Ensure the client is logged in.

        Raises:
            RuntimeError: If not logged in.
        """
        if not self._page or not self._is_logged_in:
            raise RuntimeError("Not logged in - call login() first")

    def get_status(self) -> Dict[str, Any]:
        """Get router status from the network map page.

        Returns:
            Dictionary containing router status information.

        Raises:
            RuntimeError: If not logged in.
        """
        self._ensure_logged_in()
        self._navigate_to("Network Map")

        # Extract data from the page
        data = self._page.evaluate("""
        () => {
            const result = {};

            // Try to get internet status
            const internetStatus = document.querySelector('.internet-status, .wan-status');
            if (internetStatus) {
                result.internet_status = internetStatus.textContent.trim();
            }

            // Try to get connected devices count
            const deviceCount = document.querySelector('.device-count, .client-count');
            if (deviceCount) {
                result.device_count = deviceCount.textContent.trim();
            }

            // Get router model from title or header
            const title = document.title || '';
            result.title = title;

            // Get all text content for debugging
            const mainContent = document.querySelector('#app, .main-content, main');
            if (mainContent) {
                result.page_text = mainContent.innerText.substring(0, 2000);
            }

            return result;
        }
        """)

        return data

    def get_devices(self) -> List[Dict[str, Optional[str]]]:
        """Get list of connected devices by clicking on Clients icon.

        Returns:
            List of device dictionaries with name, ip, mac, etc.

        Raises:
            RuntimeError: If not logged in.
        """
        self._ensure_logged_in()

        # Click on the Clients icon in the network map
        try:
            clients_icon = (
                self._page.query_selector('text="Clients"') or
                self._page.query_selector('.clients, [class*="client"]')
            )
            if clients_icon:
                clients_icon.click()
                self._page.wait_for_timeout(self._timeouts.page_load)
        except PlaywrightTimeoutError:
            logger.debug("Timeout clicking clients icon")
        except PlaywrightError as e:
            logger.debug("Error clicking clients icon: %s", e)

        # Wait for client list to load
        self._page.wait_for_timeout(self._timeouts.page_load)

        # Extract device data
        devices = self._page.evaluate("""
        () => {
            const devices = [];

            // Try different selectors for device list
            const rows = document.querySelectorAll(
                '.client-item, .device-row, tr[data-device], .device-card'
            );

            rows.forEach(row => {
                const device = {};

                // Try to find name
                const nameEl = row.querySelector('.device-name, .client-name, td:first-child');
                if (nameEl) device.name = nameEl.textContent.trim();

                // Try to find IP
                const ipEl = row.querySelector('.device-ip, .client-ip, [class*="ip"]');
                if (ipEl) device.ip = ipEl.textContent.trim();

                // Try to find MAC
                const macEl = row.querySelector('.device-mac, .client-mac, [class*="mac"]');
                if (macEl) device.mac = macEl.textContent.trim();

                if (Object.keys(device).length > 0) {
                    devices.push(device);
                }
            });

            // If no devices found, try to get raw text
            if (devices.length === 0) {
                const content = document.querySelector('#app, .main-content');
                if (content) {
                    return [{raw_text: content.innerText.substring(0, 3000)}];
                }
            }

            return devices;
        }
        """)

        return devices

    def get_port_forwarding(self) -> List[Dict[str, Optional[str]]]:
        """Get port forwarding rules.

        Returns:
            List of port forwarding rule dictionaries.

        Raises:
            RuntimeError: If not logged in.
        """
        self._ensure_logged_in()

        # Navigate to Advanced -> NAT Forwarding -> Virtual Servers
        self._navigate_to("Advanced")
        self._page.wait_for_timeout(self._timeouts.navigation)

        # Click NAT Forwarding
        try:
            nat_menu = (
                self._page.query_selector('text="NAT Forwarding"') or
                self._page.query_selector('text="NAT"') or
                self._page.query_selector('[class*="nat"]')
            )
            if nat_menu:
                nat_menu.click()
                self._page.wait_for_timeout(self._timeouts.short_wait * 2)

            # Click Virtual Servers
            vs_menu = (
                self._page.query_selector('text="Virtual Servers"') or
                self._page.query_selector('text="Port Forwarding"')
            )
            if vs_menu:
                vs_menu.click()
                self._page.wait_for_timeout(self._timeouts.page_load)
        except PlaywrightTimeoutError as e:
            logger.warning("Timeout navigating to port forwarding: %s", e)
        except PlaywrightError as e:
            logger.warning("Error navigating to port forwarding: %s", e)

        rules = self._page.evaluate("""
        () => {
            const rules = [];

            // Try different selectors for port forwarding list
            const rows = document.querySelectorAll(
                '.rule-item, .forward-row, tr[data-rule], .virtual-server-item, table tbody tr'
            );

            rows.forEach(row => {
                const rule = {};

                // Table columns: Name, Device IP, External Port, Internal Port, Protocol, Status, Modify
                const cells = row.querySelectorAll('td, .cell');
                if (cells.length >= 5) {
                    rule.name = cells[0]?.textContent?.trim();
                    rule.internal_ip = cells[1]?.textContent?.trim();  // Device IP Address
                    rule.external_port = cells[2]?.textContent?.trim();
                    rule.internal_port = cells[3]?.textContent?.trim();
                    rule.protocol = cells[4]?.textContent?.trim();
                    if (cells[5]) rule.status = cells[5]?.textContent?.trim();
                }

                // Skip header rows or empty rows
                if (rule.name === 'Service Name' || !rule.name) {
                    return;
                }

                if (Object.keys(rule).length > 0) {
                    rules.push(rule);
                }
            });

            // If no rules found, get page content
            if (rules.length === 0) {
                const content = document.querySelector('#app, .main-content');
                if (content) {
                    return [{raw_text: content.innerText.substring(0, 3000)}];
                }
            }

            return rules;
        }
        """)

        return rules

    def add_port_forward(
        self,
        name: str,
        external_port: str,
        internal_ip: str,
        internal_port: str = "",
        protocol: str = "All",
        is_port_range: bool = False
    ) -> bool:
        """Add a port forwarding rule through the UI.

        Args:
            name: Service name for the rule.
            external_port: External port or port range (e.g., "5060" or "18000-18100").
            internal_ip: Internal device IP address (e.g., "10.13.37.169").
            internal_port: Internal port (optional, uses external port if empty).
            protocol: "All", "TCP", or "UDP".
            is_port_range: True if external_port is a range like "18000-18100".

        Returns:
            True if successful, False otherwise.

        Raises:
            RuntimeError: If not logged in.
        """
        self._ensure_logged_in()

        # First navigate to the port forwarding page
        self.get_port_forwarding()  # This navigates to the right page

        # Escape all user inputs for safe JavaScript injection
        safe_name = self._escape_js_string(name)
        safe_internal_ip = self._escape_js_string(internal_ip)
        safe_external_port = self._escape_js_string(external_port)
        safe_internal_port = self._escape_js_string(internal_port)
        safe_protocol = self._escape_js_string(protocol)

        try:
            # Click "Add" button
            self._click_element("Add")
            self._page.wait_for_timeout(self._timeouts.page_load)

            # Fill form using parameterized JavaScript for safety
            success = self._page.evaluate(
                """(params) => {
                    const { name, internalIp, externalPort, internalPort, isPortRange } = params;

                    // Get all text inputs in the modal
                    const inputs = Array.from(document.querySelectorAll('.su-dialog input.su-input__content'));
                    if (inputs.length < 4) return { error: 'Not enough inputs found', count: inputs.length };

                    // Fill Service Name (first input)
                    inputs[0].value = name;
                    inputs[0].dispatchEvent(new Event('input', { bubbles: true }));

                    // Fill Device IP Address (second input)
                    inputs[1].value = internalIp;
                    inputs[1].dispatchEvent(new Event('input', { bubbles: true }));

                    // Select Port Range if needed
                    if (isPortRange) {
                        const portRangeRadio = document.querySelector('.su-dialog .su-radio:nth-child(2) input') ||
                                              Array.from(document.querySelectorAll('.su-dialog .su-radio')).find(r =>
                                                  r.textContent.includes('Port Range'))?.querySelector('input');
                        if (portRangeRadio) {
                            portRangeRadio.click();
                        }
                    }

                    // Fill External Port (third input)
                    inputs[2].value = externalPort;
                    inputs[2].dispatchEvent(new Event('input', { bubbles: true }));

                    // Fill Internal Port if provided (fourth input)
                    if (internalPort) {
                        inputs[3].value = internalPort;
                        inputs[3].dispatchEvent(new Event('input', { bubbles: true }));
                    }

                    return { success: true };
                }""",
                {
                    "name": safe_name,
                    "internalIp": safe_internal_ip,
                    "externalPort": safe_external_port,
                    "internalPort": safe_internal_port,
                    "isPortRange": is_port_range
                }
            )

            self._page.wait_for_timeout(self._timeouts.short_wait)

            # Select protocol from dropdown if not "All"
            if protocol != "All":
                self._page.evaluate(
                    """(protocol) => {
                        const select = document.querySelector('.su-dialog .su-select');
                        if (select) {
                            select.click();
                            setTimeout(() => {
                                const options = document.querySelectorAll('.su-select-dropdown__item');
                                for (const opt of options) {
                                    if (opt.textContent.trim() === protocol) {
                                        opt.click();
                                        break;
                                    }
                                }
                            }, 200);
                        }
                    }""",
                    safe_protocol
                )
                self._page.wait_for_timeout(self._timeouts.short_wait)

            # Click Save button
            self._page.wait_for_timeout(self._timeouts.short_wait)
            save_clicked = self._click_element("SAVE")
            if not save_clicked:
                # Try alternative selector
                self._page.evaluate("""
                () => {
                    const saveBtn = document.querySelector('.su-dialog button:last-child') ||
                                   Array.from(document.querySelectorAll('.su-dialog button')).find(b =>
                                       b.textContent.includes('SAVE'));
                    if (saveBtn) saveBtn.click();
                }
                """)

            self._page.wait_for_timeout(self._timeouts.page_load)
            logger.info("Added port forwarding rule: %s", name)
            return True

        except PlaywrightTimeoutError as e:
            logger.error("Timeout adding port forward '%s': %s", name, e)
            return False
        except PlaywrightError as e:
            logger.error("Error adding port forward '%s': %s", name, e)
            return False

    def get_dhcp_settings(self) -> Dict[str, Any]:
        """Get DHCP server settings.

        Returns:
            Dictionary containing DHCP settings.

        Raises:
            RuntimeError: If not logged in.
        """
        self._ensure_logged_in()

        # Navigate to Advanced -> DHCP Server
        self._navigate_to("Advanced")
        self._page.wait_for_timeout(self._timeouts.navigation)

        try:
            dhcp_menu = (
                self._page.query_selector('text="DHCP Server"') or
                self._page.query_selector('text="DHCP"')
            )
            if dhcp_menu:
                dhcp_menu.click()
                self._page.wait_for_timeout(self._timeouts.page_load)
        except PlaywrightTimeoutError as e:
            logger.warning("Timeout navigating to DHCP: %s", e)
        except PlaywrightError as e:
            logger.warning("Error navigating to DHCP: %s", e)

        data = self._page.evaluate("""
        () => {
            const result = {};

            // Get all input values
            const inputs = document.querySelectorAll('input, select');
            inputs.forEach(input => {
                const name = input.name || input.id || input.placeholder;
                if (name) {
                    result[name] = input.value;
                }
            });

            // Get page text as fallback
            const content = document.querySelector('#app, .main-content');
            if (content) {
                result.page_text = content.innerText.substring(0, 2000);
            }

            return result;
        }
        """)

        return data

    def take_screenshot(self, path: str = "/tmp/router_screenshot.png") -> Optional[str]:
        """Take a screenshot of the current page.

        Args:
            path: File path to save the screenshot.

        Returns:
            The path where the screenshot was saved, or None if failed.
        """
        if self._page:
            try:
                self._page.screenshot(path=path)
                logger.debug("Screenshot saved to %s", path)
                return path
            except PlaywrightError as e:
                logger.error("Failed to take screenshot: %s", e)
                return None
        return None


def test_client() -> None:
    """Test the BE3600 client."""
    import os
    from dotenv import load_dotenv

    # Configure logging for test
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    load_dotenv()

    host = os.getenv("TPLINK_HOST", "10.13.37.1")
    password = os.getenv("TPLINK_PASSWORD", "")

    logger.info("Testing BE3600 router at %s", host)

    with BE3600PlaywrightClient(host, password) as client:
        logger.info("=== Logging in ===")
        if client.login():
            logger.info("Login successful! STOK: %s", client.stok)

            logger.info("=== Getting router status ===")
            try:
                status = client.get_status()
                logger.info("Status: %s", json.dumps(status, indent=2)[:1000])
            except Exception as e:
                logger.error("Status error: %s", e)

            logger.info("=== Getting connected devices ===")
            try:
                devices = client.get_devices()
                logger.info("Devices: %s", json.dumps(devices, indent=2)[:1000])
            except Exception as e:
                logger.error("Devices error: %s", e)

            logger.info("=== Getting port forwarding rules ===")
            try:
                rules = client.get_port_forwarding()
                logger.info("Port forwarding: %s", json.dumps(rules, indent=2)[:1000])
            except Exception as e:
                logger.error("Port forwarding error: %s", e)

            logger.info("=== Taking screenshot ===")
            try:
                path = client.take_screenshot()
                logger.info("Screenshot saved to: %s", path)
            except Exception as e:
                logger.error("Screenshot error: %s", e)

            logger.info("Test complete")
        else:
            logger.error("Login failed")


if __name__ == "__main__":
    test_client()
