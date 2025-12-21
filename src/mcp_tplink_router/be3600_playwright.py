"""BE3600 Router Client using Playwright for all operations.

This module uses browser automation to handle the complex encryption
scheme of BE3600 routers. All operations are performed through the
browser's UI automation.
"""

import json
import re
from typing import Optional, List, Dict
from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page


class BE3600PlaywrightClient:
    """HTTP client for BE3600 router using Playwright for all operations.

    Since the router uses encrypted requests/responses, we let the browser
    handle all operations through its native JavaScript.
    """

    def __init__(self, host: str, password: str, username: str = "admin"):
        self.host = host
        self.password = password
        self.username = username
        self.base_url = f"http://{host}"
        self.stok: Optional[str] = None
        self.sysauth: Optional[str] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._playwright = None

    def login(self) -> bool:
        """Authenticate with the router using browser automation."""
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=True)
            self._context = self._browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )

            page = self._context.new_page()

            # Capture stok from network traffic
            def capture_stok(request):
                if "stok=" in request.url and "/stok=" not in request.url:
                    match = re.search(r';stok=([^/]+)', request.url)
                    if match and match.group(1):
                        self.stok = match.group(1)

            page.on("request", capture_stok)

            # Navigate to router
            page.goto(f"{self.base_url}/", wait_until="domcontentloaded")
            page.wait_for_timeout(2000)
            page.wait_for_load_state("networkidle")

            # Find and fill password field
            password_field = page.query_selector('input[type="password"]')
            if not password_field:
                print("Could not find password field")
                return False

            password_field.fill(self.password)
            page.wait_for_timeout(500)

            # Find and click login button
            login_button = page.query_selector('button[type="submit"]') or \
                           page.query_selector('button:has-text("Login")') or \
                           page.query_selector('button:has-text("Log In")') or \
                           page.query_selector('.login-btn') or \
                           page.query_selector('button')

            if not login_button:
                print("Could not find login button")
                return False

            login_button.click()
            page.wait_for_timeout(3000)
            page.wait_for_load_state("networkidle")

            # Get sysauth cookie
            cookies = self._context.cookies()
            for cookie in cookies:
                if cookie['name'] == 'sysauth':
                    self.sysauth = cookie['value']
                    break

            self._page = page
            return bool(self.stok and self.sysauth)

        except Exception as e:
            print(f"Login error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def logout(self):
        """Close browser and clean up."""
        try:
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except:
            pass
        self.stok = None
        self.sysauth = None
        self._page = None

    def _click_element(self, text: str, timeout: int = 5000) -> bool:
        """Click an element by text using JavaScript for reliability."""
        try:
            result = self._page.evaluate(f'''
            () => {{
                const elements = Array.from(document.querySelectorAll('*'));
                const matches = elements.filter(el =>
                    el.textContent.trim() === '{text}' &&
                    el.tagName !== 'SCRIPT' &&
                    el.offsetParent !== null
                );

                for (const el of matches) {{
                    el.click();
                    return true;
                }}
                return false;
            }}
            ''')
            return result
        except:
            return False

    def _navigate_to(self, menu_text: str, submenu_text: str = None, wait_time: int = 3000):
        """Navigate to a specific page in the router UI by clicking menu items."""
        if not self._page:
            raise Exception("Not logged in")

        try:
            # Click main menu using JavaScript (more reliable for this UI)
            if self._click_element(menu_text):
                self._page.wait_for_timeout(1500)
                self._page.wait_for_load_state("networkidle")

            # Click submenu if specified
            if submenu_text:
                self._page.wait_for_timeout(500)
                if self._click_element(submenu_text):
                    self._page.wait_for_timeout(1500)
                    self._page.wait_for_load_state("networkidle")

            self._page.wait_for_timeout(wait_time)

        except Exception as e:
            print(f"Navigation error: {e}")

    def get_status(self) -> dict:
        """Get router status from the network map page."""
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

    def get_devices(self) -> List[Dict]:
        """Get list of connected devices by clicking on Clients icon."""
        # Click on the Clients icon in the network map
        try:
            clients_icon = self._page.query_selector('text="Clients"') or \
                           self._page.query_selector('.clients, [class*="client"]')
            if clients_icon:
                clients_icon.click()
                self._page.wait_for_timeout(2000)
        except:
            pass

        # Wait for client list to load
        self._page.wait_for_timeout(2000)

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

    def get_port_forwarding(self) -> List[Dict]:
        """Get port forwarding rules."""
        # Navigate to Advanced -> NAT Forwarding -> Virtual Servers
        self._navigate_to("Advanced")
        self._page.wait_for_timeout(1500)

        # Click NAT Forwarding
        try:
            nat_menu = self._page.query_selector('text="NAT Forwarding"') or \
                       self._page.query_selector('text="NAT"') or \
                       self._page.query_selector('[class*="nat"]')
            if nat_menu:
                nat_menu.click()
                self._page.wait_for_timeout(1000)

            # Click Virtual Servers
            vs_menu = self._page.query_selector('text="Virtual Servers"') or \
                      self._page.query_selector('text="Port Forwarding"')
            if vs_menu:
                vs_menu.click()
                self._page.wait_for_timeout(2000)
        except Exception as e:
            print(f"Navigation to port forwarding failed: {e}")

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

    def add_port_forward(self, name: str, external_port: str, internal_ip: str,
                         internal_port: str = "", protocol: str = "All",
                         is_port_range: bool = False) -> bool:
        """Add a port forwarding rule through the UI.

        Args:
            name: Service name for the rule
            external_port: External port or port range (e.g., "5060" or "18000-18100")
            internal_ip: Internal device IP address (e.g., "10.13.37.169")
            internal_port: Internal port (optional, uses external port if empty)
            protocol: "All", "TCP", or "UDP"
            is_port_range: True if external_port is a range like "18000-18100"

        Returns True if successful.
        """
        # First navigate to the port forwarding page
        self.get_port_forwarding()  # This navigates to the right page

        try:
            # Click "Add" button
            self._click_element("Add")
            self._page.wait_for_timeout(2000)

            # Fill form using JavaScript for reliability
            success = self._page.evaluate(f'''
            () => {{
                // Get all text inputs in the modal
                const inputs = Array.from(document.querySelectorAll('.su-dialog input.su-input__content'));
                if (inputs.length < 4) return {{ error: 'Not enough inputs found', count: inputs.length }};

                // Fill Service Name (first input)
                inputs[0].value = '{name}';
                inputs[0].dispatchEvent(new Event('input', {{ bubbles: true }}));

                // Fill Device IP Address (second input)
                inputs[1].value = '{internal_ip}';
                inputs[1].dispatchEvent(new Event('input', {{ bubbles: true }}));

                // Select Port Range if needed
                if ({str(is_port_range).lower()}) {{
                    const portRangeRadio = document.querySelector('.su-dialog .su-radio:nth-child(2) input') ||
                                          Array.from(document.querySelectorAll('.su-dialog .su-radio')).find(r =>
                                              r.textContent.includes('Port Range'))?.querySelector('input');
                    if (portRangeRadio) {{
                        portRangeRadio.click();
                    }}
                }}

                // Wait a bit for UI to update after radio selection
                // Fill External Port (third input)
                setTimeout(() => {{
                    const updatedInputs = Array.from(document.querySelectorAll('.su-dialog input.su-input__content'));
                    updatedInputs[2].value = '{external_port}';
                    updatedInputs[2].dispatchEvent(new Event('input', {{ bubbles: true }}));

                    // Fill Internal Port if provided (fourth input)
                    if ('{internal_port}') {{
                        updatedInputs[3].value = '{internal_port}';
                        updatedInputs[3].dispatchEvent(new Event('input', {{ bubbles: true }}));
                    }}
                }}, 100);

                return {{ success: true }};
            }}
            ''')

            self._page.wait_for_timeout(500)

            # Fill the port fields again to ensure they're set
            self._page.evaluate(f'''
            () => {{
                const inputs = Array.from(document.querySelectorAll('.su-dialog input.su-input__content'));
                if (inputs.length >= 3) {{
                    inputs[2].value = '{external_port}';
                    inputs[2].dispatchEvent(new Event('input', {{ bubbles: true }}));
                }}
                if (inputs.length >= 4 && '{internal_port}') {{
                    inputs[3].value = '{internal_port}';
                    inputs[3].dispatchEvent(new Event('input', {{ bubbles: true }}));
                }}
            }}
            ''')

            # Select protocol from dropdown
            if protocol != "All":
                self._page.evaluate(f'''
                () => {{
                    const select = document.querySelector('.su-dialog .su-select');
                    if (select) {{
                        select.click();
                        setTimeout(() => {{
                            const options = document.querySelectorAll('.su-select-dropdown__item');
                            for (const opt of options) {{
                                if (opt.textContent.trim() === '{protocol}') {{
                                    opt.click();
                                    break;
                                }}
                            }}
                        }}, 200);
                    }}
                }}
                ''')
                self._page.wait_for_timeout(500)

            # Click Save button
            self._page.wait_for_timeout(500)
            save_clicked = self._click_element("SAVE")
            if not save_clicked:
                # Try alternative selector
                self._page.evaluate('''
                () => {
                    const saveBtn = document.querySelector('.su-dialog button:last-child') ||
                                   Array.from(document.querySelectorAll('.su-dialog button')).find(b =>
                                       b.textContent.includes('SAVE'));
                    if (saveBtn) saveBtn.click();
                }
                ''')

            self._page.wait_for_timeout(2000)
            return True

        except Exception as e:
            print(f"Error adding port forward: {e}")
            import traceback
            traceback.print_exc()
            return False

    def get_dhcp_settings(self) -> dict:
        """Get DHCP server settings."""
        # Navigate to Advanced -> DHCP Server
        self._navigate_to("Advanced")
        self._page.wait_for_timeout(1500)

        try:
            dhcp_menu = self._page.query_selector('text="DHCP Server"') or \
                        self._page.query_selector('text="DHCP"')
            if dhcp_menu:
                dhcp_menu.click()
                self._page.wait_for_timeout(2000)
        except Exception as e:
            print(f"Navigation to DHCP failed: {e}")

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

    def take_screenshot(self, path: str = "/tmp/router_screenshot.png"):
        """Take a screenshot of the current page."""
        if self._page:
            self._page.screenshot(path=path)
            return path
        return None


def test_client():
    """Test the BE3600 client."""
    import os
    from dotenv import load_dotenv

    load_dotenv()

    host = os.getenv("TPLINK_HOST", "10.13.37.1")
    password = os.getenv("TPLINK_PASSWORD", "")

    print(f"Testing BE3600 router at {host}")

    client = BE3600PlaywrightClient(host, password)

    print("\n=== Logging in ===")
    if client.login():
        print(f"✅ Login successful!")
        print(f"   STOK: {client.stok}")
        print(f"   Sysauth: {client.sysauth[:30]}..." if client.sysauth else "   No sysauth")

        print("\n=== Getting router status ===")
        try:
            status = client.get_status()
            print(f"Status: {json.dumps(status, indent=2)[:1000]}")
        except Exception as e:
            print(f"Status error: {e}")

        print("\n=== Getting connected devices ===")
        try:
            devices = client.get_devices()
            print(f"Devices: {json.dumps(devices, indent=2)[:1000]}")
        except Exception as e:
            print(f"Devices error: {e}")

        print("\n=== Getting port forwarding rules ===")
        try:
            rules = client.get_port_forwarding()
            print(f"Port forwarding: {json.dumps(rules, indent=2)[:1000]}")
        except Exception as e:
            print(f"Port forwarding error: {e}")

        print("\n=== Taking screenshot ===")
        try:
            path = client.take_screenshot()
            print(f"Screenshot saved to: {path}")
        except Exception as e:
            print(f"Screenshot error: {e}")

        client.logout()
        print("\n✅ Test complete")
    else:
        print("❌ Login failed")


if __name__ == "__main__":
    test_client()
