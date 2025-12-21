# TP-Link BE3600 Router Automation

A Python library for automating TP-Link BE3600 (and similar) routers using Playwright browser automation. This tool bypasses the router's complex encryption scheme by controlling the web interface directly.

## Why This Exists

TP-Link BE3600 routers use a sophisticated encryption scheme for their API:
- RSA encryption for key exchange
- AES-GCM for request/response encryption
- Complex signature generation with sequence numbers

Rather than reverse-engineering the entire encryption protocol (which changes between firmware versions), this library uses **Playwright browser automation** to interact with the router's web UI directly. The browser handles all the encryption natively.

## Features

- **Login/Authentication** - Automated browser-based login
- **Port Forwarding Management** - List, add, and manage port forwarding rules
- **DHCP Settings** - View DHCP configuration
- **Network Status** - Get router status and connected devices
- **Screenshot Capture** - Debug by capturing UI screenshots
- **MCP Server** - Model Context Protocol server for AI integration

## Supported Routers

- TP-Link BE3600 (Dual-Band Wi-Fi 7) - **Primary target**
- May work with other TP-Link routers using similar web interfaces

## Installation

### Prerequisites

- Python 3.10+
- Chromium browser (installed automatically by Playwright)

### Install from Source

```bash
# Clone the repository
git clone https://github.com/consigcody94/mcp-tplink-router.git
cd mcp-tplink-router

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Install Playwright browsers
playwright install chromium

# On Linux, you may need additional dependencies
sudo apt-get install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2
```

## Quick Start

### 1. Configure Environment

Create a `.env` file:

```env
TPLINK_HOST=192.168.0.1
TPLINK_PASSWORD=your_router_password
TPLINK_USERNAME=admin
```

### 2. Basic Usage

```python
from mcp_tplink_router.be3600_playwright import BE3600PlaywrightClient

# Initialize the client
client = BE3600PlaywrightClient(
    host="192.168.0.1",       # Your router's IP
    password="your_password"   # Router admin password
)

# Login
if client.login():
    print(f"Logged in! STOK: {client.stok}")

    # Get port forwarding rules
    rules = client.get_port_forwarding()
    for rule in rules:
        print(f"{rule['name']}: {rule['external_port']} -> {rule['internal_ip']}:{rule['internal_port']}")

    # Always logout when done
    client.logout()
else:
    print("Login failed")
```

### 3. Adding Port Forwarding Rules

```python
from mcp_tplink_router.be3600_playwright import BE3600PlaywrightClient

client = BE3600PlaywrightClient("192.168.0.1", "your_password")

if client.login():
    # Add a single port forward
    client.add_port_forward(
        name="Web Server",
        external_port="80",
        internal_ip="192.168.0.100",
        internal_port="80",
        protocol="TCP"  # "TCP", "UDP", or "All"
    )

    # Add a port range (e.g., for VoIP/RTP)
    client.add_port_forward(
        name="VoIP RTP",
        external_port="10000-10100",
        internal_ip="192.168.0.50",
        internal_port="10000-10100",
        protocol="UDP",
        is_port_range=True
    )

    client.logout()
```

## API Reference

### BE3600PlaywrightClient

#### Constructor

```python
BE3600PlaywrightClient(host: str, password: str, username: str = "admin")
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `host` | str | Router IP address (e.g., "192.168.0.1") |
| `password` | str | Admin password |
| `username` | str | Admin username (default: "admin") |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `login()` | `bool` | Authenticate with the router |
| `logout()` | `None` | Close browser and clean up |
| `get_port_forwarding()` | `List[Dict]` | Get all port forwarding rules |
| `add_port_forward(...)` | `bool` | Add a new port forwarding rule |
| `get_status()` | `dict` | Get router status |
| `get_devices()` | `List[Dict]` | Get connected devices |
| `get_dhcp_settings()` | `dict` | Get DHCP configuration |
| `take_screenshot(path)` | `str` | Capture screenshot for debugging |

#### Port Forwarding Rule Format

```python
{
    "name": "Web Server",
    "internal_ip": "192.168.0.100",
    "external_port": "80",
    "internal_port": "80",
    "protocol": "TCP",
    "status": ""
}
```

## Complete Example: FreePBX/VoIP Setup

```python
#!/usr/bin/env python3
"""Configure port forwarding for FreePBX/VoIP."""

import os
from dotenv import load_dotenv
from mcp_tplink_router.be3600_playwright import BE3600PlaywrightClient

load_dotenv()

ROUTER_HOST = os.getenv("TPLINK_HOST", "192.168.0.1")
ROUTER_PASSWORD = os.getenv("TPLINK_PASSWORD")
FREEPBX_IP = "192.168.0.169"

def main():
    client = BE3600PlaywrightClient(ROUTER_HOST, ROUTER_PASSWORD)

    if not client.login():
        print("Failed to login to router")
        return

    try:
        # Add SIP signaling port (UDP 5060)
        print("Adding SIP port forwarding...")
        client.add_port_forward(
            name="FreePBX SIP",
            external_port="5060",
            internal_ip=FREEPBX_IP,
            internal_port="5060",
            protocol="UDP"
        )

        # Add RTP media ports (UDP 10000-20000)
        print("Adding RTP port range...")
        client.add_port_forward(
            name="FreePBX RTP",
            external_port="10000-20000",
            internal_ip=FREEPBX_IP,
            internal_port="10000-20000",
            protocol="UDP",
            is_port_range=True
        )

        # Verify rules were added
        print("\nCurrent port forwarding rules:")
        rules = client.get_port_forwarding()
        for rule in rules:
            print(f"  {rule['name']}: {rule['external_port']} -> "
                  f"{rule['internal_ip']}:{rule['internal_port']} ({rule['protocol']})")

    finally:
        client.logout()

if __name__ == "__main__":
    main()
```

## MCP Server Usage (AI Integration)

This package includes an MCP (Model Context Protocol) server for use with Claude Desktop and other AI assistants.

### Configure Claude Desktop

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tplink-router": {
      "command": "/path/to/mcp-tplink-router/venv/bin/python",
      "args": ["-m", "mcp_tplink_router"],
      "env": {
        "TPLINK_HOST": "192.168.0.1",
        "TPLINK_USERNAME": "admin",
        "TPLINK_PASSWORD": "your_password"
      }
    }
  }
}
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `router_status` | Get router status including WAN info |
| `list_connected_devices` | List all connected devices |
| `list_port_forwarding` | List all port forwarding rules |
| `add_port_forwarding` | Add a new port forwarding rule |
| `router_diagnostics` | Get diagnostic information |

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Python Script                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  BE3600PlaywrightClient                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  1. Launch headless Chromium via Playwright          │   │
│  │  2. Navigate to router web interface                 │   │
│  │  3. Fill login form, click submit                    │   │
│  │  4. Capture STOK from network requests               │   │
│  │  5. Store sysauth cookie                             │   │
│  │  6. Use JS injection for Vue.js UI interaction       │   │
│  │  7. Parse page content for data extraction           │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 TP-Link BE3600 Router                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Vue.js Web Interface                                │   │
│  │  - RSA/AES-GCM encrypted API                        │   │
│  │  - Handled natively by browser JavaScript           │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Key Insight**: Instead of reverse-engineering the complex encryption, we let the browser's JavaScript handle it. Playwright automates the browser, and we extract data from the rendered DOM.

## Troubleshooting

### "Could not find password field"
- The router's web interface may not have loaded completely
- Increase wait times in the client
- Verify router is accessible at the specified IP

### "Login failed"
- Verify your password is correct
- Ensure no other admin sessions are active
- Try accessing the router web interface manually first

### Chromium crashes on Linux
Install required dependencies:
```bash
sudo apt-get install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2
```

### Debug with Screenshots
```python
client = BE3600PlaywrightClient(host, password)
if client.login():
    client.get_port_forwarding()
    client.take_screenshot("/tmp/debug.png")
    print("Screenshot saved!")
    client.logout()
```

## Project Structure

```
mcp-tplink-router/
├── src/
│   └── mcp_tplink_router/
│       ├── __init__.py
│       ├── be3600_playwright.py  # Main Playwright-based client
│       ├── be3600_crypto.py      # Direct API client (experimental)
│       ├── server.py             # MCP server implementation
│       └── tplink_client.py      # Generic TP-Link client
├── examples/
│   ├── list_rules.py
│   ├── add_port_forward.py
│   └── freepbx_setup.py
├── pyproject.toml
├── README.md
├── LICENSE
└── .env.example
```

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

```bash
# Development setup
git clone https://github.com/consigcody94/mcp-tplink-router.git
cd mcp-tplink-router
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
playwright install chromium
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for personal use only. Use responsibly and in accordance with your router's terms of service. The authors are not responsible for any misuse or damage caused by this tool.

## Acknowledgments

- [Playwright](https://playwright.dev/) for browser automation
- [tplinkrouterc6u](https://github.com/AlexandrErohin/TP-Link-Archer-C6U) for encryption research
