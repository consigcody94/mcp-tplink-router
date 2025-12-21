#!/usr/bin/env python3
"""Add a single port forwarding rule to a TP-Link BE3600 router.

Usage:
    python add_port_forward.py "Web Server" 80 192.168.0.100 80 TCP
    python add_port_forward.py "SSH" 22 192.168.0.50 22 TCP
    python add_port_forward.py "Game Server" 27015 192.168.0.200 27015 UDP
"""

import os
import sys
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_tplink_router.be3600_playwright import BE3600PlaywrightClient

load_dotenv()

def main():
    # Parse command line arguments
    if len(sys.argv) < 5:
        print("Usage: python add_port_forward.py <name> <external_port> <internal_ip> <internal_port> [protocol]")
        print()
        print("Arguments:")
        print("  name          - Service name for the rule")
        print("  external_port - External port number or range (e.g., 80 or 10000-10100)")
        print("  internal_ip   - Internal device IP address")
        print("  internal_port - Internal port number or range")
        print("  protocol      - TCP, UDP, or All (default: All)")
        print()
        print("Examples:")
        print("  python add_port_forward.py \"Web Server\" 80 192.168.0.100 80 TCP")
        print("  python add_port_forward.py \"Game\" 27015 192.168.0.50 27015 UDP")
        print("  python add_port_forward.py \"VoIP\" 10000-10100 192.168.0.75 10000-10100 UDP")
        return

    name = sys.argv[1]
    external_port = sys.argv[2]
    internal_ip = sys.argv[3]
    internal_port = sys.argv[4]
    protocol = sys.argv[5] if len(sys.argv) > 5 else "All"

    # Detect if this is a port range
    is_port_range = "-" in external_port

    # Get router configuration from environment
    host = os.getenv("TPLINK_HOST", "192.168.0.1")
    password = os.getenv("TPLINK_PASSWORD")

    if not password:
        print("Error: TPLINK_PASSWORD not set")
        return

    print(f"Connecting to router at {host}...")

    client = BE3600PlaywrightClient(host, password)

    if not client.login():
        print("Failed to login to router")
        return

    try:
        print(f"\nAdding port forwarding rule:")
        print(f"  Name: {name}")
        print(f"  External Port: {external_port}")
        print(f"  Internal IP: {internal_ip}")
        print(f"  Internal Port: {internal_port}")
        print(f"  Protocol: {protocol}")
        print(f"  Port Range: {is_port_range}")

        success = client.add_port_forward(
            name=name,
            external_port=external_port,
            internal_ip=internal_ip,
            internal_port=internal_port,
            protocol=protocol,
            is_port_range=is_port_range
        )

        if success:
            print("\n✓ Port forwarding rule added successfully!")
        else:
            print("\n✗ Failed to add port forwarding rule")

        # Verify the rule was added
        print("\nCurrent rules:")
        rules = client.get_port_forwarding()
        for rule in rules:
            if rule.get('name') == name:
                print(f"  ✓ {rule}")
                break
        else:
            print("  Rule not found in list (may take a moment to appear)")

    finally:
        client.logout()

if __name__ == "__main__":
    main()
