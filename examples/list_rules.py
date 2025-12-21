#!/usr/bin/env python3
"""List all port forwarding rules from a TP-Link BE3600 router."""

import os
import json
from dotenv import load_dotenv

# Add parent directory to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_tplink_router.be3600_playwright import BE3600PlaywrightClient

# Load environment variables from .env file
load_dotenv()

def main():
    # Get router configuration from environment
    host = os.getenv("TPLINK_HOST", "192.168.0.1")
    password = os.getenv("TPLINK_PASSWORD")

    if not password:
        print("Error: TPLINK_PASSWORD not set in environment or .env file")
        print("Create a .env file with:")
        print("  TPLINK_HOST=192.168.0.1")
        print("  TPLINK_PASSWORD=your_password")
        return

    print(f"Connecting to router at {host}...")

    # Create client and login
    client = BE3600PlaywrightClient(host, password)

    if not client.login():
        print("Failed to login to router")
        return

    try:
        # Get port forwarding rules
        print("\nPort Forwarding Rules:")
        print("-" * 80)

        rules = client.get_port_forwarding()

        if not rules:
            print("No port forwarding rules found")
        else:
            print(f"{'Name':<20} {'Internal IP':<16} {'Ext Port':<12} {'Int Port':<12} {'Protocol':<10}")
            print("-" * 80)

            for rule in rules:
                print(f"{rule.get('name', 'N/A'):<20} "
                      f"{rule.get('internal_ip', 'N/A'):<16} "
                      f"{rule.get('external_port', 'N/A'):<12} "
                      f"{rule.get('internal_port', 'N/A'):<12} "
                      f"{rule.get('protocol', 'N/A'):<10}")

        # Also print as JSON for debugging
        print("\n\nRaw JSON output:")
        print(json.dumps(rules, indent=2))

    finally:
        client.logout()
        print("\nDisconnected from router")

if __name__ == "__main__":
    main()
