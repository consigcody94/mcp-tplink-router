#!/usr/bin/env python3
"""Configure port forwarding for FreePBX/VoIP on a TP-Link BE3600 router.

This script sets up the following port forwarding rules for FreePBX:
- SIP signaling: UDP 5060
- RTP media: UDP 10000-20000 (or customizable range)

Usage:
    # Edit the FREEPBX_IP variable below or set via environment
    export FREEPBX_IP=192.168.0.169
    python freepbx_setup.py
"""

import os
import sys
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcp_tplink_router.be3600_playwright import BE3600PlaywrightClient

load_dotenv()

# Configuration - modify these as needed
FREEPBX_IP = os.getenv("FREEPBX_IP", "192.168.0.169")
SIP_PORT = "5060"
RTP_PORT_START = "10000"
RTP_PORT_END = "20000"

def main():
    # Get router configuration from environment
    host = os.getenv("TPLINK_HOST", "192.168.0.1")
    password = os.getenv("TPLINK_PASSWORD")

    if not password:
        print("Error: TPLINK_PASSWORD not set in environment or .env file")
        return

    print("FreePBX Port Forwarding Setup")
    print("=" * 50)
    print(f"Router: {host}")
    print(f"FreePBX IP: {FREEPBX_IP}")
    print(f"SIP Port: UDP {SIP_PORT}")
    print(f"RTP Ports: UDP {RTP_PORT_START}-{RTP_PORT_END}")
    print("=" * 50)
    print()

    # Confirm before proceeding
    response = input("Proceed with setup? [y/N]: ")
    if response.lower() != 'y':
        print("Aborted")
        return

    print(f"\nConnecting to router at {host}...")

    client = BE3600PlaywrightClient(host, password)

    if not client.login():
        print("Failed to login to router")
        return

    try:
        # Check existing rules
        print("\nChecking existing port forwarding rules...")
        existing_rules = client.get_port_forwarding()
        existing_names = [r.get('name', '') for r in existing_rules]

        # Add SIP port forwarding
        if "FreePBX SIP" in existing_names:
            print("✓ FreePBX SIP rule already exists, skipping...")
        else:
            print("Adding FreePBX SIP port forwarding (UDP 5060)...")
            success = client.add_port_forward(
                name="FreePBX SIP",
                external_port=SIP_PORT,
                internal_ip=FREEPBX_IP,
                internal_port=SIP_PORT,
                protocol="UDP"
            )
            if success:
                print("  ✓ SIP port forwarding added")
            else:
                print("  ✗ Failed to add SIP port forwarding")

        # Add RTP port range
        if "FreePBX RTP" in existing_names:
            print("✓ FreePBX RTP rule already exists, skipping...")
        else:
            rtp_range = f"{RTP_PORT_START}-{RTP_PORT_END}"
            print(f"Adding FreePBX RTP port forwarding (UDP {rtp_range})...")
            success = client.add_port_forward(
                name="FreePBX RTP",
                external_port=rtp_range,
                internal_ip=FREEPBX_IP,
                internal_port=rtp_range,
                protocol="UDP",
                is_port_range=True
            )
            if success:
                print("  ✓ RTP port forwarding added")
            else:
                print("  ✗ Failed to add RTP port forwarding")

        # Verify rules
        print("\n" + "=" * 50)
        print("Current FreePBX-related port forwarding rules:")
        print("=" * 50)

        rules = client.get_port_forwarding()
        for rule in rules:
            if "FreePBX" in rule.get('name', '') or "SIP" in rule.get('name', '').upper():
                print(f"  {rule['name']}: {rule['external_port']} -> "
                      f"{rule['internal_ip']}:{rule['internal_port']} ({rule['protocol']})")

        print("\n✓ FreePBX port forwarding setup complete!")
        print("\nNext steps:")
        print("1. Configure your FreePBX External Address settings")
        print("2. Set RTP port range in FreePBX to match: {}-{}".format(RTP_PORT_START, RTP_PORT_END))
        print("3. Test incoming calls from external network")

    finally:
        client.logout()

if __name__ == "__main__":
    main()
