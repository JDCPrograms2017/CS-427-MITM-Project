#!/usr/bin/env python3

import subprocess
import sys

def supports_ap_mode():
    """
    Checks if any WiFi PHY supports AP (Access Point) mode using the 'iw' tool.
    Returns True if AP mode is supported, False otherwise.
    """
    try:
        # 'iw list' shows supported interface modes for each PHY
        output = subprocess.check_output(['iw', 'list'], stderr=subprocess.STDOUT, text=True)
        # Look for the standard marker "* AP" which indicates AP mode support
        if '* AP' in output:
            return True
        return False
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        # 'iw' not installed or other error - we cannot confirm support
        print(" Could not check AP mode support (is 'iw' installed? Try: sudo apt install iw)")
        return False

def get_wifi_interface():
    """
    Returns the first WiFi interface name using nmcli (e.g., wlan0).
    Returns None if no WiFi device is found.
    """
    try:
        output = subprocess.check_output(
            ['nmcli', '-t', '-f', 'DEVICE,TYPE', 'device', 'status'],
            text=True
        )
        for line in output.splitlines():
            if line.strip():
                parts = line.split(':', 1)
                if len(parts) == 2:
                    device, dev_type = parts
                    if dev_type == 'wifi':
                        return device
        return None
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None

def main():
    print("=== CPTS 427 - WiFi Hotspot Setup Script (Ubuntu) ===\n")

    # Step 1: Check if the network card supports AP mode
    ap_supported = supports_ap_mode()

    if ap_supported:
        print(" Your device supports AP mode.")
        print("   You will now be prompted for custom SSID and passkey.\n")
        
        # Prompt user for SSID and passkey (with defaults shown)
        ssid = input("Enter SSID [default: TPLink_28]: ").strip() or "TPLink_28"
        password = input("Enter passkey [default: 03425206]: ").strip() or "03425206"
        
    else:
        print("   Your device does NOT appear to support AP mode.")
        print("   The hotspot setup will likely fail, but you can still try with defaults.\n")
        
        # Otherwise branch: ask for confirmation to use defaults
        confirm = input("Use default SSID 'TPLink_28' and passkey '03425206'? (y/n): ").strip().lower()
        if confirm != 'y':
            print("Setup cancelled by user.")
            sys.exit(0)
        
        ssid = "TPLink_28"
        password = "03425206"

    # Basic validation
    if len(password) < 8:
        print("  Warning: Passkey should be at least 8 characters for WPA2 security.")
        proceed = input("Continue anyway? (y/n): ").strip().lower()
        if proceed != 'y':
            print("Setup cancelled.")
            sys.exit(0)

    # Step 2: Find the WiFi interface
    interface = get_wifi_interface()
    if not interface:
        print(" No WiFi interface found via nmcli. Is WiFi enabled?")
        sys.exit(1)
    print(f"Using WiFi interface: {interface}")

    # Step 3: Build and execute the correct Ubuntu command
    # nmcli device wifi hotspot is the standard, one-command way on Ubuntu with NetworkManager
    cmd = [
        'nmcli', 'device', 'wifi', 'hotspot',
        'ifname', interface,
        'ssid', ssid,
        'password', password
    ]

    print(f"\n🚀 Setting up hotspot → SSID: '{ssid}' | Passkey: '{password}'")
    print("   (This may take a few seconds...)\n")

    try:
        # Run the command (no sudo forced - nmcli usually works for the current user)
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        print("   Hotspot created and activated successfully!")
        print("   You should now see the network '" + ssid + "' available on other devices.")
        print("   Password is: " + password)
        if result.stdout.strip():
            print("\nNetworkManager output:\n" + result.stdout.strip())
        
        print("\n To stop the hotspot later, run: nmcli connection down hotspot")
        print("   or reboot your machine.")

    except subprocess.CalledProcessError as e:
        print(" Failed to create hotspot.")
        if e.stderr:
            print("Error details:\n" + e.stderr.strip())
        print("\nCommon fixes:")
        print("   • Run this script with: sudo python3 hotspot_script.py")
        print("   • Ensure NetworkManager is running: sudo systemctl restart NetworkManager")
        print("   • Make sure WiFi is not already in use by another connection")
        print("   • Your hardware really might not support AP mode (check with 'iw list')")
        sys.exit(1)

    except FileNotFoundError:
        print("'nmcli' command not found. Is NetworkManager installed?")
        sys.exit(1)

if __name__ == "__main__":
    main()