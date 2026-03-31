# CS-427-MITM-Project
This project is the course project repository for WSU's CS 427 Cybersecurity course in the Spring 2026 semester.

## WPA Handshake Detection

The repository now includes [`detect_wpa_handshakes.py`](./detect_wpa_handshakes.py), a small CLI that inspects an 802.11 capture and reports WPA 4-way handshake attempts by AP/client pair.

### Requirements

- `python3`
- `tshark` available on your `PATH`

### Usage

```bash
python3 detect_wpa_handshakes.py sample_capture.cap
python3 detect_wpa_handshakes.py sample_capture.cap --show-partial
```

The output includes:

- complete handshake sets with messages 1 through 4
- incomplete handshake attempts that may contain only a subset of EAPOL messages
- frame numbers, timestamps, replay counters, and retry counts

### Scope

This helper is limited to handshake identification and reporting. It does not use [`utility/rockyou.txt`](./utility/rockyou.txt) or attempt password recovery.

## Ubuntu Wi-Fi Survey

The repository also includes [`ubuntu_wifi_survey.py`](./ubuntu_wifi_survey.py), a small Ubuntu-oriented helper that:

- detects wireless interfaces reported by NetworkManager
- scans nearby Wi-Fi networks and shows SSIDs, BSSIDs, channels, signal, and security
- lets you select a network interactively or preselect an interface/SSID with flags

### Requirements

- `python3`
- `nmcli` available on your Ubuntu machine

### Usage

```bash
python3 ubuntu_wifi_survey.py
python3 ubuntu_wifi_survey.py --interface wlan0
python3 ubuntu_wifi_survey.py --interface wlan0 --ssid ExampleNetwork
```

### Scope

This helper intentionally stops at network discovery and selection. It does not enable monitor mode or start packet capture.
