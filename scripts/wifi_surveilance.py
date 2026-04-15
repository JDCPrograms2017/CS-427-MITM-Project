#!/usr/bin/env python3
"""Survey nearby Wi-Fi networks on Ubuntu using NetworkManager."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass(slots=True)
class WifiInterface:
    name: str
    state: str


@dataclass(slots=True)
class WifiNetwork:
    in_use: bool
    ssid: str
    bssid: str
    channel: str
    signal: str
    security: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "List Ubuntu Wi-Fi interfaces, scan nearby SSIDs/channels, and "
            "interactively select a network."
        )
    )
    parser.add_argument(
        "--interface",
        help="Use a specific wireless interface instead of prompting",
    )
    parser.add_argument(
        "--ssid",
        help="Auto-select a network by SSID when it appears in the scan results",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_nmcli_available()

    interfaces = list_wifi_interfaces()
    if not interfaces:
        raise SystemExit("No Wi-Fi interfaces were reported by NetworkManager.")

    interface = choose_interface(interfaces, requested_name=args.interface)
    networks = scan_networks(interface.name)
    if not networks:
        raise SystemExit(
            f"No Wi-Fi networks were returned for interface {interface.name}. "
            "Check that Wi-Fi is enabled and try again."
        )

    network = choose_network(networks, requested_ssid=args.ssid)
    print_selection(interface, network)
    return 0


def ensure_nmcli_available() -> None:
    if shutil.which("nmcli") is None:
        raise SystemExit(
            "Unable to find nmcli. Install NetworkManager or run this on Ubuntu "
            "with nmcli available."
        )


def run_nmcli(arguments: list[str]) -> str:
    command = ["nmcli", *arguments]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"Unable to execute nmcli: {exc}") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip() or "nmcli exited with a non-zero status"
        raise SystemExit(stderr)
    return result.stdout


def list_wifi_interfaces() -> list[WifiInterface]:
    output = run_nmcli(
        ["-t", "--escape", "yes", "-f", "DEVICE,TYPE,STATE", "device", "status"]
    )
    interfaces: list[WifiInterface] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        columns = split_escaped(line, ":", expected_parts=3)
        if len(columns) != 3 or columns[1] != "wifi":
            continue
        interfaces.append(WifiInterface(name=columns[0], state=columns[2]))
    return interfaces


def choose_interface(
    interfaces: list[WifiInterface],
    requested_name: str | None,
) -> WifiInterface:
    if requested_name:
        for interface in interfaces:
            if interface.name == requested_name:
                return interface
        available = ", ".join(interface.name for interface in interfaces)
        raise SystemExit(
            f"Wireless interface {requested_name!r} was not found. "
            f"Available interfaces: {available}"
        )

    if len(interfaces) == 1:
        return interfaces[0]

    print("Wireless interfaces:")
    for index, interface in enumerate(interfaces, start=1):
        print(f"  {index}. {interface.name} ({interface.state})")
    choice = prompt_for_index(len(interfaces), "Select an interface")
    return interfaces[choice - 1]


def scan_networks(interface_name: str) -> list[WifiNetwork]:
    output = run_nmcli(
        [
            "-t",
            "--escape",
            "yes",
            "-f",
            "IN-USE,SSID,BSSID,CHAN,SIGNAL,SECURITY",
            "device",
            "wifi",
            "list",
            "ifname",
            interface_name,
            "--rescan",
            "yes",
        ]
    )
    networks: list[WifiNetwork] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        columns = split_escaped(line, ":", expected_parts=6)
        if len(columns) != 6:
            continue
        networks.append(
            WifiNetwork(
                in_use=columns[0] == "*",
                ssid=columns[1] or "<hidden>",
                bssid=columns[2],
                channel=columns[3] or "?",
                signal=columns[4] or "?",
                security=columns[5] or "--",
            )
        )
    return networks


def choose_network(
    networks: list[WifiNetwork],
    requested_ssid: str | None,
) -> WifiNetwork:
    if requested_ssid:
        matches = [network for network in networks if network.ssid == requested_ssid]
        if not matches:
            raise SystemExit(f"SSID {requested_ssid!r} was not found in the scan results.")
        if len(matches) == 1:
            return matches[0]
        print(f"Multiple radios matched SSID {requested_ssid!r}:")
        print_networks(matches)
        choice = prompt_for_index(len(matches), "Select a BSSID")
        return matches[choice - 1]

    print()
    print("Nearby Wi-Fi networks:")
    print_networks(networks)
    choice = prompt_for_index(len(networks), "Select a network")
    return networks[choice - 1]


def print_networks(networks: list[WifiNetwork]) -> None:
    header = f"{'#':>3}  {'SSID':<28}  {'BSSID':<17}  {'CH':>3}  {'SIG':>3}  SECURITY"
    print(header)
    for index, network in enumerate(networks, start=1):
        ssid = truncate(network.ssid, 28)
        print(
            f"{index:>3}  {ssid:<28}  {network.bssid:<17}  "
            f"{network.channel:>3}  {network.signal:>3}  {network.security}"
        )


def print_selection(interface: WifiInterface, network: WifiNetwork) -> None:
    print()
    print("Selected network:")
    print(f"  Interface: {interface.name}")
    print(f"  State: {interface.state}")
    print(f"  SSID: {network.ssid}")
    print(f"  BSSID: {network.bssid}")
    print(f"  Channel: {network.channel}")
    print(f"  Signal: {network.signal}")
    print(f"  Security: {network.security}")
    print()
    print(
        "This helper intentionally stops at discovery and selection. "
        "It does not enable monitor mode or start packet capture."
    )


def prompt_for_index(max_value: int, prompt: str) -> int:
    while True:
        response = input(f"{prompt} [1-{max_value}]: ").strip()
        if not response:
            continue
        try:
            choice = int(response)
        except ValueError:
            print("Enter a number from the list.")
            continue
        if 1 <= choice <= max_value:
            return choice
        print("Choice out of range.")


def split_escaped(line: str, separator: str, expected_parts: int) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False

    for character in line:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == separator and len(parts) < expected_parts - 1:
            parts.append("".join(current))
            current = []
            continue
        current.append(character)

    parts.append("".join(current))
    return parts


def truncate(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    return value[: width - 3] + "..."


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        raise SystemExit(130)
