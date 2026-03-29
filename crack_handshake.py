#!/usr/bin/env python3
"""Detect WPA 4-way handshake attempts in an 802.11 capture and optionally crack them."""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


TSHARK_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "wlan.sa",
    "wlan.da",
    "wlan.bssid",
    "wlan_rsna_eapol.keydes.msgnr",
    "eapol.keydes.replay_counter",
)


@dataclass(slots=True)
class EapolFrame:
    frame_number: int
    timestamp: float
    source: str
    destination: str
    bssid: str
    message_number: int
    replay_counter: int | None


@dataclass(slots=True)
class HandshakeAttempt:
    ap: str
    client: str
    frames: list[EapolFrame] = field(default_factory=list)
    messages: dict[int, EapolFrame] = field(default_factory=dict)
    retransmissions: dict[int, list[EapolFrame]] = field(default_factory=dict)

    def add_frame(self, frame: EapolFrame) -> None:
        self.frames.append(frame)
        if frame.message_number in self.messages:
            self.retransmissions.setdefault(frame.message_number, []).append(frame)
            return
        self.messages[frame.message_number] = frame

    @property
    def start_time(self) -> float:
        return self.frames[0].timestamp

    @property
    def end_time(self) -> float:
        return self.frames[-1].timestamp

    @property
    def seen_messages(self) -> list[int]:
        return sorted(self.messages)

    @property
    def is_complete(self) -> bool:
        return self.seen_messages == [1, 2, 3, 4]

    @property
    def retry_count(self) -> int:
        return sum(len(frames) for frames in self.retransmissions.values())

    @property
    def replay_counters(self) -> list[int]:
        counters = {
            frame.replay_counter
            for frame in self.frames
            if frame.replay_counter is not None
        }
        return sorted(counters)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect an 802.11 capture, report WPA 4-way handshake attempts, "
            "and optionally crack complete handshakes with a dictionary attack."
        )
    )
    parser.add_argument("capture", type=Path, help="Path to a .cap/.pcap file")
    parser.add_argument(
        "--tshark",
        default="tshark",
        help="Path to the tshark binary (default: %(default)s)",
    )
    parser.add_argument(
        "--show-partial",
        action="store_true",
        help="Also print incomplete handshake attempts",
    )
    parser.add_argument(
        "--crack",
        action="store_true",
        help="Run a dictionary attack on any complete 4-way handshakes",
    )
    parser.add_argument(
        "--wordlist",
        type=Path,
        default=Path("utility/rockyou.txt"),
        help="Path to the wordlist (default: %(default)s)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    validate_inputs(args.capture, args.tshark, args.crack, args.wordlist)

    frames = load_eapol_frames(args.capture, args.tshark)
    attempts = build_attempts(frames)

    complete = [a for a in attempts if a.is_complete]
    partial = [a for a in attempts if not a.is_complete]

    print_report(args.capture, attempts, complete, partial, args.show_partial)

    if args.crack:
        if complete:
            print("\n=== Starting dictionary attack on complete handshakes ===")
            crack_handshakes(args.capture, args.wordlist)
        else:
            print("\nNo complete handshakes found — nothing to crack.")

    return 0


def validate_inputs(
    capture: Path, tshark_binary: str, crack: bool, wordlist: Path
) -> None:
    if not capture.is_file():
        raise SystemExit(f"Capture file not found: {capture}")

    tshark_path = shutil.which(tshark_binary) if "/" not in tshark_binary else tshark_binary
    if not tshark_path:
        raise SystemExit(
            "Unable to find tshark on PATH. Install Wireshark/tshark or pass --tshark."
        )

    if crack:
        if not shutil.which("aircrack-ng"):
            raise SystemExit(
                "Unable to find aircrack-ng on PATH.\n"
                "Install the aircrack-ng suite (sudo apt install aircrack-ng on Debian/Ubuntu)."
            )
        if not wordlist.is_file():
            raise SystemExit(f"Wordlist not found: {wordlist}")


def load_eapol_frames(capture: Path, tshark_binary: str) -> list[EapolFrame]:
    command = [
        tshark_binary,
        "-r",
        str(capture),
        "-Y",
        "eapol && wlan_rsna_eapol.keydes.msgnr",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
    ]
    for field_name in TSHARK_FIELDS:
        command.extend(["-e", field_name])

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"Unable to execute tshark: {exc}") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip() or "tshark exited with a non-zero status"
        raise SystemExit(stderr)

    rows = csv.reader(result.stdout.splitlines(), delimiter="\t")
    frames: list[EapolFrame] = []
    for row in rows:
        if len(row) != len(TSHARK_FIELDS):
            continue
        message_number = parse_int(row[5])
        if message_number not in {1, 2, 3, 4}:
            continue
        frames.append(
            EapolFrame(
                frame_number=parse_int(row[0], required=True),
                timestamp=parse_float(row[1], required=True),
                source=normalize_mac(row[2]),
                destination=normalize_mac(row[3]),
                bssid=normalize_mac(row[4]),
                message_number=message_number,
                replay_counter=parse_int(row[6]),
            )
        )

    frames.sort(key=lambda frame: (frame.timestamp, frame.frame_number))
    return frames


def parse_int(value: str, required: bool = False) -> int | None:
    value = value.strip()
    if not value:
        if required:
            raise ValueError("Missing required integer field")
        return None
    return int(value)


def parse_float(value: str, required: bool = False) -> float | None:
    value = value.strip()
    if not value:
        if required:
            raise ValueError("Missing required float field")
        return None
    return float(value)


def normalize_mac(value: str) -> str:
    return value.strip().lower()


def build_attempts(frames: list[EapolFrame]) -> list[HandshakeAttempt]:
    attempts: list[HandshakeAttempt] = []
    attempts_by_pair: dict[tuple[str, str], list[HandshakeAttempt]] = {}

    for frame in frames:
        ap, client = infer_pair(frame)
        pair = (ap, client)
        pair_attempts = attempts_by_pair.setdefault(pair, [])

        if not pair_attempts or should_start_new_attempt(pair_attempts[-1], frame):
            pair_attempts.append(HandshakeAttempt(ap=ap, client=client))
        pair_attempts[-1].add_frame(frame)

    for pair_attempts in attempts_by_pair.values():
        attempts.extend(pair_attempts)

    attempts.sort(key=lambda attempt: (attempt.start_time, attempt.ap, attempt.client))
    return attempts


def infer_pair(frame: EapolFrame) -> tuple[str, str]:
    if frame.bssid and frame.bssid != "ff:ff:ff:ff:ff:ff":
        if frame.source == frame.bssid and frame.destination != frame.bssid:
            return frame.bssid, frame.destination
        if frame.destination == frame.bssid and frame.source != frame.bssid:
            return frame.bssid, frame.source

    if frame.message_number in {1, 3}:
        return frame.source, frame.destination
    return frame.destination, frame.source


def should_start_new_attempt(attempt: HandshakeAttempt, frame: EapolFrame) -> bool:
    if attempt.is_complete:
        return True

    existing = attempt.messages.get(frame.message_number)
    if existing is not None:
        return existing.replay_counter != frame.replay_counter

    if frame.message_number == 1:
        return bool(attempt.messages)

    if frame.message_number == 2:
        if 3 in attempt.messages or 4 in attempt.messages:
            return True
        first = attempt.messages.get(1)
        return first is not None and counters_differ(first.replay_counter, frame.replay_counter)

    if frame.message_number == 3:
        return 4 in attempt.messages

    if frame.message_number == 4:
        return False

    return False


def counters_differ(left: int | None, right: int | None) -> bool:
    return left is not None and right is not None and left != right


def print_report(
    capture: Path,
    attempts: list[HandshakeAttempt],
    complete: list[HandshakeAttempt],
    partial: list[HandshakeAttempt],
    show_partial: bool,
) -> None:
    unique_pairs = {(attempt.ap, attempt.client) for attempt in attempts}

    print(f"Capture: {capture}")
    print(f"Pairs observed: {len(unique_pairs)}")
    print(f"Handshake attempts: {len(attempts)}")
    print(f"Complete handshakes: {len(complete)}")
    print(f"Partial handshakes: {len(partial)}")

    if complete:
        print()
        print("Complete handshakes:")
        for attempt in complete:
            print_attempt(attempt)
    elif partial:
        print()
        print("No complete handshakes detected.")

    if partial and (show_partial or not complete):
        print()
        print("Partial handshakes:")
        for attempt in partial:
            print_attempt(attempt)
    elif partial:
        print()
        print("Re-run with --show-partial to list incomplete attempts.")


def print_attempt(attempt: HandshakeAttempt) -> None:
    print(f"- AP {attempt.ap} <-> Client {attempt.client}")
    print(
        f"  Status: {'complete' if attempt.is_complete else 'partial'} | "
        f"Messages: {','.join(str(message) for message in attempt.seen_messages)}"
    )
    print(
        f"  Time: {format_timestamp(attempt.start_time)} -> "
        f"{format_timestamp(attempt.end_time)}"
    )
    print(
        f"  Replay counters: {format_counters(attempt.replay_counters)} | "
        f"Retries: {attempt.retry_count}"
    )
    print(f"  Frames: {format_frames(attempt)}")


def format_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).isoformat(sep=" ", timespec="milliseconds")


def format_counters(counters: list[int]) -> str:
    if not counters:
        return "none"
    return ",".join(str(counter) for counter in counters)


def format_frames(attempt: HandshakeAttempt) -> str:
    entries = []
    for message_number in sorted(attempt.messages):
        frame = attempt.messages[message_number]
        duplicates = len(attempt.retransmissions.get(message_number, []))
        suffix = f" (+{duplicates} retry)" if duplicates == 1 else f" (+{duplicates} retries)"
        if duplicates == 0:
            suffix = ""
        entries.append(f"M{message_number}#{frame.frame_number}{suffix}")
    return ", ".join(entries)


def crack_handshakes(capture: Path, wordlist: Path) -> None:
    """Run aircrack-ng dictionary attack on the capture (it will automatically find all handshakes)."""
    command = [
        "aircrack-ng",
        "-w", str(wordlist),
        str(capture),
    ]

    print(f"Running: {' '.join(command)}")
    print("(This can take a long time with rockyou.txt — be patient!)")
    print("=" * 80)

    try:
        subprocess.run(command, check=False)  # let aircrack-ng print everything live
    except KeyboardInterrupt:
        print("\n\nCracking interrupted by user.")
    except Exception as exc:  # noqa: BLE001
        print(f"Unexpected error during cracking: {exc}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f"Unable to parse tshark output: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc