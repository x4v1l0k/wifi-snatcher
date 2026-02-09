# WiFi Snatcher (`wifi-snatcher.py`)

**wifi-snatcher.py** (Wifi-Snatcher) is a Python tool that:

- Puts a Wi‑Fi interface into **monitor mode**.
- Scans both **2.4 GHz and 5 GHz** networks with **clients** using `airodump-ng --band abg`.
- Automatically **captures WPA/WPA2 handshakes** by deauthing clients.
- Validates handshakes with **aircrack-ng** and **hcxpcapngtool** (hashcat‑ready).
- Persists valid handshakes and **never attacks the same BSSID again**.
- Optionally generates **per‑ESSID wordlists** with rich permutations and l33t variants.

---

## Installation

```bash
git clone https://github.com/x4v1l0k/wifi-snatcher
cd wifi-snatcher
pip3 install -r requirements.txt
sudo python3 wifi-snatcher.py -d wlan0
```

---

## Requirements

- **Root** privileges (run with `sudo`).
- **Aircrack-ng suite**:
  - `airmon-ng` (monitor mode)
  - `airodump-ng` (capture)
  - `aireplay-ng` (deauth)
  - `aircrack-ng` (handshake presence check)
- **Recommended**: `hcxpcapngtool` (from `hcxtools`) to create `.22000` hashes for hashcat.
- **Optional**: `colorama` for colored logging:

```bash
pip install colorama
```

---

## Basic usage (capture mode)

```bash
sudo python3 wifi-snatcher.py -d wlan0
```

This will:

- Put `wlan0` into monitor mode (e.g. `wlan0mon`).
- Continuously scan 2.4 GHz + 5 GHz (`--band abg`) for APs **with clients**.
- Iterate over those networks, capture handshakes, and repeat until Ctrl+C.

---

## Command‑line options

| Option | Description |
|--------|-------------|
| `-d`, `--device` | Wireless interface (e.g. `wlan0`). **Required** in capture mode; **optional** when using `-w/--wordlist`. |
| `-t`, `--time` | Scan duration per cycle in seconds (default: `30`). |
| `-l`, `--log` | Path to a log file. If set, all logs are also written there (without ANSI colors). |
| `-p`, `--path` | Base directory for SQLite DB, handshakes, and temp files. Default: **current directory**. |
| `-se`, `--skip-essid ESSID` | ESSID to skip (repeatable). Those networks are never attacked in this run. |
| `-sb`, `--skip-bssid BSSID` | BSSID (AP MAC) to skip (repeatable). Case‑insensitive; combined with DB‑stored BSSIDs. |
| `-v`, `--verbose` | Show extra warnings (e.g. handshake rejected by `hcxpcapngtool`). |
| `-w`, `--wordlist [DIR]` | **Wordlist‑only mode**: no attacks, only generate per‑ESSID wordlists from DB. Optional `DIR` for output (default: `<path>/wordlists`). |
| `-b`, `--bssid BSSID` | **Single target by BSSID** (repeatable). If used, only these BSSIDs will be attacked. |
| `-e`, `--essid ESSID` | **Single target by ESSID** (repeatable). If used, all APs with that ESSID will be attacked. |
| `-c`, `--channel N` | **Fixed channel** for both scanning and capture. |
| `--stats [SECONDS]` | Show run statistics every 30 s (default) or every `SECONDS` if provided. |
| `--ap-timeout SECONDS` | Maximum capture time per AP (limits how long `airodump-ng` + deauth runs). |
| `--ap-delay SECONDS` | Delay between APs to avoid driver issues (default: `2`). |
| `--hidden-wait SECONDS` | Max time (seconds) to try revealing a hidden ESSID before capture (default: `25`). |

Notes:

- If `-w` is **not** used, `-d` is **required**.
- If `-w` **is** used, capture logic is skipped and the interface is **not** touched.

---

## Capture behaviour (online mode)

1. **Monitor mode**
   - If the interface is not already in monitor mode, `airmon-ng start <device>` is used.
   - On exit (including Ctrl+C), the script calls `airmon-ng stop <mon_iface>` to restore managed mode.

2. **Scanning** (`get_networks_with_clients`)
   - Runs `airodump-ng` with:
     - Default: `airodump-ng --output-format csv --write <tmp_prefix> --band abg -a <mon_iface>`
     - With fixed channel (`-c/--channel`): `airodump-ng --output-format csv --write <tmp_prefix> --channel N -a <mon_iface>`
   - `--band abg` means: **2.4 GHz (b/g) + 5 GHz (a)**.
   - Output CSV is parsed to find APs with at least one **associated client**.

3. **Target selection**
   - APs are **ignored** if:
     - BSSID is already in the SQLite `captured` table.
     - BSSID is in `--skip-bssid`.
     - ESSID is in `--skip-essid`.
   - With single-target options:
     - If `-b/--bssid` is used, only APs whose BSSID is in the given list are processed.
     - If `-e/--essid` is used, only APs whose ESSID matches are processed (all APs with that ESSID are attacked).

4. **Hidden ESSID recovery** (before handshake)
   - If the AP’s ESSID is hidden (beacon does not broadcast it), the script treats it as `hidden_network`.
   - Before capturing the handshake, it tries to **reveal the real ESSID**:
     - Runs `airodump-ng` focused on that BSSID for a few seconds.
     - Sends 1–2 deauth frames so clients reconnect; the **Association Request** from the client contains the SSID.
     - Re-parses the airodump CSV and, if the ESSID appears for that BSSID, uses it for the rest of the run (filenames, DB, logs).
   - Revealed ESSIDs are cached in the `discovered_essids` table (BSSID → ESSID), so hidden APs are not re-probed in later runs.
   - `--hidden-wait` limits how long (seconds) the script spends on this recovery before proceeding to handshake capture with `hidden_network` if unrevealed.
   - Statistics count **hidden_detected** and **hidden_resolved**.

5. **Handshake capture** (`capture_handshake`)
   - For each eligible AP (with clients):
     - Runs a focused `airodump-ng` on `--channel <ch> --bssid <BSSID>` and writes `hs_<BSSID>_<ESSID>-01.cap` in `handshakes/`.
     - Sends up to **5 rounds** of deauths with `aireplay-ng -0 2 -a <BSSID> -c <STA>`.
     - Keeps the capture running while sending deauths and briefly after.
   - If **no handshake** is detected (`aircrack-ng <cap> -w /dev/null`):
     - The `.cap` and its side files are removed.
     - A per‑run **failure counter** for that BSSID is incremented.

6. **Crackable handshake verification**
   - A capture is only considered **valid & done** if **both**:
     1. `aircrack-ng` confirms at least one handshake.
     2. `hcxpcapngtool` successfully converts the `.cap` to `.22000` (non‑empty file).
   - If hcxpcapngtool **fails**, the capture is treated as a **false positive** and removed; the network will be attacked again later.

7. **Storing successful captures**
   - When hcxpcapngtool succeeds:
     - The `.cap` is renamed to `handshakes/<ESSID>_<hash>_<BSSID>.cap` (a short hash avoids collisions when ESSIDs share the first 32 chars).
     - The `.22000` is renamed to `handshakes/<ESSID>_<hash>_<BSSID>.cap.22000`.
     - An entry is inserted/updated in `captured.db` (table `captured`):  
       `bssid`, `essid`, `handshake_path`, `created_at`.
     - That BSSID is **never attacked again** (persistently, across runs).
   - If the ESSID could not be revealed, it is stored as `hidden_network` in the database and in file names.

8. **Per‑run failure limits**
   - For each BSSID, the script tracks the number of **failed attempts** in the current run (either no handshake or hcxpcapngtool failure).
   - After **4 failures** in the current execution, that BSSID is skipped for the rest of this run (but not added to the DB, so future runs can still try).

9. **Looping**
   - Once all candidates in a scan are processed, the tool logs completion of the cycle and starts a fresh scan.
   - This continues until you hit **Ctrl+C**.

10. **Ctrl+C / SIGINT behaviour**
   - Active `airodump-ng` processes are terminated.
   - The `finally` block:
     - Restores the interface to **managed** mode.
     - Re‑validates all stored handshakes in `captured.db` with hcxpcapngtool and removes any that fail re‑check (DB row + files).
     - Closes the SQLite connection and logs a clean exit.
     - Cleans the temporary directory used for scan CSVs.

11. **Statistics**
    - The script keeps counters for: cycles, candidate networks (with clients), capture attempts, successful captures, failures, skipped APs, and **hidden_detected** / **hidden_resolved** (hidden ESSID recovery).
    - A statistics summary is always shown on exit.
    - With `--stats` or `--stats SECONDS`, periodic statistics are shown during the run.

---

## Wordlist‑only mode (`-w/--wordlist`)

When `-w` is used, **no scans or attacks are performed**. Instead:

1. The script opens `captured.db` and enumerates distinct ESSIDs.
2. For each ESSID, it creates one wordlist file:
   - Default path: `<path>/wordlists/<ESSID_SAFE>.txt`
   - Or in the directory passed to `-w DIR`.

### Wordlist generation per ESSID

For each ESSID:

- Generate all **case permutations** (full 2ⁿ, n ≤ 12):  
  e.g. `MyNetwork`, `mYnEtWoRk`, `MYNETWORK`, `mynetwork`, etc.
- For each case variant, generate all **leet variants**:  
  substitutions like `a→4`, `e→3`, `i→1`, `o→0`, `s→5`, `t→7`, `b→8`, `g→9`, `z→2`, `l→1`.  
  Example: `MyNetwork` → `MyN3tw0rk`, `myn3twork`, `myN3tw0rk`, etc.
- For every resulting base word:
  - Append/prepend **suffixes**: `!`, `!!`, `@`, `#`, `123`, `1234`, `12345`, `123456`, `00`, `01`, `1`, `0`, `2`, `11`, `12`, `22`, `*`, `?`.
  - Add **years**:
    - Current year and previous 5: `YYYY` and `YY` (e.g. `2026`, `26`, `2025`, `25`, …).
    - Also all years `1990–2030` in `YYYY` and `YY`.
  - Add **months**: `01–12`.
  - Combine with **separators** `.` `-` `_`, e.g.:  
    `ESSID_1234`, `ESSID-2024`, `2024.ESSID`, `ESSID_26`, etc.

All candidates are **deduplicated** and sorted before being written.

Example:

```bash
# Generate wordlists for all captured ESSIDs into ./wordlists
python3 wifi-snatcher.py -w

# Generate into a custom directory, using data under ./data
python3 wifi-snatcher.py -w /tmp/wl -p ./data
```

---

## Directory layout under `-p/--path`

Within the base path:

- `captured.db` – SQLite database with:
  - Table `captured`: `bssid` (PRIMARY KEY), `essid`, `handshake_path`, `created_at`
  - Table `discovered_essids`: `bssid` (PRIMARY KEY), `essid`, `discovered_at` (cache of revealed hidden ESSIDs)
- `handshakes/` – final handshake artifacts:
  - `<ESSID>_<hash>_<BSSID>.cap`
  - `<ESSID>_<hash>_<BSSID>.cap.22000` (if hcxpcapngtool is available)
- Temporary scan CSVs are written into a dedicated temporary directory under `/tmp` on each run (not persistent).
