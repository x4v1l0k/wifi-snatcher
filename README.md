# WiFi Snatcher (`wifi-snatcher.py`)

**wifi-snatcher.py** (Wifi-Snatcher) is a Python tool that:

- Puts a Wi‑Fi interface into **monitor mode**.
- Scans both **2.4 GHz and 5 GHz** for APs **with clients** or **hidden** (no client) using `airodump-ng --band abg`.
- **Captures WPA/WPA2 handshakes** by broadcast deauth (all clients on the AP); validates with **aircrack-ng** and **hcxpcapngtool** (hashcat‑ready).
- For **hidden networks without clients**, captures **PMKID** (every 5 cycles, grouped by channel) when **hcxdumptool** is available.
- **Startup cleanup** of leftover files from previous runs; **exit**: re‑verifies handshakes and restores the interface.
- Persists valid handshakes and **never attacks the same BSSID again**.
- Optionally generates **per‑ESSID wordlists** with case/leet variants and ISP masks.

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
- **Aircrack-ng suite**: `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`.
- **iw** (channel / monitor mode).
- **Recommended**: **hcxtools** (`hcxpcapngtool` for `.22000` hashes, `hcxdumptool` for PMKID on hidden networks):  
  `sudo apt install hcxtools`
- **Optional**: `colorama` for colored console output:  
  `pip3 install -r requirements.txt`

---

## Basic usage (capture mode)

```bash
sudo python3 wifi-snatcher.py -d wlan0
```

This will:

- Clean leftover files from previous runs in `handshakes/`.
- Put `wlan0` into monitor mode (e.g. `wlan0mon`).
- Continuously scan 2.4 GHz + 5 GHz for APs **with clients** or **hidden** (no clients).
- Capture handshakes (broadcast deauth), then at end of each cycle run **PMKID** for hidden-without-clients (every 5 cycles). Repeat until Ctrl+C.

---

## Command‑line options

| Option | Description |
|--------|-------------|
| `-d`, `--device` | Wireless interface (e.g. `wlan0`). **Required** in capture mode; **optional** when using `-w/--wordlist`. |
| `-t`, `--time` | Scan duration per cycle in seconds (default: `60`). |
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
| `--hidden-passive SECONDS` | Passive sniff time before deauth when revealing hidden ESSID (default: `10`). |
| `--pmkid-timeout SECONDS` | Time per channel for PMKID capture; multiple BSSIDs on same channel are captured together (default: `15`). |
| `--mac-rotate N` | Rotate interface MAC every N cycles to reduce router blocking (default: `0` = disabled). |

Notes:

- If `-w` is **not** used, `-d` is **required**.
- If `-w` **is** used, capture logic is skipped and the interface is **not** touched.

---

## Capture behaviour (online mode)

1. **Monitor mode**
   - If the interface is not already in monitor mode, `airmon-ng start <device>` is used.
   - On exit (including Ctrl+C), the script calls `airmon-ng stop <mon_iface>` to restore managed mode.

2. **Startup cleanup**
   - Removes leftover files in `handshakes/` from previous runs: `pmkid_filter_*.txt`, `pmkid_*.pcapng`, `hs_*` (temporary capture files).

3. **Scanning** (`get_networks_with_clients`)
   - Runs `airodump-ng` with `--output-format csv --write <tmp_prefix> --band abg -a <mon_iface>` (or `--channel N` if `-c` is set).
   - **Included**: APs with at least one **associated client** (for handshake), or **hidden** APs with no clients (for PMKID at end of cycle). Visible-ESSID APs with no clients are **not** attacked in that cycle.

4. **Target selection**
   - APs are **ignored** if:
     - BSSID is already in the SQLite `captured` table.
     - BSSID is in `--skip-bssid`.
     - ESSID is in `--skip-essid`.
   - With single-target options:
     - If `-b/--bssid` is used, only APs whose BSSID is in the given list are processed.
     - If `-e/--essid` is used, only APs whose ESSID matches are processed (all APs with that ESSID are attacked).

5. **Hidden ESSID recovery** (before handshake)
   - If the AP’s ESSID is hidden (beacon does not broadcast it), the script treats it as `hidden_network`.
   - Before capturing the handshake, it tries to **reveal the real ESSID**:
     - Runs `airodump-ng` focused on that BSSID for a few seconds.
     - Sends 1–2 deauth frames so clients reconnect; the **Association Request** from the client contains the SSID.
     - Re-parses the airodump CSV and, if the ESSID appears for that BSSID, uses it for the rest of the run (filenames, DB, logs).
   - Revealed ESSIDs are cached in the `discovered_essids` table (BSSID → ESSID), so hidden APs are not re-probed in later runs.
   - `--hidden-wait` limits how long (seconds) the script spends on this recovery before proceeding to handshake capture with `hidden_network` if unrevealed.
   - Statistics count **unique hidden** BSSIDs and **hidden_resolved**.

6. **Handshake capture** (`capture_handshake`)
   - For each eligible AP (with clients):
     - Runs `airodump-ng` on `--channel <ch> --bssid <BSSID>` and writes `hs_<BSSID>_<ESSID>-01.cap` in `handshakes/`.
     - Sends up to **5 rounds** of **broadcast deauth** with `aireplay-ng -0 4 -a <BSSID>` (no `-c`), so all clients on the AP are deauth’ed and any reconnect can yield the handshake.
     - Keeps the capture running while sending deauths and briefly after.
   - If **no handshake** is detected (`aircrack-ng <cap> -w /dev/null`):
     - The `.cap` and its side files are removed.
     - A per‑run **failure counter** for that BSSID is incremented.

7. **Crackable handshake verification**
   - A capture is only considered **valid & done** if **both**:
     1. `aircrack-ng` confirms at least one handshake.
     2. `hcxpcapngtool` successfully converts the `.cap` to `.22000` (non‑empty file).
   - If hcxpcapngtool **fails**, the capture is treated as a **false positive** and removed; the network will be attacked again later.

8. **Storing successful captures**
   - When hcxpcapngtool succeeds:
     - The `.cap` is renamed to `handshakes/<ESSID>_<hash>_<BSSID>.cap` (a short hash avoids collisions when ESSIDs share the first 32 chars).
     - The `.22000` is renamed to `handshakes/<ESSID>_<hash>_<BSSID>.cap.22000`.
     - An entry is inserted/updated in `captured.db` (table `captured`):  
       `bssid`, `essid`, `handshake_path`, `created_at`.
     - That BSSID is **never attacked again** (persistently, across runs).
   - If the ESSID could not be revealed, it is stored as `hidden_network` in the database and in file names.

9. **PMKID (hidden, no clients)**
   - At **end of each cycle**, only when **cycle is a multiple of 5**, the script runs PMKID capture for hidden APs that have no clients (requires **hcxdumptool** and **hcxpcapngtool**).
   - All such BSSIDs on the **same channel** are captured in **one run** per channel (time per channel set by `--pmkid-timeout`, default 15 s). Output is converted to `.22000` and stored; each captured BSSID is marked in the DB and not attacked again.

10. **Per‑run failure limits**
   - For each BSSID, the script tracks the number of **failed attempts** in the current run (either no handshake or hcxpcapngtool failure).
   - After **4 failures** in the current execution, that BSSID is skipped for the rest of this run (but not added to the DB, so future runs can still try).

11. **Looping**
   - Once all candidates in a scan are processed, the tool logs completion of the cycle and starts a fresh scan.
   - This continues until you hit **Ctrl+C**.

12. **Ctrl+C / SIGINT behaviour**
   - Active `airodump-ng` processes are terminated.
   - The `finally` block:
     - Restores the interface to **managed** mode.
     - Re‑validates all stored handshakes in `captured.db` with hcxpcapngtool and removes any that fail re‑check (DB row + files).
     - Closes the SQLite connection and logs a clean exit.
     - Cleans the temporary directory used for scan CSVs.

13. **Statistics**
    - Counters: **cycles**, **unique networks** (distinct BSSIDs seen), **attempts**, **success**, **failed**, **skipped**, **unique hidden** / **resolved**.
    - Summary is shown on exit; with `--stats` or `--stats SECONDS`, periodic stats are printed during the run.

---

## Wordlist‑only mode (`-w/--wordlist`)

When `-w` is used, **no scans or attacks are performed**. Instead:

1. The script opens `captured.db` and enumerates distinct ESSIDs.
2. For each ESSID, it creates one wordlist file:
   - Default path: `<path>/wordlists/<ESSID_SAFE>.txt`
   - Or in the directory passed to `-w DIR`.

### Wordlist generation per ESSID

For each ESSID:

- **Case variants**: lower, UPPER, Title (e.g. `mynetwork`, `MYNETWORK`, `Mynetwork`).
- **Limited leet** (only `a→4`, `e→3`, `o→0`) for words up to 12 chars.
- For each base word: **suffixes** (`!`, `!!`, `@`, `#`, `123`, `1234`, `*`, `?`), **years** (current and previous 5 in `YYYY` and `YY`), **months** (`01`–`12`), **separators** (`.`, `-`, `_`).
- **ISP masks** (`.hcmask`) and hybrid bases are generated when ESSID matches known ISP patterns (e.g. MOVISTAR, VODAFONE, ORANGE).

Candidates are deduplicated and sorted. Use `--max-words N` to cap entries per ESSID.

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
- `handshakes/` – handshake artifacts:
  - `<ESSID>_<hash>_<BSSID>.cap` and `.cap.22000` (four-way handshake)
  - `pmkid_ch<N>_<tag>.22000` (PMKID captures for hidden networks; one file can contain multiple BSSIDs)
- Temporary scan CSVs are written to a temp directory under `/tmp` each run (removed on exit). Startup removes leftover `pmkid_filter_*.txt`, `pmkid_*.pcapng`, and `hs_*` from previous runs.
