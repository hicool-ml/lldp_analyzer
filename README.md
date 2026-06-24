# LLDP/CDP Protocol Analyzer

Offline and online LLDP/CDP packet analyzer with vendor-specific private TLV decoding. Dual interface: **CLI** for scripting and quick inspection, **GUI** (tkinter) for interactive analysis with capture history and network adapter management.

Cross-platform: **Windows** (fully tested) and **macOS** (Apple Silicon + Intel).

## Quick Start

### Windows
```powershell
# CLI — online capture + neighbor summary
python lldp.py

# GUI — interactive mode
python lldp_gui.py
```

### macOS
```bash
# Activate virtual environment first
source venv/bin/activate

# CLI — online capture + neighbor summary (elevates automatically)
python lldp.py

# GUI — interactive mode (elevates on startup)
python lldp_gui.py
```

> **Note for macOS 14+ (Sonoma/Sequoia)**: The GUI auto-elevates using the system Python to avoid TCC restrictions. If you get `Operation not permitted` errors, grant Terminal / Python **Full Disk Access** in System Settings → Privacy & Security → Files and Folders.

## CLI Usage

```bash
python lldp.py                          # online capture + neighbor summary
python lldp.py -v                       # verbose parsed TLV output
python lldp.py -d                       # debug mode (offset, raw hex, bitfields)
python lldp.py -l -t                    # raw packet hex + hexdump, wait for both LLDP and CDP
python lldp.py <hex_file>               # offline hex file
```

| Flag | Description |
|------|-------------|
| (none) | Scan physical Ethernet, trigger link down/up, capture LLDP/CDP, print neighbor summary |
| `-v` | Verbose — Type, Len, Subtype and decoded fields |
| `-d` | Debug — offset, raw hex, TLV header bitfield |
| `-l` | Raw capture log — payload hex and full-frame hexdump |
| `-t` | Thorough — wait for both LLDP and CDP before stopping (useful for Cisco devices) |
| `<file>` | Parse offline hex text file, print summary + full TLV details |
| `--no-renegotiate` | Skip the link down/up operation |
| `--wait-for-link` | Wait for link up before starting capture |
| `--interface <name>` | Specify interface (skip auto-detection) |
| `--json-out <path>` | Write capture results as JSON (for GUI automation) |

### CLI Elevation Behavior

- **Windows**: Automatically elevates via UAC for online capture; offline parsing needs no elevation.
- **macOS/Linux**: Automatically elevates via `sudo` for online capture.

CLI exit: press `q` then `Enter` (or `q` on Windows if stdin is a TTY).

## GUI

```bash
python lldp_gui.py
python lldp_gui.py <offline_file>   # launch with offline file loaded
```

Three tabs:

- **Capture** — select Ethernet adapter, start online capture (auto-elevates), or open an offline hex file. Displays device identity, port info, and semantic analysis (port role, device type, confidence).
- **History** — query past captures by time range, device name, or port role. View per-record detail, raw packet hex, and aggregate statistics.
- **Network** — view local adapter status (IP, gateway, DNS, DHCP, link speed, MTU). Modify MAC address (requires elevation), configure static IP or DHCP.

### macOS GUI Notes

1. **Startup elevation**: The GUI automatically requests admin privileges on startup (not on capture click). After entering your password, the GUI runs with full privileges.
2. **Capture engine**: The GUI reuses `lldp.py` as its capture engine — it launches `lldp.py --json-out` with elevation so the interface down/up triggers fresh LLDP+CDP frames from the switch.
3. **Scapy availability**: The capture subprocess uses the system Python with `PYTHONPATH` set to the virtual environment's site-packages, so scapy is found automatically.
4. **Adaptive refresh**: After capture or network operations, the UI refreshes with progress dots.

## Setup

### Windows
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### macOS
```bash
# Create venv (use Homebrew Python, not system Python)
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

ChmodBPF (optional — allows non-root packet capture):
```bash
brew install homebrew/cask/chmodbpf
```
Then restart your Mac. Without ChmodBPF, the tool auto-elevates via `sudo`.

### Requirements
- Python 3.10+
- `scapy` — online packet capture
- `tkinter` — GUI (included with most Python distributions)

## Supported Protocols

### LLDP (IEEE 802.1AB)

Standard TLVs: Chassis ID, Port ID, TTL, Port Description, System Name, System Description, System Capabilities, Management Address.

Organizational TLVs by OUI:

| OUI | Name | Coverage |
|-----|------|----------|
| `00:80:C2` | IEEE 802.1 | PVID, PPVID, VLAN Name, Protocol Identity, VID Usage Digest, Management VID, Link Aggregation, Congestion Notification, ETS Configuration/Recommendation, PFC Configuration, Application Priority |
| `00:12:0F` | IEEE 802.3 | MAC/PHY Config, Power via MDI, Link Aggregation, Max Frame Size, Energy Efficient Ethernet |
| `00:12:BB` | LLDP-MED / shared | MED Capabilities, Network Policy, Location, Extended Power-via-MDI, Inventory subtypes 5-11 |
| `00:12:BB` | H3C / Ruijie / Huawei / Cisco | Dispatched by device fingerprint when OUI is shared |
| `00:E0:FC` | Huawei private | Vendor-specific subtypes |
| `00:90:69` | Juniper private | Three-layer decode (serial, model, firmware, DCBXP bitmap per device schema) |
| `00:00:0C` / `00:0C:05` | Cisco private | CDP-over-LLDP TLVs |

### CDP (Cisco Discovery Protocol)

All TLV types through `0x001A`: Device ID, Address, Port ID, Capabilities (bitfield), Software Version, Platform, IP Prefix, VTP Management Domain, Duplex, VoIP VLAN, Power Request/Available, Trust Bitmap, System Name, Management Address, Location.

### Sample Files

The `samples/` directory contains real captured packets for offline testing:

```
samples/
  ruijie_S2910.txt            Ruijie S2910 (LLDP) — 16 TLVs
  H3C-S5120V2-28P-SI.txt      H3C S5120V2 (LLDP)
  H3C_FINAL_453bytes.txt       H3C LLDP (compact)
  S12700E.txt                  Huawei S12700E (LLDP)
  S5700-52P-LI-AC.txt          Huawei S5700 (LLDP)
  cisco_cdp.txt                Cisco CDP packet
  cisco_lldp.txt               Cisco LLDP packet
  juniper_10016.txt            Juniper MX10016 (LLDP)
  juniper_qfx5110.txt          Juniper QFX5110 (LLDP + DCBXP)
  ruijie.txt                   Ruijie (LLDP)
```

## Architecture Overview

### Backend Abstraction

The project uses a platform-specific backend architecture for network operations:

```
network/
  backend.py                   Abstract NetworkBackend (legacy)
  core/interfaces.py           NetworkInterface dataclass + NetworkAdapterBackend (current)
  backends/
    windows/adapter.py         WindowsNetworkBackend — PowerShell, registry, cfgmgr32
    macos/adapter.py           MacOSNetworkBackend — lldp_helper.py, networksetup, ifconfig
    posix/adapter.py           PosixNetworkBackend — Linux fallback via ip/ethtool
  elevated_op.py              Privileged operation helper (UAC / sudo)
  engine.py                   Network engine (prefer platform.get_backend())
  platform.py                 Platform detection and backend factory
```

Each backend provides:
- Interface enumeration (name, MAC, IP, gateway, DNS, DHCP, link speed, MTU)
- MAC address modification / restore
- Static IP / DHCP configuration
- Interface restart

### Capture Pipeline

```
User clicks Capture → capture_page.py
  → subprocess (elevated) → lldp.py --json-out
  → utils/packet_capture.py :: run_online_capture()
    → _scapy_suppress() — suppress macOS ipconfig stderr
    → AsyncSniffer (BPF kernel filter) — LLDP (0x88cc) + CDP (01:00:0c:cc:cc:cc)
    → wait_for_link() + trigger_link_renegotiation() — force fresh frames
    → Poll with deadline — fast mode (first frame) or thorough mode (both protocols)
  → Write JSON → GUI reads and displays
```

### Decision Engine

After capture, the decision engine infers port semantics:
- **Port role**: access / trunk / hybrid / uplink
- **Device type**: bridge / router / telephone / wlan
- **Confidence**: derived from TLV evidence
- **Intent**: management / data / voice / storage

## Build

PyInstaller onefile, excludes dev/data directories:

```powershell
venv\Scripts\pyinstaller.exe LLDP_CLI.spec --noconfirm
venv\Scripts\pyinstaller.exe LLDP_GUI.spec --noconfirm
```

Output:
- `dist\LLDP_CLI.exe` (~12 MB) — CLI version
- `dist\LLDP_GUI.exe` (~12 MB) — GUI version

## Internationalization (i18n)

The GUI supports 7 languages with automatic system language detection:

| Language | Code | Display Name |
|----------|------|--------------|
| English | `en` | English |
| Chinese | `zh` | 中文 |
| French | `fr` | Français |
| Spanish | `es` | Español |
| Russian | `ru` | Русский |
| Japanese | `ja` | 日本語 |
| Korean | `ko` | 한국어 |

Select from the dropdown in the top-right corner, or use `--lang`:

```bash
python lldp_gui.py --lang zh
```

## Known Issues & Limitations

### macOS

1. **Built-in Ethernet MAC spoofing**: Apple Silicon Macs (M1/M2/M3/M4) do not support MAC address modification on the built-in Ethernet adapter (`en0`). The tool detects this and reports the failure. **Solution**: Use a USB Ethernet adapter — these support MAC spoofing normally.

2. **macOS 14+ TCC restrictions**: `sudo` may not be able to read files on `~/Desktop/` due to kernel-level provenance enforcement. **Workaround**: Grant Full Disk Access to Terminal/Python in System Settings, or move the project to `/Applications/` or `~/Documents/`.

3. **DHCP server detection**: The `ipconfig getpacket` command used to detect DHCP server may return "not found" for interfaces without active DHCP leases. The tool falls back to `networksetup -getinfo`.

4. **Interface naming**: macOS names physical Ethernet interfaces `en0`, `en1`, etc. The scanner filters out virtual interfaces (utun, awdl, llw, bridge, etc.) automatically.

### Windows

- MAC modification requires admin privileges (auto-elevated via UAC).
- DHCP configuration uses netsh commands.

## Project Layout

```
lldp.py                    CLI entry — online capture, offline parse, elevation
lldp_gui.py                GUI entry — tkinter application, macOS startup elevation
lldp_helper.py             macOS privileged helper — networksetup, tcpdump, ifconfig
vendor_dispatcher.py       OUI/fingerprint dispatch for LLDP TLV 127

decoders/
  cisco_decoder.py         Cisco OUI 00:00:0C / 00:0C:05 private TLVs
  h3c_decoder.py           H3C / Comware OUI 00:12:BB private TLVs
  huawei_decoder.py        Huawei OUI 00:E0:FC private TLVs
  juniper_decoder.py       Juniper OUI 00:90:69 private TLVs (three-layer)
  ruijie_decoder.py        Ruijie OUI 00:12:BB private TLVs

engine/
  api.py                   Engine API layer
  decision_engine.py       Adapter — feeds from parsed result into inference rules
  port_profile.py          Port semantic inference (role, device type, confidence)

network/
  core/interfaces.py       NetworkInterface dataclass + NetworkAdapterBackend
  backends/
    windows/adapter.py     PowerShell-based Windows adapter backend
    macos/adapter.py       macOS adapter backend (lldp_helper)
    posix/adapter.py       POSIX (Linux) adapter backend
    platform.py            Platform detection and backend factory
  elevated_op.py           Privileged operation helper
  engine.py                Network engine core

ui/
  main_window.py           Notebook layout (Capture / History / Network tabs)
  capture_page.py          Online capture + offline file parse + display
  history_page.py          SQLite history browser with filters and statistics
  network_page.py          Local adapter info, MAC modify, IP configuration
  widgets.py               InfoCard reusable widget
  styles.py                Light/dark theme support

db/
  database.py              SQLite capture history (auto-migration schema)

i18n/
  config.py                Language configuration persistence (INI)
  translations.py          Translation manager (auto-detect, fallback)
  locales/                 7 language JSON files

utils/
  adapter_scanner.py       Unified adapter enumeration (OS-level + keyword)
  capture_engine.py        Persistent capture engine (always-on monitoring)
  elevator.py              Unified elevation: run_elevated() + is_admin()
  hexdump.py               Pure byte-array display
  interface_finder.py      Physical Ethernet discovery + link renegotiation
  link_monitor.py          Link status monitoring
  packet_capture.py        Scapy capture, de-duplication, neighbor summary
  platform_utils.py        Platform detection, theme, resource path
  protocol_parser.py       Shared LLDP/CDP parser + display formatting

samples/                   10 real captured packet files for offline testing
```
