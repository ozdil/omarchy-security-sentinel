# Security Sentinel Hub - Unified Cyber Defense and Privacy Sentinel for Omarchy Linux

All-in-one native cyber defense, hardware integrity, and privacy sentinel plugin for Omarchy Linux.

Author: Ozan Ozdil (ozdil)  
License: MIT  
Plugin ID: ozdil.security-sentinel

---

## Overview

Security Sentinel Hub unifies 8 essential Linux defense and privacy subsystems into a single high-performance native Rust daemon (`sentinel-engine`) with an integrated, theme-harmonized Omarchy Quickshell dashboard.

---

## Subsystems and Features

Each subsystem features an interactive inspection menu:

1. Network and Sockets Radar: Real-time socket monitoring (`/proc/net/tcp*`, `/proc/net/udp*`) reporting Listening versus Established sockets and detecting suspicious ports. Expands to display individual listening ports (`LISTEN :53`, `LISTEN :631`) and active sockets.
2. BadUSB Defense: Hardware HID device monitoring (`/sys/bus/usb/devices`), maintaining a cryptographically hashed local baseline (`trusted_usb.json`) to alert against unauthorized Rubber Ducky and BadUSB keystroke injectors. Expands to list all attached USB hardware, device vendor:product IDs, and provides a 1-click action to trust all currently connected USB devices.
3. CVE Vulnerability Radar: Local package vulnerability auditing synchronized with Arch Security Tracker and pending updates across installed packages.
4. Authentication Watch: Systemd journald and PAM audit monitoring unauthorized root, sudo, and SSH login failures over a rolling 24-hour window.
5. Tripwire Canaries: Honey-token canary files with SHA-256 baseline verification for ransomware and tampering early warning, with an instant action to reset baseline hashes.
6. DNS Leak Guard (DoT): Native integration with `/usr/bin/omarchy-dns`, featuring an interactive toggle to enable encrypted Cloudflare DNS-over-TLS (DoT 1.1.1.1) and prevent ISP plaintext sniffing.
7. Ghost MAC (Wi-Fi Randomizer): NetworkManager integration (`nmcli`) featuring an interactive toggle enforcing per-connection randomized MAC addressing and triggering live interface re-association to cloak hardware vendor fingerprints.
8. OpSec Metadata Scrubber: Lossless in-memory JPEG and PNG metadata and EXIF stripper. Supports panel drag-and-drop, native file picker dialog, and batch cleaning for downloads.

---

## Requirements

- cargo and rustc (Rust toolchain, for building from source)
- libnotify (for desktop notifications via notify-send)
- networkmanager (nmcli, for MAC address management)
- systemd (journalctl, for authentication log monitoring)

---

## Installation and Setup

### Why Building from Source is Required
Under the Omarchy Linux Security Standards (AGENTS.md Rule 5.3), precompiled binaries are strictly forbidden from Git repositories to guarantee user system integrity. Therefore, the native engine must be compiled from source on your local machine after adding the plugin.

### Step 1: Add the Plugin to Omarchy
```bash
omarchy plugin add https://github.com/ozdil/omarchy-security-sentinel.git
```

### Step 2: Build the Native Engine
Navigate to the plugin directory and compile the engine:
```bash
cd ~/.config/omarchy/plugins/ozdil.security-sentinel
cargo build --release --locked
install -m 755 target/release/sentinel-engine ./sentinel-engine
```

### Step 3: Add to Omarchy Shell Configuration
Add `ozdil.security-sentinel` to `bar.layout.right` in `~/.config/omarchy/shell.json`:
```json
{
  "id": "ozdil.security-sentinel"
}
```

### Step 4: Restart Shell
```bash
omarchy-restart-shell
```

---

## CLI Usage

The sentinel engine can be run directly from the command line:

```bash
# Output formatted status summary
sentinel-engine

# Run status check for bar widget
sentinel-engine --status

# Output machine-readable JSON telemetry
sentinel-engine --json
```

---

## Security and Architecture Standards

Security Sentinel Hub complies strictly with the Omarchy Linux Security Standards (AGENTS.md):
- Subprocess Isolation: Process executions run in isolated process groups (`cmd.process_group(0)`) with non-blocking I/O and strict monotonic deadlines.
- Safe Privilege Boundaries: Sudo and system operations are bounded without shell string interpolation.
- State File Hardening: Baseline hashes and state files are written with POSIX mode 0600 permissions. Symlinks are rejected.
- Plain Text UI: All dynamic text rendered in QML components utilizes `textFormat: Text.PlainText` to prevent script and markup injection.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
