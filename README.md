# Security Sentinel Hub - Unified Cyber Defense and Privacy Sentinel for Omarchy Linux

[![Omarchy Verified Plugin](https://img.shields.io/badge/Omarchy-Verified_Plugin-22c55e?style=for-the-badge)](https://github.com/omacom/omarchy-plugin-marketplace/issues/9531)
[![Version](https://img.shields.io/github/v/release/ozdil/omarchy-security-sentinel?style=for-the-badge)](https://github.com/ozdil/omarchy-security-sentinel/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/ozdil/omarchy-security-sentinel/rust.yml?branch=master&style=for-the-badge&label=CI)](https://github.com/ozdil/omarchy-security-sentinel/actions/workflows/rust.yml)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-Support_Development-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ozdil)

![Security Sentinel Preview](preview.png)

All-in-one native cyber defense, hardware integrity, and privacy sentinel plugin for Omarchy Linux.

Author: Ozan Ozdil (ozdil)  
License: MIT  
Plugin ID: ozdil.security-sentinel  
Version: 1.4.0 ([changelog](CHANGELOG.md))

---

## Overview

Security Sentinel Hub unifies 8 essential Linux defense and privacy subsystems into a single high-performance native Rust daemon (`sentinel-engine`) with an integrated, theme-harmonized Omarchy Quickshell dashboard. 
Fully hardened with HANCORE Military-Grade Security Standards, providing kernel-level zero-trust policies, bounded IPC processes, and real-time hardware integrity validation.

---

## What's New in 1.4.0

Release from a full-stack security audit. Highlights (full list in [CHANGELOG.md](CHANGELOG.md)):

- Event-driven background monitor: USB hot-plug is checked within a second, not on the next 20 s poll.
- BadUSB fingerprints pin serial number and interface classes, so a cloned VID:PID with an added keyboard is caught.
- Real CVE data from the Arch Security Tracker via `arch-audit`.
- Every socket names its process and PID; the socket anomaly analyzer now runs.
- Privileged actions go through the shipped polkit policy; PIDs are signalled via pidfd.
- USB Armor no longer locks out your own keyboard and mouse after "Trust Devices".
- Failed toggles roll back instead of reporting success; destructive actions need a confirming click.
- Simpler, flat Omarchy-style panel and dashboard.

---

## Subsystems and Features

Each subsystem features an interactive inspection menu:

1. Network and Sockets Radar: Real-time socket monitoring (`/proc/net/tcp*`, `/proc/net/udp*`) reporting Listening versus Established sockets and detecting suspicious ports. Expands to display individual listening ports (`LISTEN :53`, `LISTEN :631`) and active sockets.
2. BadUSB Defense & Hardware Armor: Hardware HID device monitoring (`/sys/bus/usb/devices`), maintaining a local device-fingerprint baseline (`trusted_usb.json`, mode 0600: VID:PID, serial number and interface classes) so a device that clones a trusted ID but adds a keyboard interface is flagged the moment it is plugged in (kernel uevent, no 20 s polling gap) to alert against unauthorized Rubber Ducky and BadUSB keystroke injectors. Features an instant UI killswitch to toggle USB Armor lockdown.
3. CVE Vulnerability Radar: Matches installed packages against the Arch Security Tracker via `arch-audit` (CVE IDs, severity, fixed version; cached for 6 h) and lists pending updates via `checkupdates` (pacman-contrib). A critical advisory that already has a fix raises an alert.
4. Authentication Watch: Systemd journald and PAM audit monitoring unauthorized login and SSH authentication failures over a rolling 24-hour window.
5. Tripwire Canaries & Self-Defense: Honey-token canary files with SHA-256 baseline verification for ransomware and tampering early warning. Includes active self-integrity verification (Self-Exe SHA-256 hash checks) and Panic Blackout triggers.
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

# Background monitor (started by the panel): reacts to USB hot-plug via kernel
# uevents within a second and keeps $XDG_RUNTIME_DIR/omarchy-security-sentinel/report.json fresh
sentinel-engine --daemon
```

---

## Security and Architecture Standards

Security Sentinel Hub complies strictly with the Omarchy Linux Security Standards (AGENTS.md):
- Subprocess Isolation: Process executions run in isolated process groups (`cmd.process_group(0)`) with non-blocking I/O and strict monotonic deadlines.
- Least Privilege: Monitoring runs unprivileged in user space. Interventions that need root (USB de-authorization, freeze, network quarantine) go through `pkexec` and the shipped polkit policy (`io.omarchy.sentinel.policy`), and the root-side helper re-validates every argument.
- State File Hardening: Baseline hashes and state files are written with POSIX mode 0600 permissions. Symlinks are rejected.
- Plain Text UI: All dynamic text rendered in QML components utilizes `textFormat: Text.PlainText` to prevent script and markup injection.

---

## Support & Sponsorship

If you find Security Sentinel Hub valuable and want to support independent Linux cyber defense:

<a href="https://buymeacoffee.com/ozdil" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 50px !important;width: 180px !important;" ></a>

---

## License

MIT License. See [LICENSE](LICENSE) for details.
