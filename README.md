# 🛡️ Security Sentinel Hub • Unified Cyber Defense & Privacy Hub

> **All-in-one native cyber defense, hardware integrity, and privacy sentinel plugin for Omarchy Linux.**

Author: **Ozan Özdil (ozdil)**  
License: **MIT**  
Plugin ID: `ozdil.security-sentinel`

---

## ✨ Overview

**Security Sentinel Hub** unifies 8 essential Linux defense and privacy subsystems into a single high-performance native Rust daemon (`sentinel-engine`) with an integrated, theme-harmonized Omarchy Quickshell dashboard.

### 🛡️ Integrated Subsystems

1. **Network & Sockets Radar:** Real-time socket monitoring (`/proc/net/tcp`) and intrusion detection.
2. **BadUSB Defense:** Hardware HID device monitoring and unauthorized injection filter (`/sys/bus/usb/devices`).
3. **CVE Vulnerability Radar:** Local package vulnerability auditing synchronized with Arch Security Tracker.
4. **Authentication Watch:** Systemd journal and PAM authentication failure watchdog.
5. **Tripwire Canaries:** Honey-token canary files with SHA-256 baseline verification for ransomware early warning.
6. **DNS Leak Guard:** Real-time DNS resolver auditing and DNS-over-TLS (DoT) verification.
7. **Ghost MAC:** Wi-Fi hardware MAC address cloaking and telemetry prevention.
8. **OpSec Cleaner:** Lossless in-memory JPEG/PNG metadata and EXIF stripper.

---

## 🚀 Native Omarchy Integration

- **Bar Widget:** Sleek, flat, theme-matching `` (`\uf132`) shield icon inheriting `bar.barForeground`.
- **KeyboardPanel:** Native Omarchy layer-shell popup styled strictly with `Color.popups.*`, `Style.selectedFillFor`, and zero hardcoded colors.
- **Zero Heavy Dependencies:** 100% native Rust engine with zero script dependencies.

---

## 📦 Installation & Setup

```bash
# Clone to Omarchy plugins directory
git clone https://github.com/ozdil/omarchy-security-sentinel.git ~/.config/omarchy/plugins/ozdil.security-sentinel

# Build native release binary
cd ~/.config/omarchy/plugins/ozdil.security-sentinel
cargo build --release
cp target/release/sentinel-engine ~/.local/bin/sentinel-engine
```

Add to `bar.layout.right` in `~/.config/omarchy/shell.json`:
```json
{
  "id": "ozdil.security-sentinel"
}
```

Reload the shell:
```bash
omarchy-restart-shell
```
