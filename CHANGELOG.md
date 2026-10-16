# Changelog

All notable changes to Security Sentinel are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.4.0] - 2026-10-16

This release comes out of a full-stack security audit of the engine, the
panel and the packaging. It fixes several cases where the plugin reported
"secure" while it was not, moves every privileged action behind the shipped
polkit policy, and replaces polling with an event-driven background monitor.

### Added

- **Background monitor** (`sentinel-engine --daemon`): reacts to USB
  hot-plug through kernel uevents within about a second instead of the next
  20 s poll, and publishes a cached report to
  `$XDG_RUNTIME_DIR/omarchy-security-sentinel/report.json` (0600). The panel
  starts it; it stays in the graphical session so polkit `allow_active` works.
- **Real CVE data**: the CVE radar matches installed packages against the
  Arch Security Tracker via `arch-audit` (CVE IDs, severity, fixed version,
  cached for 6 h). A critical advisory with a released fix raises an alert.
- **Socket attribution**: every listening and connected socket names its
  process and PID. Real IPv6 addresses are shown, and the socket analyzer
  (rogue sshd, nc/socat listeners, plaintext services) now actually runs.
- **BadUSB fingerprints**: the trust baseline (`trusted_usb.json` v2) pins
  serial number and interface classes, not just VID:PID, so a device that
  clones a trusted ID but adds a keyboard interface is caught. Old baselines
  are upgraded in place.
- **Confirmations**: Freeze, Kill and Panic Blackout need a second click,
  and the armed button names its target.
- CI workflow: `cargo fmt`, `clippy -D warnings`, tests and an MSRV 1.88
  build on every push.

### Fixed

- Privilege escalation goes through a root-side helper mode, so `pkexec`
  runs `/usr/bin/sentinel-engine` and the shipped polkit actions and messages
  apply. No more `sh -c` in privileged paths; every argument is re-validated
  as root.
- Freeze, terminate and thaw signal through a pidfd, so a recycled PID is
  never hit. A process renamed to `sshd` or `Hyprland` is no longer immune.
- CLI arguments are dispatched on the first argument only, so a file name
  passed to `--clean-files` cannot trigger another command.
- Network quarantine is one idempotent nftables transaction covering both
  directions; socket sever only targets connected sockets and checks the
  result.
- Toggles (Ghost MAC, DNS, USB Armor) report failure and the panel rolls
  the switch back, instead of always announcing success.
- The CVE radar reports a warning when `checkupdates` or `arch-audit` fails,
  instead of "up to date".
- Auth watch filters in journald, so the 24 h window is really covered.
- The JPEG metadata scrubber keeps colour profiles and refuses malformed
  files instead of overwriting the original with a truncated copy.
- Perl and Ruby reverse-shell signatures could never match; they do now.
- Forensic evidence JSON is built with serde instead of string splicing.
- USB Armor no longer strands trusted devices:
  - a corrupt baseline does not de-authorize every device;
  - hubs are never auto-blocked (that cut off the keyboard behind them);
  - "Trust Devices" re-enables blocked devices, waits for them, then trusts
    the full set;
  - identical units (two hubs, two receivers) both stay trusted;
  - root hub interfaces are read under their real sysfs names;
  - entries recorded with an empty interface set are re-learned;
  - a declined block prompt is remembered until the device is replugged,
    so pkexec is not raised on every scan.
- USB product strings are sanitized and all dynamic panel text is plain
  text.

### Changed

- Panel and dashboard follow the Omarchy look: flat rows, square corners,
  theme colours, plain-text verdicts, no duplicate buttons, shorter labels.
  Notifications use short plain sentences.
- The engine is split into one module per subsystem; statuses are typed
  enums. The JSON read by the panel is unchanged.
- The self-assigned "verified" mark is removed from the manifest, the About
  dialog and the README. Omarchy has no third-party verification program;
  only plugins that ship with Omarchy are marked first-party by the shell.

## [1.3.2]

- Sanitized USB product strings, private state storage for the network
  blackout, SECURITY.md and CodeQL workflow.

## [1.3.1]

- Fixed the USB Armor toggle and the sysfs write permissions for BadUSB
  de-authorization.

## [1.3.0]

- Kernel defense actions, keyboard navigation and documentation.

[1.4.0]: https://github.com/ozdil/omarchy-security-sentinel/releases/tag/v1.4.0
