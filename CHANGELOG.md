# Changelog

All notable changes to Security Sentinel are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.5.0] - Unreleased

Fixes from a second full-stack analysis (engine, panel, dashboard,
packaging), plus the follow-ups to the review of the 1.4.0 hardening work.

### Security

- **CVE radar**: `arch-audit` prints severities as "High risk", which were
  all parsed as Unknown, so a fixable critical or high advisory never raised
  the module. Severities are read correctly; the cache file is versioned.
- **Tripwire**: a deleted `canary.token` or `canary.sha256` was re-created
  and reported intact, so rename-then-delete ransomware passed. Once armed,
  a missing canary is an ALERT; only "Reset canaries" re-creates it. The
  `/tmp` decoy is per user and created with `O_EXCL`.
- **USB Armor**: blocking needed a polkit prompt the BadUSB device itself
  could dismiss with Esc, and the cancel was remembered until replug. Blocks
  now use their own polkit action (`io.omarchy.sentinel.usb-block`) that the
  active session may run without a password; it refuses hubs. A failed
  block is retried after 60 s and shown as an ALERT.
- **Polkit**: `auth_admin_keep` became `auth_admin` on every action, so one
  approval no longer allows five minutes of prompt-free root actions.
  Re-enabling a blocked USB device has its own action.
- **No generic `pkexec kill`**: without the packaged helper, signalling
  another user's process fails with an explanation instead of a prompt that
  names no process and could hit a reused PID.
- **PID reuse**: reports carry each flagged process's start time and the
  panel and dashboard pass `<pid>:<start_time>`, so Freeze/Kill from a
  report up to a minute old refuse a different process.
- **Dashboard**: process names (settable by any local process) were shown
  as StyledText; every dashboard text is plain text now.
- **Hiding from the analyzer**: a command line padded past 64 KiB was
  blanked and scored 0; it is now analysed and the padding itself scored.
- **OpSec scrubber**: metadata between the scans of a progressive JPEG and
  everything after the end of the image (phone MPF images with their own
  EXIF/GPS, vendor trailers) survived cleaning; both are removed now.

### Fixed

- The panel and dashboard fail closed: they start as "ENGINE OFFLINE /
  UNKNOWN", show why a report is missing or invalid, and mark a report older
  than 90 s as stale. They used to show "ALL SYSTEMS SECURE" in all of
  these cases.
- Reports over 128 KiB were cut before `JSON.parse`, always failed, and the
  rewrite of the cache started back-to-back full scans. The engine now
  caps the report (16 flagged processes, 512-char command lines) and the UI
  no longer rescans on an invalid cache.
- Failed actions exit non-zero and the UI shows the engine's message.
- USB Armor's summary and notification count the devices the kernel
  reports blocked, not the ones a block was attempted on. An untrusted
  non-HID device (for example a USB DAC) is a WARNING, not CRITICAL.
- A scan can no longer overwrite the baseline that "Trust Devices" just
  saved; `--trust-all-usb` reports a save error.
- An unreadable `/proc/net` table or an invisible system journal is a
  warning, not "verified clean".
- Lost uevents (socket buffer overflow) trigger a USB rescan, and a burst
  of events delays it by at most 3 s.
- Ghost MAC handles SSIDs with a colon and treats `stable` MACs as
  randomized; DNS reports an `omarchy dns Custom` resolver and the toggle
  no longer replaces it with Cloudflare.
- An empty or relative `XDG_STATE_HOME` no longer puts state files in the
  working directory.
- `kernel_capabilities` is probed instead of a fixed list; `timestamp` is a
  real RFC 3339 time.
- Toggles show progress and are no longer flipped back by a report built
  before they finished.
- `sentinel-dashboard` brings the open window forward instead of starting a
  new instance on every click, and keeps the D-Bus session address.

### Packaging

- The PKGBUILD builds from the release tag in `$srcdir` (it built the
  caller's checkout via `$startdir`), installs the LICENSE and the missing
  dependencies, and puts the plugin in `/usr/share/omarchy-security-sentinel`
  with instructions to link it into `~/.config/omarchy/plugins`. The old
  location was never scanned by Omarchy.
- CI: CodeQL analyses Rust, and a new job lints the QML, the shell scripts
  and the PKGBUILD.

### Fixed

- **Immune processes**: a protected name such as `sshd` now only counts when
  the process runs the executable that daemon ships as. Before, any program
  under `/usr/` qualified, so a script run by `/usr/bin/python3` that renamed
  itself to `sshd` could not be frozen or terminated. Daemons still running
  from a binary replaced by a package upgrade keep their immunity.
- **Signals after a password prompt**: freeze, terminate and resume pass the
  process start time to the root-side helper along with the PID. If the
  process exits and its PID is reused while polkit asks for the password,
  the helper refuses instead of signalling the unrelated new process.
- **Blackout status**: the dashboard no longer presents the panic blackout as
  engaged when that is only inferred from Sentinel's own marker file (for
  example after root cleared the table). It shows "blackout unconfirmed".
  The report and `--blackout-status` gained a `confirmed` field.
- **Authentication Watch**: a journal query that fails or times out now
  reports a warning ("Auth logs unavailable") instead of SECURE, and the
  query no longer shares its deadline with the version probe.

### Changed

- CI actions are pinned to commit SHAs, with the Rust toolchains passed as
  explicit inputs.
- The USB Armor decisions (corrupt baseline, hubs, already-blocked devices,
  keeping unplugged devices when trusting) are covered by unit tests.

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

## [1.3.2]

- Sanitized USB product strings, private state storage for the network
  blackout, SECURITY.md and CodeQL workflow.

## [1.3.1]

- Fixed the USB Armor toggle and the sysfs write permissions for BadUSB
  de-authorization.

## [1.3.0]

- Kernel defense actions, keyboard navigation and documentation.

[1.4.0]: https://github.com/ozdil/omarchy-security-sentinel/releases/tag/v1.4.0
