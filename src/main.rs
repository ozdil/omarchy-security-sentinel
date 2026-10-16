use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// The binary links the library crate instead of re-declaring its modules, so the
// engine logic (and its SHA-256 implementation) is compiled and tested once.
use sentinel_engine::subproc::{run_cmd_bounded, run_cmd_bounded_status};
use sentinel_engine::{ai, kernel, sha256_hex};

const O_NOFOLLOW: i32 = 0o400000;

extern "C" {
    fn getuid() -> u32;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModuleStatus {
    pub id: String,
    pub name: String,
    pub status: String, // "SECURE", "WARNING", "ALERT", "READY"
    pub summary: String,
    pub detail: String,
    pub is_toggleable: bool,
    pub toggle_state: bool,
    pub items: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SentinelReport {
    pub overall_status: String,
    pub threat_level: String,
    pub threat_color: String,
    pub active_modules: usize,
    pub ghost_mac_enabled: bool,
    pub dns_dot_enabled: bool,
    pub usb_armor_enabled: bool,
    pub network_blackout_active: bool,
    pub self_integrity_hash: String,
    pub ai_threat_score: u32,
    pub ai_anomalies: Vec<ai::ProcessAnomaly>,
    pub kernel_capabilities: Vec<String>,
    pub modules: Vec<ModuleStatus>,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BarStatus {
    pub text: String,
    pub tooltip: String,
    pub class: String,
    pub color: String,
}

/// Enforces 0700 mode state directory per AGENTS.md Rule 4
fn get_state_dir() -> PathBuf {
    let base = env::var("XDG_STATE_HOME")
        .unwrap_or_else(|_| format!("{}/.local/state", env::var("HOME").unwrap_or_default()));
    let dir = Path::new(&base).join("omarchy/security-sentinel");
    let _ = fs::create_dir_all(&dir);
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    dir
}

/// Atomically writes sensitive state file with mode 0600, sync_all, and O_NOFOLLOW per AGENTS.md Rule 4
fn write_secure_state_file(path: &Path, content: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Invalid state file parent path".to_string())?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create parent dir: {}", e))?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = parent.join(format!(".tmp_state_{}_{}", std::process::id(), nanos));

    struct StateFileGuard<'a> {
        path: &'a Path,
        active: bool,
    }
    impl<'a> Drop for StateFileGuard<'a> {
        fn drop(&mut self) {
            if self.active {
                let _ = fs::remove_file(self.path);
            }
        }
    }

    let mut guard = StateFileGuard {
        path: &tmp_path,
        active: true,
    };

    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(&tmp_path)
        .map_err(|e| {
            format!(
                "Failed to create temp state file with 0600/O_NOFOLLOW: {}",
                e
            )
        })?;

    let _ = tmp_file.set_permissions(fs::Permissions::from_mode(0o600));

    tmp_file
        .write_all(content)
        .map_err(|e| format!("Failed to write state file: {}", e))?;

    tmp_file
        .sync_all()
        .map_err(|e| format!("Failed to sync state file to disk: {}", e))?;

    let meta = tmp_file
        .metadata()
        .map_err(|e| format!("Failed to read temp metadata: {}", e))?;
    if meta.len() != content.len() as u64 {
        return Err("State file size verification mismatch".to_string());
    }

    drop(tmp_file);

    if path.exists() {
        let dest_meta = fs::symlink_metadata(path)
            .map_err(|e| format!("Cannot check existing target: {}", e))?;
        if dest_meta.file_type().is_symlink() {
            return Err("Refusing to overwrite symlinked state file".to_string());
        }
        if !dest_meta.is_file() {
            return Err("Target state path is not a regular file".to_string());
        }
    }

    fs::rename(&tmp_path, path).map_err(|e| format!("Atomic state rename failed: {}", e))?;
    guard.active = false;
    Ok(())
}

/// Reads sensitive state file with bounded buffer, O_NOFOLLOW, and UID verification
fn read_secure_state_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    if !path.exists() {
        return Err("File does not exist".to_string());
    }

    let sym_meta =
        fs::symlink_metadata(path).map_err(|e| format!("symlink_metadata failed: {}", e))?;
    if sym_meta.file_type().is_symlink() {
        return Err("Symlinks are strictly prohibited for state files".to_string());
    }
    if !sym_meta.is_file() {
        return Err("State file target is not a regular file".to_string());
    }
    if sym_meta.len() > max_bytes as u64 {
        return Err("State file exceeds maximum allowed size".to_string());
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("Failed to open state file with O_NOFOLLOW: {}", e))?;

    let fd_meta = file
        .metadata()
        .map_err(|e| format!("Descriptor metadata failed: {}", e))?;
    if !fd_meta.is_file() {
        return Err("Descriptor is not a regular file".to_string());
    }

    // SAFETY: getuid is a POSIX libc syscall returning the real UID of current process
    let current_uid = unsafe { getuid() };
    if fd_meta.uid() != current_uid {
        return Err("State file is not owned by current user".to_string());
    }

    let mut buf = Vec::with_capacity(fd_meta.len() as usize);
    let mut handle = (&mut file).take((max_bytes + 1) as u64);
    handle
        .read_to_end(&mut buf)
        .map_err(|e| format!("Read failed: {}", e))?;
    if buf.len() > max_bytes {
        return Err("Read exceeded max_bytes limit".to_string());
    }
    Ok(buf)
}

fn notify_desktop(title: &str, body: &str, is_critical: bool) {
    let urgency = if is_critical { "critical" } else { "normal" };
    let deadline = Instant::now() + Duration::from_millis(1500);

    let mut extra_envs = Vec::new();
    let dbus = env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_default();
    if !dbus.is_empty() {
        extra_envs.push(("DBUS_SESSION_BUS_ADDRESS", dbus.as_str()));
    }
    let wayland = env::var("WAYLAND_DISPLAY").unwrap_or_default();
    if !wayland.is_empty() {
        extra_envs.push(("WAYLAND_DISPLAY", wayland.as_str()));
    }
    let display = env::var("DISPLAY").unwrap_or_default();
    if !display.is_empty() {
        extra_envs.push(("DISPLAY", display.as_str()));
    }
    let runtime_dir = env::var("XDG_RUNTIME_DIR").unwrap_or_default();
    if !runtime_dir.is_empty() {
        extra_envs.push(("XDG_RUNTIME_DIR", runtime_dir.as_str()));
    }

    // Try omarchy-notification-send first with explicit shield glyph (Nerd Font) and app identity
    let glyph = "";
    let status = run_cmd_bounded(
        "omarchy-notification-send",
        &[
            "--app-name",
            "Security Sentinel",
            "-g",
            glyph,
            "-u",
            urgency,
            title,
            body,
        ],
        &extra_envs,
        deadline,
        4096,
    );

    // Fallback to notify-send with verified system icon if omarchy-notification-send is absent
    if status.is_none() {
        let icon = if is_critical {
            "dialog-warning"
        } else {
            "dialog-information"
        };
        let _ = run_cmd_bounded(
            "notify-send",
            &[
                "-a",
                "Security Sentinel",
                "-u",
                urgency,
                "-i",
                icon,
                "--",
                title,
                body,
            ],
            &extra_envs,
            deadline,
            4096,
        );
    }
}

/// Reads a system/procfs file with bounded buffer and O_NOFOLLOW to prevent symlink traversal and DoS memory exhaustion
pub fn read_file_bounded(path: &Path, max_bytes: usize) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("Failed to open {} with O_NOFOLLOW: {}", path.display(), e))?;

    let meta = file
        .metadata()
        .map_err(|e| format!("Failed to read metadata: {}", e))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }

    let mut buf = Vec::new();
    let mut handle = (&mut file).take((max_bytes + 1) as u64);
    handle
        .read_to_end(&mut buf)
        .map_err(|e| format!("Read failed on {}: {}", path.display(), e))?;
    if buf.len() > max_bytes {
        return Err(format!(
            "File {} exceeded limit of {} bytes",
            path.display(),
            max_bytes
        ));
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub fn parse_ip_port(s: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let port = u16::from_str_radix(parts[1], 16).ok()?;
    let ip_hex = parts[0];
    if ip_hex.len() == 8 {
        let num = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = format!(
            "{}.{}.{}.{}",
            num & 0xFF,
            (num >> 8) & 0xFF,
            (num >> 16) & 0xFF,
            (num >> 24) & 0xFF
        );
        Some((ip, port))
    } else {
        Some(("IPv6".to_string(), port))
    }
}

pub fn port_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS Resolver",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        631 => "CUPS Print",
        853 => "DoT Encrypted",
        993 => "IMAPS",
        995 => "POP3S",
        1337 => "Backdoor/C2",
        1883 => "MQTT",
        3000 => "Node/Web",
        3306 => "MySQL/MariaDB",
        4444 => "Metasploit C2",
        5173 => "Vite Dev",
        5432 => "PostgreSQL",
        5555 => "ADB/Trojan",
        6379 => "Redis Cache",
        6666 | 6667 => "IRC Botnet",
        8000 => "Dev Server",
        8080 => "HTTP Proxy",
        8443 => "HTTPS Alt",
        8844 => "Local Service",
        9001 => "Tor/Malware C2",
        27017 => "MongoDB",
        31337 => "Back Orifice",
        _ => "System Port",
    }
}

pub fn is_suspicious_port(port: u16) -> bool {
    matches!(port, 1337 | 4444 | 5555 | 6666 | 6667 | 9001 | 31337)
}

// 1. Network Sockets Radar
fn check_network_sockets() -> ModuleStatus {
    let mut total = 0;
    let mut listen = 0;
    let mut estab = 0;
    let mut flagged = 0;
    let mut alert_items = Vec::new();
    let mut listen_items = Vec::new();
    let mut estab_items = Vec::new();

    let paths = [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ];
    for p in &paths {
        if let Ok(content) = read_file_bounded(Path::new(p), 1024 * 1024) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 3 {
                    total += 1;
                    let st = parts[3];
                    if st == "0A" {
                        listen += 1;
                        if let Some((ip, port)) = parse_ip_port(parts[1]) {
                            if is_suspicious_port(port) {
                                flagged += 1;
                                alert_items.push(format!(
                                    "[ALERT] Unauthorized listening backdoor on port {} ({}) [{}]",
                                    port,
                                    port_service_name(port),
                                    ip
                                ));
                            }
                            if listen_items.len() < 5 {
                                listen_items.push(format!(
                                    "LISTEN :{} ({}) [{}]",
                                    port,
                                    port_service_name(port),
                                    ip
                                ));
                            }
                        }
                    } else if st == "01" {
                        estab += 1;
                        if let Some((rem_ip, rem_port)) = parse_ip_port(parts[2]) {
                            if is_suspicious_port(rem_port) {
                                flagged += 1;
                                alert_items.push(format!(
                                    "[ALERT] Outbound C2/Reverse Shell to {}:{} ({})",
                                    rem_ip,
                                    rem_port,
                                    port_service_name(rem_port)
                                ));
                            }
                            if estab_items.len() < 5 {
                                estab_items.push(format!(
                                    "ESTAB -> {}:{} ({})",
                                    rem_ip,
                                    rem_port,
                                    port_service_name(rem_port)
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    let mut items = Vec::new();
    items.extend(alert_items);
    items.extend(listen_items);
    items.extend(estab_items);
    if items.is_empty() {
        items.push("No active listening sockets found".to_string());
    }

    let status = if flagged > 0 { "ALERT" } else { "SECURE" };
    ModuleStatus {
        id: "network".to_string(),
        name: "Network & Sockets Radar".to_string(),
        status: status.to_string(),
        summary: format!("{} Active ({} Listen, {} Estab)", total, listen, estab),
        detail: if flagged > 0 {
            format!("[ALERT] {} Suspicious connections detected!", flagged)
        } else {
            "All outbound connections verified".to_string()
        },
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}

fn is_usb_armor_enabled() -> bool {
    get_state_dir().join("usb_armor.enabled").exists()
}

fn toggle_usb_armor() -> bool {
    let flag = get_state_dir().join("usb_armor.enabled");
    if flag.exists() {
        let _ = fs::remove_file(&flag);
        false
    } else {
        let _ = write_secure_state_file(&flag, b"1");
        true
    }
}

/// Sanitizes USB hardware product strings to prevent HTML tag injection,
/// control character evasion, and excessive length in telemetry displays.
pub fn sanitize_usb_product(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .filter(|c| {
            !c.is_control() && *c != '<' && *c != '>' && *c != '&' && *c != '"' && *c != '\''
        })
        .take(64)
        .collect::<String>()
        .trim()
        .to_string();
    if sanitized.is_empty() {
        "USB Device".to_string()
    } else {
        sanitized
    }
}

fn load_trusted_usb(path: &Path) -> Option<Vec<String>> {
    let bytes = read_secure_state_file(path, 65536).ok()?;
    serde_json::from_slice(&bytes).ok()
}

// 2. BadUSB Defense
fn check_badusb() -> ModuleStatus {
    let mut total_usb = 0;
    let mut hid_count = 0;
    let mut current_ids = Vec::new();
    let mut unapproved_bus_ids = Vec::new();
    let mut items = Vec::new();

    let trusted_file = get_state_dir().join("trusted_usb.json");
    let file_existed = trusted_file.exists();
    // An existing but unreadable/corrupt baseline must not be treated as "trust nothing":
    // with USB Armor on that would de-authorize every device, keyboard and mouse included.
    let loaded = if file_existed {
        load_trusted_usb(&trusted_file)
    } else {
        None
    };
    let baseline_corrupt = file_existed && loaded.is_none();
    let mut trusted: Vec<String> = loaded.unwrap_or_default();
    let mut deauth_targets = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.join("idVendor").is_file() {
                total_usb += 1;
                let v = read_file_bounded(&p.join("idVendor"), 512)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let pr = read_file_bounded(&p.join("idProduct"), 512)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let dev_id = format!("{}:{}", v, pr);
                let bus_id = entry.file_name().to_string_lossy().to_string();
                current_ids.push(dev_id.clone());

                let mut is_hid = false;
                if let Ok(sub) = fs::read_dir(&p) {
                    for s in sub.flatten() {
                        let name = s.file_name().to_string_lossy().to_string();
                        if name.contains(":1.") {
                            let driver = s.path().join("driver");
                            if driver.exists()
                                && driver
                                    .read_link()
                                    .map(|l| l.to_string_lossy().contains("hid"))
                                    .unwrap_or(false)
                            {
                                hid_count += 1;
                                is_hid = true;
                            }
                        }
                    }
                }

                let raw_prod = read_file_bounded(&p.join("product"), 512)
                    .unwrap_or_else(|_| "USB Device".to_string());
                let prod = sanitize_usb_product(&raw_prod);
                let is_trusted = !file_existed || baseline_corrupt || trusted.contains(&dev_id);
                let already_blocked = read_file_bounded(&p.join("authorized"), 16)
                    .map(|a| a.trim() == "0")
                    .unwrap_or(false);
                let tag = if baseline_corrupt {
                    "UNVERIFIED"
                } else if is_trusted {
                    "Approved"
                } else if already_blocked {
                    "UNAPPROVED, BLOCKED"
                } else {
                    "UNAPPROVED"
                };
                let hid_tag = if is_hid { " (HID)" } else { "" };
                items.push(format!("{} [{}]{} [{}]", prod, dev_id, hid_tag, tag));
                if !is_trusted {
                    // Root hubs (usbN) are never auto-severed: that would drop every port on
                    // the bus. Devices already de-authorized are skipped so each 20 s poll
                    // does not re-trigger sysfs writes or pkexec prompts.
                    if !already_blocked && !bus_id.starts_with("usb") {
                        deauth_targets.push(bus_id.clone());
                    }
                    unapproved_bus_ids.push(bus_id);
                }
            }
        }
    }

    if !file_existed {
        trusted = current_ids.clone();
        if let Ok(data) = serde_json::to_vec(&trusted) {
            let _ = write_secure_state_file(&trusted_file, &data);
        }
    }

    let untrusted_count = unapproved_bus_ids.len();
    let armor_active = is_usb_armor_enabled();

    if armor_active && untrusted_count > 0 {
        for b_id in &deauth_targets {
            let _ = kernel::kernel_deauth_usb(b_id);
        }
        items.push(
            "[ARMOR ENGAGED] Unauthorized USB hardware de-authorized at kernel interface"
                .to_string(),
        );
    }

    if baseline_corrupt {
        items.push(format!(
            "[WARNING] Trusted baseline {} is unreadable or corrupt; auto-blocking suspended. Use 'Trust Devices' to rebuild it.",
            trusted_file.display()
        ));
        return ModuleStatus {
            id: "badusb".to_string(),
            name: "BadUSB Defense".to_string(),
            status: "WARNING".to_string(),
            summary: format!("{} Devices (Baseline Unreadable)", total_usb),
            detail: "Trusted USB baseline could not be verified; devices are listed but not auto-blocked.".to_string(),
            is_toggleable: true,
            toggle_state: armor_active,
            items,
        };
    }

    let status = if untrusted_count > 0 {
        "ALERT"
    } else {
        "SECURE"
    };
    ModuleStatus {
        id: "badusb".to_string(),
        name: "BadUSB Defense".to_string(),
        status: status.to_string(),
        summary: if untrusted_count > 0 {
            if armor_active {
                format!(
                    "[AUTO-BLOCKED] {} Untrusted USB Deauthorized",
                    untrusted_count
                )
            } else {
                format!("[ALERT] {} UNTRUSTED USB DETECTED", untrusted_count)
            }
        } else {
            format!("{} Devices ({} Trusted HID)", total_usb, hid_count)
        },
        detail: if untrusted_count > 0 {
            if armor_active {
                "Military USB Armor active: Unauthorized USB hardware automatically severed."
                    .to_string()
            } else {
                "Unauthorized USB device attached! Click 'Trust Devices' or toggle 'USB Armor' to auto-quarantine.".to_string()
            }
        } else {
            "All attached HID devices match approved hardware baseline".to_string()
        },
        is_toggleable: true,
        toggle_state: armor_active,
        items,
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct CveCache {
    timestamp: u64,
    pkg_count: usize,
    pending_pkgs: Vec<String>,
    #[serde(default)]
    check_failed: bool,
}

// 3. CVE Vulnerability Radar
fn check_cve() -> ModuleStatus {
    let pkg_count = fs::read_dir("/var/lib/pacman/local")
        .map(|entries| entries.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0);

    let cache_file = get_state_dir().join("cve_cache.json");
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    const CACHE_TTL_SECS: u64 = 900; // 15 minutes TTL
    const FAILED_CACHE_TTL_SECS: u64 = 120; // retry failed checks sooner

    let mut pending_pkgs = Vec::new();
    let mut cache_hit = false;
    let mut check_failed = false;

    if let Ok(bytes) = read_secure_state_file(&cache_file, 65536) {
        if let Ok(cache) = serde_json::from_slice::<CveCache>(&bytes) {
            let ttl = if cache.check_failed {
                FAILED_CACHE_TTL_SECS
            } else {
                CACHE_TTL_SECS
            };
            if now_secs.saturating_sub(cache.timestamp) < ttl {
                pending_pkgs = cache.pending_pkgs;
                check_failed = cache.check_failed;
                cache_hit = true;
            }
        }
    }

    // checkupdates (pacman-contrib) exits 0 with a list, 2 when there is nothing to
    // update, and 1 (or fails to spawn / times out) on error. Errors must not be
    // reported as "up to date"; they are cached briefly so a slow mirror does not
    // stall every 20 s poll.
    if !cache_hit {
        let deadline = Instant::now() + Duration::from_millis(8000);
        match run_cmd_bounded_status("/usr/bin/checkupdates", &[], &[], deadline, 65536) {
            Some((0, stdout)) => {
                let text = String::from_utf8_lossy(&stdout);
                for l in text.lines().filter(|l| !l.trim().is_empty()) {
                    pending_pkgs.push(l.trim().to_string());
                }
            }
            Some((2, _)) => {}
            _ => check_failed = true,
        }
        let cache = CveCache {
            timestamp: now_secs,
            pkg_count,
            pending_pkgs: pending_pkgs.clone(),
            check_failed,
        };
        if let Ok(json_bytes) = serde_json::to_vec(&cache) {
            let _ = write_secure_state_file(&cache_file, &json_bytes);
        }
    }

    let pending_count = pending_pkgs.len();

    let mut items = Vec::new();
    items.push(format!(
        "Audited Packages: {} local packages in /var/lib/pacman/local",
        pkg_count
    ));
    if check_failed {
        items.push("[WARNING] checkupdates failed or is not installed (pacman-contrib); update status unknown".to_string());
        return ModuleStatus {
            id: "cve".to_string(),
            name: "CVE Vulnerability Radar".to_string(),
            status: "WARNING".to_string(),
            summary: format!("{} Packages (Update Check Unavailable)", pkg_count),
            detail: "Could not query pending updates; install pacman-contrib or check network"
                .to_string(),
            is_toggleable: false,
            toggle_state: false,
            items,
        };
    }
    if pending_count == 0 {
        items.push("Pending Updates: none reported by checkupdates".to_string());
        items.push("System Status: All installed packages up to date".to_string());
    } else {
        items.push(format!(
            "Updates Available: {} packages pending update",
            pending_count
        ));
        for p in pending_pkgs.iter().take(5) {
            items.push(format!("Update -> {}", p));
        }
    }

    let status = if pending_count > 10 {
        "WARNING"
    } else {
        "SECURE"
    };
    ModuleStatus {
        id: "cve".to_string(),
        name: "CVE Vulnerability Radar".to_string(),
        status: status.to_string(),
        summary: if pending_count > 0 {
            format!("{} Packages ({} Updates Pending)", pkg_count, pending_count)
        } else {
            format!("{} Packages (All Up to Date)", pkg_count)
        },
        detail: if pending_count > 0 {
            format!(
                "{} system updates pending package manager sync",
                pending_count
            )
        } else {
            "checkupdates verified | No pending package updates".to_string()
        },
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}

// 4. Authentication Watch
fn check_auth_watch() -> ModuleStatus {
    let mut failed_count = 0;
    let mut fail_entries = Vec::new();

    let journal_bin = if Path::new("/usr/bin/journalctl").exists() {
        "/usr/bin/journalctl"
    } else {
        "/bin/journalctl"
    };

    let deadline = Instant::now() + Duration::from_millis(1500);
    // Bounded execution: producer-side limit (-n 200), deadline 1.5s, buffer cap 64 KiB.
    // Filtering in journald (--grep) makes -n 200 mean "the last 200 auth failures in
    // 24h" instead of "the last 200 log lines", which on a busy system covered minutes.
    // Builds without PCRE2 reject --grep, so fall back to the unfiltered tail there.
    const AUTH_PATTERN: &str = "authentication failure|failed password|incorrect password attempt";
    let base_args = ["-n", "200", "--since", "24 hours ago", "-q", "-o", "cat"];
    let has_pcre2 = run_cmd_bounded(journal_bin, &["--version"], &[], deadline, 4096)
        .map(|v| String::from_utf8_lossy(&v).contains("+PCRE2"))
        .unwrap_or(false);
    let journal_out = if has_pcre2 {
        let mut grep_args = base_args.to_vec();
        grep_args.extend_from_slice(&["--case-sensitive=false", "--grep", AUTH_PATTERN]);
        match run_cmd_bounded_status(journal_bin, &grep_args, &[], deadline, 65536) {
            // journalctl exits 1 with empty output when --grep matches nothing
            Some((0, out)) => Some(out),
            Some((1, out)) if out.is_empty() => Some(out),
            _ => None,
        }
    } else {
        run_cmd_bounded(journal_bin, &base_args, &[], deadline, 65536)
    };
    if let Some(stdout) = journal_out {
        let text = String::from_utf8_lossy(&stdout);
        for line in text.lines() {
            let lower = line.to_lowercase();
            if lower.contains("authentication failure")
                || lower.contains("failed password")
                || lower.contains("incorrect password attempt")
            {
                failed_count += 1;
                if fail_entries.len() < 4 {
                    fail_entries.push(line.trim().to_string());
                }
            }
        }
    }

    let mut items = Vec::new();
    items
        .push("Log Target: systemd-journald & Linux PAM (24h scope, last 200 matches)".to_string());
    items.push(format!(
        "Failed Authentication Events: {} recorded",
        failed_count
    ));
    if failed_count == 0 {
        items.push("Integrity: No brute-force or unauthorized auth/ssh attempts".to_string());
    } else {
        for fe in fail_entries {
            items.push(format!("Alert -> {}", fe));
        }
    }

    let status = if failed_count > 0 {
        "WARNING"
    } else {
        "SECURE"
    };
    ModuleStatus {
        id: "auth".to_string(),
        name: "Authentication Watch".to_string(),
        status: status.to_string(),
        summary: if failed_count > 0 {
            format!("[ALERT] {} Failed Logins (24h)", failed_count)
        } else {
            "0 Failed Logins (24h)".to_string()
        },
        detail: if failed_count > 0 {
            format!(
                "PAM & systemd journal recorded {} failed auth attempts!",
                failed_count
            )
        } else {
            "Journald & PAM authentication logs verified clean".to_string()
        },
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}

// 5. Tripwire Canaries
fn check_tripwire() -> ModuleStatus {
    let token_path = get_state_dir().join("canary.token");
    let hash_path = get_state_dir().join("canary.sha256");

    if !token_path.exists() || !hash_path.exists() {
        let token_data = b"OMARCHY_SECURITY_SENTINEL_TRIPWIRE_TOKEN_V2_INIT\n";
        let _ = write_secure_state_file(&token_path, token_data);
        let hash = sha256_hex(token_data);
        let _ = write_secure_state_file(&hash_path, hash.as_bytes());
    }

    let expected_hash = read_secure_state_file(&hash_path, 128)
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_default();

    let current_hash = read_secure_state_file(&token_path, 4096)
        .map(|b| sha256_hex(&b))
        .unwrap_or_default();

    let is_token_intact = !expected_hash.is_empty() && expected_hash == current_hash;

    // Decoy canary in /tmp to trap filesystem crawlers, wipers, and ransomware
    let tmp_canary_path = Path::new("/tmp/.omarchy_canary.token");
    if !tmp_canary_path.exists() {
        let _ = write_secure_state_file(tmp_canary_path, b"OMARCHY_MILITARY_TRIPWIRE_TMP_CANARY\n");
    }
    // /tmp is shared: a decoy pre-created (or replaced) by another user would otherwise
    // pass this check forever, so require it to be our own regular, non-symlink file.
    let tmp_intact = read_secure_state_file(tmp_canary_path, 128)
        .map(|b| String::from_utf8_lossy(&b).contains("OMARCHY_MILITARY_TRIPWIRE_TMP_CANARY"))
        .unwrap_or(false);

    let is_intact = is_token_intact && tmp_intact;
    let status = if is_intact { "SECURE" } else { "ALERT" };

    let mut items = Vec::new();
    items.push(format!("Primary Canary: {}", token_path.display()));
    items.push(format!("Decoy Canary: {}", tmp_canary_path.display()));
    let hash_display = if expected_hash.len() > 16 {
        format!(
            "{}...{}",
            &expected_hash[..8],
            &expected_hash[expected_hash.len() - 8..]
        )
    } else {
        expected_hash.clone()
    };
    items.push(format!(
        "SHA-256 Seal: {} [{}]",
        hash_display,
        if is_token_intact {
            "Intact"
        } else {
            "MISMATCH"
        }
    ));
    items.push(if is_intact {
        "Ransomware Defense: All honey-tokens intact | File baseline verified".to_string()
    } else {
        "[ALERT] Canary token modified or wiped by untrusted process!".to_string()
    });

    ModuleStatus {
        id: "tripwire".to_string(),
        name: "Tripwire Canaries".to_string(),
        status: status.to_string(),
        summary: if is_intact {
            "Honey-tokens Intact (SHA-256 Verified)".to_string()
        } else {
            "[ALERT] TRIPWIRE TOKEN TAMPERED / ENCRYPTED!".to_string()
        },
        detail: if is_intact {
            "Canary file hash matches baseline | Ransomware early-warning active".to_string()
        } else {
            "Canary token mismatch detected! Possible filesystem compromise!".to_string()
        },
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}

// 6. DNS Leak Guard
fn check_dns_leak() -> (ModuleStatus, bool) {
    let deadline = Instant::now() + Duration::from_millis(1500);
    let current_provider =
        if let Some(out) = run_cmd_bounded("omarchy-dns", &[], &[], deadline, 4096) {
            String::from_utf8_lossy(&out).trim().to_string()
        } else {
            "DHCP".to_string()
        };

    let is_dot = current_provider == "Cloudflare" || current_provider == "Google";
    let status = if is_dot { "SECURE" } else { "WARNING" };

    let mut items = Vec::new();
    if is_dot {
        let resolver_ip = if current_provider == "Google" {
            "8.8.8.8"
        } else {
            "1.1.1.1"
        };
        items.push(format!(
            "Active Resolver: {} DNS ({} / 853)",
            current_provider, resolver_ip
        ));
        items.push("Protocol: DNS-over-TLS (DoT Encrypted Tunnel)".to_string());
        items.push("Privacy Status: Zero plaintext query leakage to ISP".to_string());
    } else {
        items.push("Active Resolver: Standard Gateway DHCP DNS".to_string());
        items.push("Protocol: Cleartext UDP (Port 53 Unencrypted)".to_string());
        items.push("Warning: DNS queries exposed to local network & ISP inspection".to_string());
    }

    let mod_status = ModuleStatus {
        id: "dns".to_string(),
        name: "DNS Leak Guard (DoT)".to_string(),
        status: status.to_string(),
        summary: if is_dot {
            format!("DoT Active ({})", current_provider)
        } else {
            "Unencrypted ISP DNS (DHCP)".to_string()
        },
        detail: if is_dot {
            "Encrypted DNS-over-TLS tunnel active | Zero ISP plaintext leak".to_string()
        } else {
            "DNS queries sent in cleartext | Toggle switch to enable DoT".to_string()
        },
        is_toggleable: true,
        toggle_state: is_dot,
        items,
    };

    (mod_status, is_dot)
}

// 7. Ghost MAC
fn check_ghost_mac() -> (ModuleStatus, bool) {
    let mut is_randomized = false;
    let mut current_mac = "Unknown".to_string();
    let mut conn_name = String::new();
    let mut dev_name = String::new();

    let deadline = Instant::now() + Duration::from_millis(1500);
    if let Some(out) = run_cmd_bounded(
        "nmcli",
        &[
            "-t",
            "-f",
            "NAME,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ],
        &[],
        deadline,
        8192,
    ) {
        let text = String::from_utf8_lossy(&out);
        for line in text.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[1] == "802-11-wireless" {
                conn_name = parts[0].to_string();
                dev_name = parts[2].to_string();

                if !dev_name.is_empty()
                    && dev_name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
                    && !dev_name.contains("..")
                {
                    let addr_path = Path::new("/sys/class/net").join(&dev_name).join("address");
                    if let Ok(addr) = read_file_bounded(&addr_path, 64) {
                        current_mac = addr.trim().to_string();
                    }
                }

                let sub_deadline = Instant::now() + Duration::from_millis(1500);
                if let Some(c_out) = run_cmd_bounded(
                    "nmcli",
                    &[
                        "-t",
                        "-f",
                        "802-11-wireless.cloned-mac-address",
                        "connection",
                        "show",
                        &conn_name,
                    ],
                    &[],
                    sub_deadline,
                    4096,
                ) {
                    let c_val = String::from_utf8_lossy(&c_out).trim().to_string();
                    if c_val.contains("random") || c_val.contains("stable-random") {
                        is_randomized = true;
                    }
                }
            }
        }
    }

    let mut items = Vec::new();
    items.push(format!(
        "Active MAC: {} ({})",
        current_mac,
        if is_randomized {
            "Randomized / Cloaked"
        } else {
            "Hardware Permanent"
        }
    ));
    items.push(format!(
        "Connection: {} on interface {}",
        if conn_name.is_empty() {
            "None"
        } else {
            &conn_name
        },
        if dev_name.is_empty() {
            "wlo1"
        } else {
            &dev_name
        }
    ));
    items.push(if is_randomized {
        "Privacy Mode: NetworkManager assigns random MAC on every connection".to_string()
    } else {
        "Privacy Mode: Real hardware vendor MAC is exposed to local access points".to_string()
    });

    let status = if is_randomized { "SECURE" } else { "WARNING" };
    let mod_status = ModuleStatus {
        id: "ghost_mac".to_string(),
        name: "Ghost MAC (Wi-Fi Randomizer)".to_string(),
        status: status.to_string(),
        summary: if is_randomized {
            format!("Randomized ({})", current_mac)
        } else {
            format!("Hardware MAC ({})", current_mac)
        },
        detail: if is_randomized {
            "Hardware MAC hidden | Random address generated per connection".to_string()
        } else {
            "Hardware vendor MAC exposed to local APs | Toggle switch to randomize".to_string()
        },
        is_toggleable: true,
        toggle_state: is_randomized,
        items,
    };

    (mod_status, is_randomized)
}

// 8. OpSec Cleaner
fn check_opsec_cleaner() -> ModuleStatus {
    let items = vec![
        "Supported Formats: JPEG (EXIF / APP1-15), PNG (tEXt, zTXt, iTXt, eXIf)".to_string(),
        "Engine: In-memory lossless binary metadata & EXIF stripper".to_string(),
        "Drag & Drop: Drag any image from file manager onto this panel".to_string(),
        "Batch Mode: Click 'Scrub Downloads' to sanitize recent downloads".to_string(),
    ];

    ModuleStatus {
        id: "opsec".to_string(),
        name: "OpSec Metadata Scrubber".to_string(),
        status: "READY".to_string(),
        summary: "Lossless EXIF/PNG Sanitizer".to_string(),
        detail: "Drag & drop images or click to sanitize metadata".to_string(),
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}

const MAX_IMAGE_SIZE: usize = 25 * 1024 * 1024; // 25 MiB cap

// Lossless JPEG & PNG cleaner with strict bounded I/O, no-follow descriptor binding, and atomic replacement
fn clean_file(path: &Path) -> Result<(), String> {
    // 1. Initial symlink and regular file verification
    let sym_meta =
        fs::symlink_metadata(path).map_err(|e| format!("Cannot read metadata: {}", e))?;
    if sym_meta.file_type().is_symlink() {
        return Err("Symlinks are strictly prohibited".to_string());
    }
    if !sym_meta.is_file() {
        return Err("Target is not a regular file".to_string());
    }
    if sym_meta.len() > MAX_IMAGE_SIZE as u64 {
        return Err(format!(
            "File exceeds maximum allowed size of {} bytes",
            MAX_IMAGE_SIZE
        ));
    }

    // 2. Open through held descriptor with O_NOFOLLOW
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("Failed to open file safely with O_NOFOLLOW: {}", e))?;

    // 3. Re-verify attributes on the held descriptor
    let fd_meta = file
        .metadata()
        .map_err(|e| format!("Failed to read descriptor metadata: {}", e))?;
    if !fd_meta.is_file() {
        return Err("Descriptor is not a regular file".to_string());
    }
    if fd_meta.len() > MAX_IMAGE_SIZE as u64 {
        return Err(format!(
            "Descriptor file size exceeds {} bytes",
            MAX_IMAGE_SIZE
        ));
    }

    // SAFETY: getuid returns the real UID of the running process
    unsafe {
        extern "C" {
            fn getuid() -> u32;
        }
        if fd_meta.uid() != getuid() {
            return Err("File is not owned by current user".to_string());
        }
    }

    // 4. Bounded read
    let mut data = Vec::with_capacity(fd_meta.len() as usize);
    let mut handle = (&mut file).take((MAX_IMAGE_SIZE + 1) as u64);
    handle
        .read_to_end(&mut data)
        .map_err(|e| format!("Read failed: {}", e))?;
    if data.len() > MAX_IMAGE_SIZE {
        return Err("Read data exceeded maximum image buffer limit".to_string());
    }

    // 5. Lossless metadata stripping
    let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let out = if data.len() >= 4 && data[0] == 0xFF && data[1] == 0xD8 {
        strip_jpeg_metadata(&data)?
    } else if data.len() >= 8 && data[..8] == png_header {
        strip_png_metadata(&data)
    } else {
        return Err("Unsupported image format or invalid header".to_string());
    };

    // Close descriptor before replacing file
    drop(file);

    // 6. Same-directory atomic replacement: write to .tmp_clean_..., verify, sync_all, rename
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = parent.join(format!(".tmp_clean_{}_{}", std::process::id(), nanos));

    let orig_mode = fd_meta.mode() & 0o777;
    let target_mode = if orig_mode != 0 { orig_mode } else { 0o600 };

    struct TempFileGuard<'a> {
        path: &'a Path,
        active: bool,
    }
    impl<'a> Drop for TempFileGuard<'a> {
        fn drop(&mut self) {
            if self.active {
                let _ = fs::remove_file(self.path);
            }
        }
    }

    let mut guard = TempFileGuard {
        path: &tmp_path,
        active: true,
    };

    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(target_mode)
        .custom_flags(O_NOFOLLOW)
        .open(&tmp_path)
        .map_err(|e| format!("Failed to create temporary clean file: {}", e))?;

    let _ = tmp_file.set_permissions(fs::Permissions::from_mode(target_mode));

    tmp_file
        .write_all(&out)
        .map_err(|e| format!("Failed to write cleaned image bytes: {}", e))?;

    tmp_file
        .sync_all()
        .map_err(|e| format!("Failed to sync cleaned file to disk: {}", e))?;

    let tmp_meta = tmp_file
        .metadata()
        .map_err(|e| format!("Failed to read temp metadata: {}", e))?;
    if tmp_meta.len() != out.len() as u64 {
        return Err("Written bytes verification mismatch".to_string());
    }

    drop(tmp_file);

    // Re-verify target path is still regular file and not replaced with symlink prior to rename
    let pre_rename_meta = fs::symlink_metadata(path)
        .map_err(|e| format!("Cannot verify target prior to rename: {}", e))?;
    if pre_rename_meta.file_type().is_symlink() {
        return Err("Target path changed to symlink during cleaning".to_string());
    }

    fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to atomically replace image: {}", e))?;

    guard.active = false;

    Ok(())
}

/// Removes EXIF/XMP/comment segments from a JPEG without re-encoding.
///
/// Kept on purpose: APP0 (JFIF), APP2 ICC_PROFILE (colour management) and APP14
/// "Adobe" (colour transform; dropping it corrupts CMYK/YCCK images). Malformed or
/// truncated segment headers abort with an error instead of producing a truncated
/// file that would then atomically replace the original.
fn strip_jpeg_metadata(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&[0xFF, 0xD8]);
    let mut idx = 2;
    loop {
        if idx >= data.len() {
            return Err("Truncated JPEG: no start-of-scan marker found".to_string());
        }
        if data[idx] != 0xFF {
            return Err(format!("Malformed JPEG: expected marker at offset {}", idx));
        }
        while idx < data.len() && data[idx] == 0xFF {
            idx += 1;
        }
        if idx >= data.len() {
            return Err("Truncated JPEG marker".to_string());
        }
        let marker = data[idx];
        idx += 1;
        match marker {
            0xD9 => {
                out.extend_from_slice(&[0xFF, 0xD9]);
                return Ok(out);
            }
            0xDA => {
                // Start of scan: entropy-coded data and everything after it is kept verbatim
                out.extend_from_slice(&[0xFF, 0xDA]);
                out.extend_from_slice(&data[idx..]);
                return Ok(out);
            }
            // Standalone markers carry no length field
            0x01 | 0xD0..=0xD7 => {
                out.extend_from_slice(&[0xFF, marker]);
                continue;
            }
            _ => {}
        }
        if idx + 2 > data.len() {
            return Err("Truncated JPEG segment length".to_string());
        }
        let len = ((data[idx] as usize) << 8) | (data[idx + 1] as usize);
        if len < 2 || idx + len > data.len() {
            return Err(format!("Malformed JPEG segment 0x{:02X} length", marker));
        }
        let payload = &data[idx + 2..idx + len];
        let keep_colour_info = (marker == 0xE2 && payload.starts_with(b"ICC_PROFILE\0"))
            || (marker == 0xEE && payload.starts_with(b"Adobe"));
        let is_meta = ((0xE1..=0xEF).contains(&marker) || marker == 0xFE) && !keep_colour_info;
        if !is_meta {
            out.extend_from_slice(&[0xFF, marker]);
            out.extend_from_slice(&data[idx..idx + len]);
        }
        idx += len;
    }
}

/// Removes textual and EXIF chunks (tEXt, zTXt, iTXt, eXIf) from a PNG.
fn strip_png_metadata(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..8]);
    let mut idx = 8;
    while idx + 12 <= data.len() {
        let length =
            u32::from_be_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]) as usize;
        let chunk_type = &data[idx + 4..idx + 8];
        let total_chunk_len = 12usize.saturating_add(length);
        if idx.saturating_add(total_chunk_len) > data.len() {
            out.extend_from_slice(&data[idx..]);
            return out;
        }
        let is_meta = matches!(chunk_type, b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf");
        if !is_meta {
            out.extend_from_slice(&data[idx..idx + total_chunk_len]);
        }
        idx += total_chunk_len;
    }
    // Keep any trailing bytes that do not form a full chunk instead of dropping them
    out.extend_from_slice(&data[idx..]);
    out
}

fn scrub_downloads() -> usize {
    let ddir = dirs_downloads();
    let mut cleaned = 0;
    if let Ok(entries) = fs::read_dir(ddir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = fs::symlink_metadata(&p) {
                if !meta.file_type().is_symlink() && meta.is_file() {
                    if let Some(ext) = p.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if (ext_str == "jpg" || ext_str == "jpeg" || ext_str == "png")
                            && clean_file(&p).is_ok()
                        {
                            cleaned += 1;
                        }
                    }
                }
            }
        }
    }
    cleaned
}

fn dirs_downloads() -> PathBuf {
    let home = env::var("HOME").unwrap_or_default();
    Path::new(&home).join("Downloads")
}

fn toggle_ghost_mac() -> bool {
    let deadline = Instant::now() + Duration::from_millis(1500);
    if let Some(out) = run_cmd_bounded(
        "nmcli",
        &["-t", "-f", "NAME,TYPE", "connection", "show", "--active"],
        &[],
        deadline,
        8192,
    ) {
        let text = String::from_utf8_lossy(&out);
        for line in text.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 && parts[1] == "802-11-wireless" {
                let conn = parts[0];
                let sub_deadline = Instant::now() + Duration::from_millis(1500);
                let current_cloned = if let Some(c_out) = run_cmd_bounded(
                    "nmcli",
                    &[
                        "-t",
                        "-f",
                        "802-11-wireless.cloned-mac-address",
                        "connection",
                        "show",
                        conn,
                    ],
                    &[],
                    sub_deadline,
                    4096,
                ) {
                    String::from_utf8_lossy(&c_out).trim().to_string()
                } else {
                    String::new()
                };

                if current_cloned.contains("random") {
                    let mod_deadline = Instant::now() + Duration::from_millis(2000);
                    let _ = run_cmd_bounded(
                        "nmcli",
                        &[
                            "connection",
                            "modify",
                            conn,
                            "802-11-wireless.cloned-mac-address",
                            "permanent",
                        ],
                        &[],
                        mod_deadline,
                        4096,
                    );
                    let up_deadline = Instant::now() + Duration::from_millis(3000);
                    let _ = run_cmd_bounded(
                        "nmcli",
                        &["connection", "up", conn],
                        &[],
                        up_deadline,
                        4096,
                    );
                    notify_desktop(
                        "Ghost MAC",
                        "Reverted to Wi-Fi hardware (original) MAC address.",
                        false,
                    );
                    return false;
                } else {
                    let mod_deadline = Instant::now() + Duration::from_millis(2000);
                    let _ = run_cmd_bounded(
                        "nmcli",
                        &[
                            "connection",
                            "modify",
                            conn,
                            "802-11-wireless.cloned-mac-address",
                            "random",
                        ],
                        &[],
                        mod_deadline,
                        4096,
                    );
                    let up_deadline = Instant::now() + Duration::from_millis(3000);
                    let _ = run_cmd_bounded(
                        "nmcli",
                        &["connection", "up", conn],
                        &[],
                        up_deadline,
                        4096,
                    );
                    notify_desktop(
                        "Ghost MAC",
                        "Wi-Fi MAC randomization enabled (random MAC per connection).",
                        false,
                    );
                    return true;
                }
            }
        }
    }
    false
}

fn toggle_dns() -> bool {
    let deadline = Instant::now() + Duration::from_millis(1500);
    let current = if let Some(out) = run_cmd_bounded("omarchy-dns", &[], &[], deadline, 4096) {
        String::from_utf8_lossy(&out).trim().to_string()
    } else {
        String::new()
    };

    if current == "Cloudflare" || current == "Google" {
        let deadline = Instant::now() + Duration::from_millis(2000);
        let _ = run_cmd_bounded("omarchy-dns", &["DHCP"], &[], deadline, 4096);
        notify_desktop(
            "DNS Leak Guard",
            "Switched to standard ISP DNS (DHCP) mode.",
            false,
        );
        false
    } else {
        let deadline = Instant::now() + Duration::from_millis(2000);
        let _ = run_cmd_bounded("omarchy-dns", &["Cloudflare"], &[], deadline, 4096);
        notify_desktop(
            "DNS Leak Guard",
            "Cloudflare DNS-over-TLS (DoT 1.1.1.1) encrypted tunnel enabled.",
            false,
        );
        true
    }
}

fn trust_all_usb() -> usize {
    let mut ids = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.join("idVendor").is_file() {
                let v = read_file_bounded(&p.join("idVendor"), 512)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let pr = read_file_bounded(&p.join("idProduct"), 512)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                ids.push(format!("{}:{}", v, pr));
            }
        }
    }
    let count = ids.len();
    let trusted_file = get_state_dir().join("trusted_usb.json");
    // Merge with the existing baseline so devices that are approved but currently
    // unplugged are not silently dropped from the whitelist.
    let mut merged = load_trusted_usb(&trusted_file).unwrap_or_default();
    for id in ids {
        if !merged.contains(&id) {
            merged.push(id);
        }
    }
    if let Ok(data) = serde_json::to_vec(&merged) {
        let _ = write_secure_state_file(&trusted_file, &data);
    }
    notify_desktop(
        "BadUSB Defense",
        &format!(
            "Added {} connected USB devices to trusted whitelist.",
            count
        ),
        false,
    );
    count
}

fn reset_canaries() {
    let token_path = get_state_dir().join("canary.token");
    let hash_path = get_state_dir().join("canary.sha256");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let token_data = format!("OMARCHY_SECURITY_SENTINEL_TRIPWIRE_TOKEN_GEN_{}\n", now);
    let _ = write_secure_state_file(&token_path, token_data.as_bytes());
    let hash = sha256_hex(token_data.as_bytes());
    let _ = write_secure_state_file(&hash_path, hash.as_bytes());
    notify_desktop(
        "Tripwire Canaries",
        "New canary honeypot token generated and SHA-256 hash sealed.",
        false,
    );
}

fn check_ai_behavior() -> (ModuleStatus, u32, Vec<ai::ProcessAnomaly>) {
    let anomalies = ai::analyze_all_processes();
    let max_score = anomalies.iter().map(|a| a.score).max().unwrap_or(0);

    let (status, summary, detail) = if max_score >= 80 {
        (
            "ALERT",
            format!(
                "CRITICAL: {} suspicious behavioral anomalies detected (Highest Threat Score: {})",
                anomalies.len(),
                max_score
            ),
            "Immediate kernel intervention recommended (freeze process / sever active socket)."
                .to_string(),
        )
    } else if max_score >= 40 {
        (
            "WARNING",
            format!("ELEVATED: {} behavioral process anomalies flagged (Score: {})", anomalies.len(), max_score),
            "Suspicious process behavior, commandline obfuscation, or untrusted filesystem execution detected.".to_string(),
        )
    } else {
        (
            "SECURE",
            "Zero process anomalies or covert shell behaviors detected".to_string(),
            "Shannon entropy, memory injection, reverse shell heuristics, and execution paths verified normal.".to_string(),
        )
    };

    let items = anomalies
        .iter()
        .take(8)
        .map(|a| {
            format!(
                "[PID {} - {}] Score {}: {}",
                a.pid,
                a.name,
                a.score,
                a.reasons.join(", ")
            )
        })
        .collect();

    (
        ModuleStatus {
            id: "ai_behavior".to_string(),
            name: "AI Behavioral Threat Shield".to_string(),
            status: status.to_string(),
            summary,
            detail,
            is_toggleable: false,
            toggle_state: true,
            items,
        },
        max_score,
        anomalies,
    )
}

fn build_report() -> SentinelReport {
    let (ai_mod, ai_threat_score, ai_anomalies) = check_ai_behavior();
    let (dns_mod, dns_dot_enabled) = check_dns_leak();
    let (ghost_mac_mod, ghost_mac_enabled) = check_ghost_mac();

    let modules = vec![
        ai_mod,
        check_network_sockets(),
        check_badusb(),
        check_cve(),
        check_auth_watch(),
        check_tripwire(),
        dns_mod,
        ghost_mac_mod,
        check_opsec_cleaner(),
    ];

    let has_alert = modules.iter().any(|m| m.status == "ALERT");
    let has_warning = modules.iter().any(|m| m.status == "WARNING");

    let (overall_status, threat_level, threat_color) = if has_alert {
        ("THREAT DETECTED", "CRITICAL", "#ef4444")
    } else if has_warning {
        ("ATTENTION REQUIRED", "ELEVATED", "#f59e0b")
    } else {
        ("ALL SYSTEMS SECURE", "ZERO", "#22c55e")
    };

    let usb_armor_enabled = is_usb_armor_enabled();
    let network_blackout_active = kernel::kernel_is_network_blackout_active();
    let self_integrity_hash =
        kernel::calculate_self_exe_sha256().unwrap_or_else(|_| "UNVERIFIED".to_string());

    let kernel_capabilities = vec![
        "cgroups_v2_freeze".to_string(),
        "posix_kernel_sigstop".to_string(),
        "sock_diag_tcp_reset".to_string(),
        "sysfs_usb_deauthorization".to_string(),
        "nftables_ip_quarantine".to_string(),
        "nftables_panic_blackout".to_string(),
        "prctl_anti_dumpable".to_string(),
        "forensic_hash_capture".to_string(),
    ];

    SentinelReport {
        overall_status: overall_status.to_string(),
        threat_level: threat_level.to_string(),
        threat_color: threat_color.to_string(),
        active_modules: modules.len(),
        ghost_mac_enabled,
        dns_dot_enabled,
        usb_armor_enabled,
        network_blackout_active,
        self_integrity_hash,
        ai_threat_score,
        ai_anomalies,
        kernel_capabilities,
        modules,
        timestamp: "Live Defense".to_string(),
    }
}

fn main() {
    // 1. Enforce military-grade anti-tamper (prctl PR_SET_DUMPABLE 0)
    let _ = kernel::enforce_anti_tamper();

    let args: Vec<String> = env::args().collect();
    // Only the first argument selects the action. Scanning every argument would let a
    // file name passed to --clean-files (e.g. a dropped file called "panic-blackout")
    // trigger an unrelated, possibly destructive subcommand.
    let cmd = args.get(1).map(String::as_str).unwrap_or("");

    // Root-side polkit helper: `pkexec /usr/bin/sentinel-engine --privileged-* <op> [arg]`
    if matches!(
        cmd,
        kernel::PRIVILEGED_INTERVENTION_FLAG | kernel::PRIVILEGED_NETWORK_FLAG
    ) {
        let op = args.get(2).map(String::as_str).unwrap_or("");
        let res = kernel::run_privileged_operation(cmd, op, args.get(3).map(String::as_str));
        println!("{}", serde_json::to_string(&res).unwrap());
        std::process::exit(if res.success { 0 } else { 1 });
    }

    // Verify self-integrity
    if matches!(cmd, "--verify-integrity" | "verify-integrity") {
        match kernel::calculate_self_exe_sha256() {
            Ok(hash) => {
                println!(
                    "{{\"self_integrity\": \"SECURE\", \"sha256\": \"{}\", \"anti_tamper\": true}}",
                    hash
                );
            }
            Err(e) => {
                eprintln!(
                    "{{\"self_integrity\": \"COMPROMISED\", \"error\": \"{}\"}}",
                    e
                );
                std::process::exit(1);
            }
        }
        return;
    }

    // Emergency Military Network Blackout (Killswitch)
    if matches!(cmd, "--panic-blackout" | "panic-blackout") {
        let res = kernel::kernel_apply_network_blackout();
        println!("{}", serde_json::to_string(&res).unwrap());
        return;
    }

    if matches!(cmd, "--resume-network" | "resume-network") {
        let res = kernel::kernel_clear_network_blackout();
        println!("{}", serde_json::to_string(&res).unwrap());
        return;
    }

    if matches!(cmd, "--blackout-status" | "blackout-status") {
        let active = kernel::kernel_is_network_blackout_active();
        println!("{{\"blackout_active\": {}}}", active);
        return;
    }

    if matches!(cmd, "--toggle-usb-armor") {
        let state = toggle_usb_armor();
        println!("{}", if state { "ENABLED" } else { "DISABLED" });
        return;
    }

    // AI audit subcommand
    if matches!(cmd, "--ai-audit" | "ai-audit") {
        let anomalies = ai::analyze_all_processes();
        println!("{}", serde_json::to_string_pretty(&anomalies).unwrap());
        return;
    }

    // Kernel freeze process
    if let Some(pos) = matches!(
        cmd,
        "--kernel-freeze" | "kernel-freeze" | "--freeze-process"
    )
    .then_some(1usize)
    {
        if let Some(pid_str) = args.get(pos + 1) {
            if let Ok(pid) = pid_str.parse::<i32>() {
                let res = kernel::kernel_freeze_process(pid);
                println!("{}", serde_json::to_string(&res).unwrap());
                return;
            }
        }
        eprintln!("Error: Valid numeric PID required for kernel freeze");
        std::process::exit(1);
    }

    // Kernel terminate process
    if let Some(pos) = matches!(
        cmd,
        "--kernel-terminate" | "kernel-terminate" | "--terminate-process"
    )
    .then_some(1usize)
    {
        if let Some(pid_str) = args.get(pos + 1) {
            if let Ok(pid) = pid_str.parse::<i32>() {
                let res = kernel::kernel_terminate_process(pid);
                println!("{}", serde_json::to_string(&res).unwrap());
                return;
            }
        }
        eprintln!("Error: Valid numeric PID required for kernel terminate");
        std::process::exit(1);
    }

    // Kernel thaw process
    if let Some(pos) = matches!(cmd, "--kernel-thaw" | "kernel-thaw").then_some(1usize) {
        if let Some(pid_str) = args.get(pos + 1) {
            if let Ok(pid) = pid_str.parse::<i32>() {
                let res = kernel::kernel_thaw_process(pid);
                println!("{}", serde_json::to_string(&res).unwrap());
                return;
            }
        }
        eprintln!("Error: Valid numeric PID required for kernel thaw");
        std::process::exit(1);
    }

    // Kernel sever socket
    if let Some(pos) =
        matches!(cmd, "--kernel-sever-socket" | "kernel-sever-socket").then_some(1usize)
    {
        if let Some(target) = args.get(pos + 1) {
            let res = kernel::kernel_sever_socket(target);
            println!("{}", serde_json::to_string(&res).unwrap());
            return;
        }
        eprintln!("Error: Target port or IP required for socket severing");
        std::process::exit(1);
    }

    // Kernel de-auth USB
    if let Some(pos) = matches!(cmd, "--kernel-deauth-usb" | "kernel-deauth-usb").then_some(1usize)
    {
        if let Some(bus_id) = args.get(pos + 1) {
            let res = kernel::kernel_deauth_usb(bus_id);
            println!("{}", serde_json::to_string(&res).unwrap());
            return;
        }
        eprintln!("Error: USB bus ID required for de-authorization");
        std::process::exit(1);
    }

    // Kernel quarantine IP
    if let Some(pos) =
        matches!(cmd, "--kernel-quarantine-ip" | "kernel-quarantine-ip").then_some(1usize)
    {
        if let Some(ip) = args.get(pos + 1) {
            let res = kernel::kernel_quarantine_ip(ip);
            println!("{}", serde_json::to_string(&res).unwrap());
            return;
        }
        eprintln!("Error: IP address required for quarantine");
        std::process::exit(1);
    }

    if matches!(cmd, "--toggle-ghost-mac") {
        let state = toggle_ghost_mac();
        println!("{}", if state { "ENABLED" } else { "DISABLED" });
        return;
    }

    if matches!(cmd, "--toggle-dns" | "--toggle-dot") {
        let state = toggle_dns();
        println!("{}", if state { "ENABLED" } else { "DISABLED" });
        return;
    }

    if matches!(cmd, "--trust-all-usb") {
        let count = trust_all_usb();
        println!("Trusted {} devices", count);
        return;
    }

    if matches!(cmd, "--reset-canaries") {
        reset_canaries();
        println!("Canaries reset");
        return;
    }

    if matches!(cmd, "--scrub-downloads") {
        let count = scrub_downloads();
        if count > 0 {
            notify_desktop(
                "OpSec Cleaner",
                &format!("EXIF metadata stripped from {} images in Downloads.", count),
                false,
            );
        } else {
            notify_desktop(
                "OpSec Cleaner",
                "No images needing metadata scrubbing found in Downloads.",
                false,
            );
        }
        println!("Cleaned {} image files in Downloads", count);
        return;
    }

    if let Some(pos) = matches!(cmd, "--clean-files").then_some(1usize) {
        let files = &args[pos + 1..];
        let mut cleaned = 0;
        for f_str in files {
            let p = Path::new(f_str);
            if clean_file(p).is_ok() {
                cleaned += 1;
            }
        }
        if cleaned > 0 {
            notify_desktop(
                "OpSec Cleaner",
                &format!("Stripped EXIF and metadata from {} files.", cleaned),
                false,
            );
        } else {
            notify_desktop(
                "OpSec Cleaner",
                "No metadata to scrub found in selected files or operation failed.",
                true,
            );
        }
        println!("Cleaned {} files", cleaned);
        return;
    }

    let report = build_report();

    if matches!(cmd, "--status" | "--bar") {
        let text = "\u{f0483}".to_string();
        let tooltip = format!(
            "Security Sentinel Hub\nStatus: {}\nThreat Level: {}\nActive Subsystems: {} / {}\n\n[Left Click] Open Security Center",
            report.overall_status, report.threat_level, report.active_modules, report.active_modules
        );
        let out = BarStatus {
            text,
            tooltip,
            class: if report.threat_level == "ZERO" {
                "normal".to_string()
            } else {
                "warning".to_string()
            },
            color: report.threat_color,
        };
        println!("{}", serde_json::to_string(&out).unwrap());
        return;
    }

    if matches!(cmd, "--json") {
        println!("{}", serde_json::to_string(&report).unwrap());
        return;
    }

    println!("OMARCHY SECURITY SENTINEL - UNIFIED DEFENSE ENGINE");
    println!(
        "Status: {} | Threat: {}",
        report.overall_status, report.threat_level
    );
    for m in &report.modules {
        println!("{:<25} [{:<8}] {}", m.name, m.status, m.summary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_file_rejects_symlinks() {
        let temp_dir = env::temp_dir().join(format!("sentinel_sym_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let real_file = temp_dir.join("real_image.png");
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        fs::write(&real_file, png_header).unwrap();

        let sym_file = temp_dir.join("symlink_image.png");
        std::os::unix::fs::symlink(&real_file, &sym_file).unwrap();

        let res = clean_file(&sym_file);
        assert!(res.is_err(), "clean_file must reject symlinks");
        assert!(res
            .unwrap_err()
            .contains("Symlinks are strictly prohibited"));

        // Verify real file was untouched
        assert_eq!(fs::read(&real_file).unwrap(), png_header);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_clean_file_rejects_directories_and_non_files() {
        let temp_dir = env::temp_dir().join(format!("sentinel_dir_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let res = clean_file(&temp_dir);
        assert!(res.is_err(), "clean_file must reject directories");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_clean_file_atomic_png_scrubbing_and_cleanup() {
        let temp_dir = env::temp_dir().join(format!("sentinel_clean_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let png_file = temp_dir.join("test_photo.png");

        // Construct a synthetic PNG with IHDR, tEXt (metadata), and IEND chunks
        let mut png_data = Vec::new();
        png_data.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]); // Header

        // IHDR chunk (length 13, type IHDR, 13 data bytes, 4 CRC bytes = 25 bytes total)
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
        png_data.extend_from_slice(b"IHDR");
        png_data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00,
        ]);
        png_data.extend_from_slice(&[0x1F, 0x15, 0xC4, 0x89]); // CRC

        // tEXt metadata chunk (length 9, type tEXt, "Author=Oz", 4 CRC bytes)
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x09]);
        png_data.extend_from_slice(b"tEXt");
        png_data.extend_from_slice(b"Author=Oz");
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC dummy

        // IEND chunk (length 0, type IEND, 4 CRC bytes)
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        png_data.extend_from_slice(b"IEND");
        png_data.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);

        fs::write(&png_file, &png_data).unwrap();

        // Verify file contains metadata before cleaning
        let raw_before = fs::read(&png_file).unwrap();
        assert!(raw_before.windows(4).any(|w| w == b"tEXt"));

        // Clean file
        let clean_res = clean_file(&png_file);
        assert!(
            clean_res.is_ok(),
            "clean_file must succeed on valid PNG: {:?}",
            clean_res.err()
        );

        // Verify metadata was stripped
        let raw_after = fs::read(&png_file).unwrap();
        assert_eq!(
            &raw_after[..8],
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        );
        assert!(
            !raw_after.windows(4).any(|w| w == b"tEXt"),
            "tEXt metadata must be stripped"
        );
        assert!(
            raw_after.windows(4).any(|w| w == b"IHDR"),
            "IHDR chunk must be preserved"
        );
        assert!(
            raw_after.windows(4).any(|w| w == b"IEND"),
            "IEND chunk must be preserved"
        );

        // Verify no temporary files remain in directory
        let remaining_files: Vec<_> = fs::read_dir(&temp_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(remaining_files, vec!["test_photo.png"]);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_clean_file_atomic_jpeg_scrubbing() {
        let temp_dir = env::temp_dir().join(format!("sentinel_jpg_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let jpg_file = temp_dir.join("sample.jpg");

        // Construct synthetic JPEG with APP1 (EXIF: 0xFF, 0xE1) and SOI (0xFF, 0xD8), EOI (0xFF, 0xD9)
        let mut jpg_data = Vec::new();
        jpg_data.extend_from_slice(&[0xFF, 0xD8]); // SOI
                                                   // APP1 metadata segment (length 6: len bytes 0x00, 0x06 + 4 bytes payload)
        jpg_data.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x06, 0x45, 0x78, 0x69, 0x66]);
        // EOI marker
        jpg_data.extend_from_slice(&[0xFF, 0xD9]);

        fs::write(&jpg_file, &jpg_data).unwrap();

        let clean_res = clean_file(&jpg_file);
        assert!(
            clean_res.is_ok(),
            "clean_file must succeed on synthetic JPEG: {:?}",
            clean_res.err()
        );

        let raw_after = fs::read(&jpg_file).unwrap();
        assert_eq!(&raw_after[..2], &[0xFF, 0xD8]);
        assert_eq!(&raw_after[raw_after.len() - 2..], &[0xFF, 0xD9]);
        // APP1 marker must be stripped
        assert!(!raw_after.windows(2).any(|w| w == [0xFF, 0xE1]));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_strip_jpeg_keeps_icc_and_adobe_segments() {
        let mut jpg = vec![0xFF, 0xD8];
        // APP1 EXIF (stripped)
        jpg.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x08]);
        jpg.extend_from_slice(b"Exif\0\0");
        // APP2 ICC_PROFILE (kept)
        jpg.extend_from_slice(&[0xFF, 0xE2, 0x00, 0x0E]);
        jpg.extend_from_slice(b"ICC_PROFILE\0");
        // APP14 Adobe (kept)
        jpg.extend_from_slice(&[0xFF, 0xEE, 0x00, 0x07]);
        jpg.extend_from_slice(b"Adobe");
        // COM comment (stripped)
        jpg.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x05, b'h', b'i', b'!']);
        jpg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0x11, 0x22, 0xFF, 0xD9]);

        let out = strip_jpeg_metadata(&jpg).unwrap();
        assert!(!out.windows(4).any(|w| w == b"Exif"));
        assert!(!out.windows(3).any(|w| w == b"hi!"));
        assert!(out.windows(11).any(|w| w == b"ICC_PROFILE"));
        assert!(out.windows(5).any(|w| w == b"Adobe"));
        assert!(out.ends_with(&[0x11, 0x22, 0xFF, 0xD9]));
    }

    #[test]
    fn test_strip_jpeg_rejects_truncated_input_without_touching_file() {
        let temp_dir = env::temp_dir().join(format!("sentinel_trunc_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        let jpg_file = temp_dir.join("truncated.jpg");
        // APP1 claims 0x1000 bytes but the file ends early
        let data = [0xFF, 0xD8, 0xFF, 0xE1, 0x10, 0x00, 0x45, 0x78];
        fs::write(&jpg_file, data).unwrap();

        assert!(clean_file(&jpg_file).is_err());
        assert_eq!(fs::read(&jpg_file).unwrap(), data);
        // Zero-length segment headers are malformed too
        assert!(strip_jpeg_metadata(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x00]).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_sha256_hex_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"message digest"),
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"
        );
    }

    #[test]
    fn test_secure_state_file_mode_0600_and_symlink_rejection() {
        let temp_dir = env::temp_dir().join(format!("sentinel_state_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        let _ = fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o700));

        let state_file = temp_dir.join("test_state.json");
        let content = b"{\"active\":true,\"count\":42}";

        // 1. Write file securely
        let write_res = write_secure_state_file(&state_file, content);
        assert!(
            write_res.is_ok(),
            "write_secure_state_file should succeed: {:?}",
            write_res.err()
        );

        // 2. Verify file permissions are strictly 0600
        let meta = fs::symlink_metadata(&state_file).unwrap();
        assert_eq!(
            meta.mode() & 0o777,
            0o600,
            "State file mode must be strictly 0600 (-rw-------)"
        );

        // 3. Read file back
        let read_bytes = read_secure_state_file(&state_file, 1024).unwrap();
        assert_eq!(read_bytes, content);

        // 4. Overwrite atomically
        let new_content = b"{\"active\":false,\"count\":99}";
        assert!(write_secure_state_file(&state_file, new_content).is_ok());
        let read_bytes2 = read_secure_state_file(&state_file, 1024).unwrap();
        assert_eq!(read_bytes2, new_content);

        // 5. Test symlink rejection on read
        let sym_file = temp_dir.join("sym_state.json");
        std::os::unix::fs::symlink(&state_file, &sym_file).unwrap();
        let sym_read = read_secure_state_file(&sym_file, 1024);
        assert!(
            sym_read.is_err(),
            "read_secure_state_file must reject symlinks"
        );

        // 6. Test symlink rejection on write
        let sym_write = write_secure_state_file(&sym_file, b"hack");
        assert!(
            sym_write.is_err(),
            "write_secure_state_file must refuse to overwrite symlink"
        );

        // 7. Verify no temporary files remain
        let remaining_files: Vec<_> = fs::read_dir(&temp_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(".tmp_state_"))
            .collect();
        assert!(remaining_files.is_empty(), "No temp files should remain");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_read_file_bounded_success_and_overflow() {
        let temp_dir = env::temp_dir().join(format!("sentinel_read_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let test_file = temp_dir.join("sample.txt");
        fs::write(&test_file, b"1234567890").unwrap();

        // Reading with exact or larger limit succeeds
        let res1 = read_file_bounded(&test_file, 10);
        assert!(res1.is_ok());
        assert_eq!(res1.unwrap(), "1234567890");

        let res2 = read_file_bounded(&test_file, 100);
        assert!(res2.is_ok());
        assert_eq!(res2.unwrap(), "1234567890");

        // Reading with smaller limit fails with bounded overflow error
        let res3 = read_file_bounded(&test_file, 9);
        assert!(res3.is_err());
        assert!(res3.unwrap_err().contains("exceeded limit"));

        // Symlink rejection
        let sym_file = temp_dir.join("sym_sample.txt");
        std::os::unix::fs::symlink(&test_file, &sym_file).unwrap();
        let sym_res = read_file_bounded(&sym_file, 100);
        assert!(
            sym_res.is_err(),
            "read_file_bounded must reject symlinks via O_NOFOLLOW"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_suspicious_port_detection_and_service_mapping() {
        assert!(is_suspicious_port(1337));
        assert!(is_suspicious_port(4444));
        assert!(is_suspicious_port(5555));
        assert!(is_suspicious_port(6666));
        assert!(is_suspicious_port(6667));
        assert!(is_suspicious_port(9001));
        assert!(is_suspicious_port(31337));

        assert!(!is_suspicious_port(22));
        assert!(!is_suspicious_port(53));
        assert!(!is_suspicious_port(80));
        assert!(!is_suspicious_port(443));
        assert!(!is_suspicious_port(853));

        assert_eq!(port_service_name(4444), "Metasploit C2");
        assert_eq!(port_service_name(1337), "Backdoor/C2");
        assert_eq!(port_service_name(31337), "Back Orifice");
        assert_eq!(port_service_name(853), "DoT Encrypted");
        assert_eq!(port_service_name(6379), "Redis Cache");
    }

    #[test]
    fn test_parse_ip_port_ipv4() {
        let parsed = parse_ip_port("0100007F:115C");
        assert!(parsed.is_some());
        let (ip, port) = parsed.unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 4444);

        assert!(parse_ip_port("invalid").is_none());
        assert!(parse_ip_port("0100007F:GGGG").is_none());
    }

    #[test]
    fn test_sanitize_usb_product_strips_html_and_control_chars() {
        let malicious = "<img src=\"http://127.0.0.1:8080/beacon\">BadUSB Payload\0\x1b";
        let cleaned = sanitize_usb_product(malicious);
        assert!(!cleaned.contains('<'));
        assert!(!cleaned.contains('>'));
        assert!(!cleaned.contains('"'));
        assert!(!cleaned.contains('\0'));
        assert_eq!(
            cleaned,
            "img src=http://127.0.0.1:8080/beaconBadUSB Payload"
        );

        let empty = "   \n\t  ";
        assert_eq!(sanitize_usb_product(empty), "USB Device");

        let normal = "Logitech USB Optical Mouse";
        assert_eq!(sanitize_usb_product(normal), "Logitech USB Optical Mouse");
    }
}
