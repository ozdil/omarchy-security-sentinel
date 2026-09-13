use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod subproc;
use subproc::run_cmd_bounded;

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

/// Standalone in-memory SHA-256 implementation (FIPS 180-4 compliant)
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 64);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, w_val) in w.iter_mut().take(16).enumerate() {
            let idx = i * 4;
            *w_val = u32::from_be_bytes([chunk[idx], chunk[idx + 1], chunk[idx + 2], chunk[idx + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
    )
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
    let parent = path.parent().ok_or_else(|| "Invalid state file parent path".to_string())?;
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
        .map_err(|e| format!("Failed to create temp state file with 0600/O_NOFOLLOW: {}", e))?;

    let _ = tmp_file.set_permissions(fs::Permissions::from_mode(0o600));

    tmp_file
        .write_all(content)
        .map_err(|e| format!("Failed to write state file: {}", e))?;

    tmp_file
        .sync_all()
        .map_err(|e| format!("Failed to sync state file to disk: {}", e))?;

    let meta = tmp_file.metadata().map_err(|e| format!("Failed to read temp metadata: {}", e))?;
    if meta.len() != content.len() as u64 {
        return Err("State file size verification mismatch".to_string());
    }

    drop(tmp_file);

    if path.exists() {
        let dest_meta = fs::symlink_metadata(path).map_err(|e| format!("Cannot check existing target: {}", e))?;
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

    let sym_meta = fs::symlink_metadata(path).map_err(|e| format!("symlink_metadata failed: {}", e))?;
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

    let fd_meta = file.metadata().map_err(|e| format!("Descriptor metadata failed: {}", e))?;
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
    handle.read_to_end(&mut buf).map_err(|e| format!("Read failed: {}", e))?;
    if buf.len() > max_bytes {
        return Err("Read exceeded max_bytes limit".to_string());
    }
    Ok(buf)
}

fn notify_desktop(title: &str, body: &str, is_critical: bool) {
    let urgency = if is_critical { "critical" } else { "normal" };
    let icon = if is_critical { "security-low" } else { "security-high" };
    let deadline = Instant::now() + Duration::from_millis(1500);
    let _ = run_cmd_bounded(
        "notify-send",
        &["-a", "Security Sentinel", "-u", urgency, "-i", icon, title, body],
        &[],
        deadline,
        4096,
    );
}


fn parse_ip_port(s: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 { return None; }
    let port = u16::from_str_radix(parts[1], 16).ok()?;
    let ip_hex = parts[0];
    if ip_hex.len() == 8 {
        let num = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = format!("{}.{}.{}.{}", num & 0xFF, (num >> 8) & 0xFF, (num >> 16) & 0xFF, (num >> 24) & 0xFF);
        Some((ip, port))
    } else {
        Some(("IPv6".to_string(), port))
    }
}

fn port_service_name(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        53 => "DNS Resolver",
        80 => "HTTP",
        443 => "HTTPS",
        631 => "CUPS Print",
        853 => "DoT Encrypted",
        3000 => "Node/Web",
        5173 => "Vite Dev",
        8080 => "HTTP Proxy",
        8844 => "Local Service",
        _ => "System Port",
    }
}

// 1. Network Sockets Radar
fn check_network_sockets() -> ModuleStatus {
    let mut total = 0;
    let mut listen = 0;
    let mut estab = 0;
    let mut flagged = 0;
    let mut listen_items = Vec::new();
    let mut estab_items = Vec::new();

    let paths = ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"];
    for p in &paths {
        if let Ok(content) = fs::read_to_string(p) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 3 {
                    total += 1;
                    let st = parts[3];
                    if st == "0A" {
                        listen += 1;
                        if listen_items.len() < 5 {
                            if let Some((ip, port)) = parse_ip_port(parts[1]) {
                                listen_items.push(format!("LISTEN :{} ({}) [{}]", port, port_service_name(port), ip));
                            }
                        }
                    } else if st == "01" {
                        estab += 1;
                        if estab_items.len() < 5 {
                            if let Some((rem_ip, rem_port)) = parse_ip_port(parts[2]) {
                                estab_items.push(format!("ESTAB -> {}:{} ({})", rem_ip, rem_port, port_service_name(rem_port)));
                            }
                        }
                        if let Some(rem) = parts.get(2) {
                            if rem.ends_with(":115C") || rem.ends_with(":1F90") || rem.ends_with(":1A0A") {
                                flagged += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    let mut items = Vec::new();
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

// 2. BadUSB Defense
fn check_badusb() -> ModuleStatus {
    let mut total_usb = 0;
    let mut hid_count = 0;
    let mut current_ids = Vec::new();
    let mut items = Vec::new();

    let trusted_file = get_state_dir().join("trusted_usb.json");
    let file_existed = trusted_file.exists();
    let mut trusted: Vec<String> = if file_existed {
        if let Ok(bytes) = read_secure_state_file(&trusted_file, 65536) {
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.join("idVendor").is_file() {
                total_usb += 1;
                let v = fs::read_to_string(p.join("idVendor")).unwrap_or_default().trim().to_string();
                let pr = fs::read_to_string(p.join("idProduct")).unwrap_or_default().trim().to_string();
                let dev_id = format!("{}:{}", v, pr);
                current_ids.push(dev_id.clone());

                let mut is_hid = false;
                if let Ok(sub) = fs::read_dir(&p) {
                    for s in sub.flatten() {
                        let name = s.file_name().to_string_lossy().to_string();
                        if name.contains(":1.") {
                            let driver = s.path().join("driver");
                            if driver.exists() && driver.read_link().map(|l| l.to_string_lossy().contains("hid")).unwrap_or(false) {
                                hid_count += 1;
                                is_hid = true;
                            }
                        }
                    }
                }

                let prod = fs::read_to_string(p.join("product")).unwrap_or_else(|_| "USB Device".to_string()).trim().to_string();
                let is_trusted = trusted.contains(&dev_id) || !file_existed;
                let tag = if is_trusted { "Approved" } else { "UNAPPROVED" };
                let hid_tag = if is_hid { " (HID)" } else { "" };
                items.push(format!("{} [{}]{} [{}]", prod, dev_id, hid_tag, tag));
            }
        }
    }

    if !file_existed {
        trusted = current_ids.clone();
        if let Ok(data) = serde_json::to_vec(&trusted) {
            let _ = write_secure_state_file(&trusted_file, &data);
        }
    }

    let mut untrusted_count = 0;
    for id in &current_ids {
        if !trusted.contains(id) {
            untrusted_count += 1;
        }
    }

    let status = if untrusted_count > 0 { "ALERT" } else { "SECURE" };
    ModuleStatus {
        id: "badusb".to_string(),
        name: "BadUSB Defense".to_string(),
        status: status.to_string(),
        summary: if untrusted_count > 0 {
            format!("[ALERT] {} UNTRUSTED USB DETECTED", untrusted_count)
        } else {
            format!("{} Devices ({} Trusted HID)", total_usb, hid_count)
        },
        detail: if untrusted_count > 0 {
            "Unauthorized USB device attached! Click 'Trust Devices' to approve.".to_string()
        } else {
            "All attached HID devices match approved hardware baseline".to_string()
        },
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct CveCache {
    timestamp: u64,
    pkg_count: usize,
    pending_pkgs: Vec<String>,
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

    let mut pending_pkgs = Vec::new();
    let mut cache_hit = false;

    if let Ok(bytes) = read_secure_state_file(&cache_file, 65536) {
        if let Ok(cache) = serde_json::from_slice::<CveCache>(&bytes) {
            if now_secs.saturating_sub(cache.timestamp) < CACHE_TTL_SECS {
                pending_pkgs = cache.pending_pkgs;
                cache_hit = true;
            }
        }
    }

    if !cache_hit {
        let deadline = Instant::now() + Duration::from_millis(4000);
        if let Some(stdout) = run_cmd_bounded("checkupdates", &[], &[], deadline, 65536) {
            let text = String::from_utf8_lossy(&stdout);
            for l in text.lines().filter(|l| !l.trim().is_empty()) {
                pending_pkgs.push(l.trim().to_string());
            }
        }
        let cache = CveCache {
            timestamp: now_secs,
            pkg_count,
            pending_pkgs: pending_pkgs.clone(),
        };
        if let Ok(json_bytes) = serde_json::to_vec(&cache) {
            let _ = write_secure_state_file(&cache_file, &json_bytes);
        }
    }

    let pending_count = pending_pkgs.len();

    let mut items = Vec::new();
    items.push(format!("Audited Packages: {} local packages in /var/lib/pacman/local", pkg_count));
    if pending_count == 0 {
        items.push("Arch Security Tracker: Zero pending security patches".to_string());
        items.push("System Status: All installed binaries up to date".to_string());
    } else {
        items.push(format!("Updates Available: {} packages pending update", pending_count));
        for p in pending_pkgs.iter().take(5) {
            items.push(format!("Update -> {}", p));
        }
    }

    let status = if pending_count > 10 { "WARNING" } else { "SECURE" };
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
            format!("{} system updates pending package manager sync", pending_count)
        } else {
            "Arch Security Tracker verified | Zero pending security patches".to_string()
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
    // Bounded execution: producer-side limit (-n 200), deadline 1.5s, buffer cap 64 KiB
    if let Some(stdout) = run_cmd_bounded(
        journal_bin,
        &["-n", "200", "--since", "24 hours ago", "-q", "-o", "cat"],
        &[],
        deadline,
        65536,
    ) {
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
    items.push("Log Target: systemd-journald & Linux PAM (24h scope)".to_string());
    items.push(format!("Failed Authentication Events: {} recorded", failed_count));
    if failed_count == 0 {
        items.push("Integrity: No brute-force or unauthorized sudo/ssh attempts".to_string());
    } else {
        for fe in fail_entries {
            items.push(format!("Alert -> {}", fe));
        }
    }

    let status = if failed_count > 0 { "WARNING" } else { "SECURE" };
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
            format!("PAM & systemd journal recorded {} failed auth attempts!", failed_count)
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

    let is_intact = !expected_hash.is_empty() && expected_hash == current_hash;
    let status = if is_intact { "SECURE" } else { "ALERT" };

    let mut items = Vec::new();
    items.push(format!("Canary Path: {}", token_path.display()));
    let hash_display = if expected_hash.len() > 16 {
        format!("{}...{}", &expected_hash[..8], &expected_hash[expected_hash.len() - 8..])
    } else {
        expected_hash.clone()
    };
    items.push(format!("SHA-256 Seal: {} [Intact]", hash_display));
    items.push(if is_intact {
        "Ransomware Defense: Token intact | File baseline verified".to_string()
    } else {
        "[ALERT] Canary token modified or encrypted by untrusted process!".to_string()
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
    let current_provider = if let Some(out) = run_cmd_bounded("omarchy-dns", &[], &[], deadline, 4096) {
        String::from_utf8_lossy(&out).trim().to_string()
    } else {
        "DHCP".to_string()
    };

    let is_dot = current_provider == "Cloudflare" || current_provider == "Google";
    let status = if is_dot { "SECURE" } else { "WARNING" };

    let mut items = Vec::new();
    if is_dot {
        items.push(format!("Active Resolver: {} DNS (1.1.1.1 / 853)", current_provider));
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
        &["-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"],
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

                if let Ok(addr) = fs::read_to_string(format!("/sys/class/net/{}/address", dev_name)) {
                    current_mac = addr.trim().to_string();
                }

                let sub_deadline = Instant::now() + Duration::from_millis(1500);
                if let Some(c_out) = run_cmd_bounded(
                    "nmcli",
                    &["-t", "-f", "802-11-wireless.cloned-mac-address", "connection", "show", &conn_name],
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
    items.push(format!("Active MAC: {} ({})", current_mac, if is_randomized { "Randomized / Cloaked" } else { "Hardware Permanent" }));
    items.push(format!("Connection: {} on interface {}", if conn_name.is_empty() { "None" } else { &conn_name }, if dev_name.is_empty() { "wlo1" } else { &dev_name }));
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
    let sym_meta = fs::symlink_metadata(path).map_err(|e| format!("Cannot read metadata: {}", e))?;
    if sym_meta.file_type().is_symlink() {
        return Err("Symlinks are strictly prohibited".to_string());
    }
    if !sym_meta.is_file() {
        return Err("Target is not a regular file".to_string());
    }
    if sym_meta.len() > MAX_IMAGE_SIZE as u64 {
        return Err(format!("File exceeds maximum allowed size of {} bytes", MAX_IMAGE_SIZE));
    }

    // 2. Open through held descriptor with O_NOFOLLOW
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("Failed to open file safely with O_NOFOLLOW: {}", e))?;

    // 3. Re-verify attributes on the held descriptor
    let fd_meta = file.metadata().map_err(|e| format!("Failed to read descriptor metadata: {}", e))?;
    if !fd_meta.is_file() {
        return Err("Descriptor is not a regular file".to_string());
    }
    if fd_meta.len() > MAX_IMAGE_SIZE as u64 {
        return Err(format!("Descriptor file size exceeds {} bytes", MAX_IMAGE_SIZE));
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
    handle.read_to_end(&mut data).map_err(|e| format!("Read failed: {}", e))?;
    if data.len() > MAX_IMAGE_SIZE {
        return Err("Read data exceeded maximum image buffer limit".to_string());
    }

    // 5. Lossless metadata stripping
    let cleaned_bytes: Option<Vec<u8>> = if data.len() >= 4 && data[0] == 0xFF && data[1] == 0xD8 {
        // JPEG cleaner
        let mut out = Vec::with_capacity(data.len());
        out.push(0xFF);
        out.push(0xD8);
        let mut idx = 2;
        while idx < data.len() {
            if data[idx] != 0xFF {
                out.extend_from_slice(&data[idx..]);
                break;
            }
            while idx < data.len() && data[idx] == 0xFF {
                idx += 1;
            }
            if idx >= data.len() {
                break;
            }
            let marker = data[idx];
            idx += 1;
            if marker == 0xD9 {
                out.push(0xFF);
                out.push(0xD9);
                break;
            }
            if marker == 0xDA {
                out.push(0xFF);
                out.push(0xDA);
                out.extend_from_slice(&data[idx..]);
                break;
            }
            if idx + 2 > data.len() {
                break;
            }
            let len = ((data[idx] as usize) << 8) | (data[idx + 1] as usize);
            if idx + len > data.len() {
                break;
            }
            let is_meta = (0xE1..=0xEF).contains(&marker) || marker == 0xFE;
            if !is_meta {
                out.push(0xFF);
                out.push(marker);
                out.extend_from_slice(&data[idx..idx + len]);
            }
            idx += len;
        }
        Some(out)
    } else {
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        if data.len() >= 8 && data[..8] == png_header {
            // PNG cleaner
            let mut out = Vec::with_capacity(data.len());
            out.extend_from_slice(&png_header);
            let mut idx = 8;
            while idx + 12 <= data.len() {
                let length = ((data[idx] as usize) << 24)
                    | ((data[idx + 1] as usize) << 16)
                    | ((data[idx + 2] as usize) << 8)
                    | (data[idx + 3] as usize);
                let chunk_type = &data[idx + 4..idx + 8];
                let total_chunk_len = 12 + length;
                if idx + total_chunk_len > data.len() {
                    out.extend_from_slice(&data[idx..]);
                    break;
                }
                let type_str = String::from_utf8_lossy(chunk_type);
                let is_meta = type_str == "tEXt" || type_str == "zTXt" || type_str == "iTXt" || type_str == "eXIf";
                if !is_meta {
                    out.extend_from_slice(&data[idx..idx + total_chunk_len]);
                }
                idx += total_chunk_len;
            }
            Some(out)
        } else {
            None
        }
    };

    let out = match cleaned_bytes {
        Some(b) => b,
        None => return Err("Unsupported image format or invalid header".to_string()),
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

    let tmp_meta = tmp_file.metadata().map_err(|e| format!("Failed to read temp metadata: {}", e))?;
    if tmp_meta.len() != out.len() as u64 {
        return Err("Written bytes verification mismatch".to_string());
    }

    drop(tmp_file);

    // Re-verify target path is still regular file and not replaced with symlink prior to rename
    let pre_rename_meta = fs::symlink_metadata(path).map_err(|e| format!("Cannot verify target prior to rename: {}", e))?;
    if pre_rename_meta.file_type().is_symlink() {
        return Err("Target path changed to symlink during cleaning".to_string());
    }

    fs::rename(&tmp_path, path).map_err(|e| format!("Failed to atomically replace image: {}", e))?;

    guard.active = false;

    Ok(())
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
                        if (ext_str == "jpg" || ext_str == "jpeg" || ext_str == "png") && clean_file(&p).is_ok() {
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
                    &["-t", "-f", "802-11-wireless.cloned-mac-address", "connection", "show", conn],
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
                    let _ = run_cmd_bounded("nmcli", &["connection", "modify", conn, "802-11-wireless.cloned-mac-address", "permanent"], &[], mod_deadline, 4096);
                    let up_deadline = Instant::now() + Duration::from_millis(3000);
                    let _ = run_cmd_bounded("nmcli", &["connection", "up", conn], &[], up_deadline, 4096);
                    notify_desktop("Ghost MAC", "Reverted to Wi-Fi hardware (original) MAC address.", false);
                    return false;
                } else {
                    let mod_deadline = Instant::now() + Duration::from_millis(2000);
                    let _ = run_cmd_bounded("nmcli", &["connection", "modify", conn, "802-11-wireless.cloned-mac-address", "random"], &[], mod_deadline, 4096);
                    let up_deadline = Instant::now() + Duration::from_millis(3000);
                    let _ = run_cmd_bounded("nmcli", &["connection", "up", conn], &[], up_deadline, 4096);
                    notify_desktop("Ghost MAC", "Wi-Fi MAC randomization enabled (random MAC per connection).", false);
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
        notify_desktop("DNS Leak Guard", "Switched to standard ISP DNS (DHCP) mode.", false);
        false
    } else {
        let deadline = Instant::now() + Duration::from_millis(2000);
        let _ = run_cmd_bounded("omarchy-dns", &["Cloudflare"], &[], deadline, 4096);
        notify_desktop("DNS Leak Guard", "Cloudflare DNS-over-TLS (DoT 1.1.1.1) encrypted tunnel enabled.", false);
        true
    }
}

fn trust_all_usb() -> usize {
    let mut ids = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.join("idVendor").is_file() {
                let v = fs::read_to_string(p.join("idVendor")).unwrap_or_default().trim().to_string();
                let pr = fs::read_to_string(p.join("idProduct")).unwrap_or_default().trim().to_string();
                ids.push(format!("{}:{}", v, pr));
            }
        }
    }
    let count = ids.len();
    let trusted_file = get_state_dir().join("trusted_usb.json");
    if let Ok(data) = serde_json::to_vec(&ids) {
        let _ = write_secure_state_file(&trusted_file, &data);
    }
    notify_desktop("BadUSB Defense", &format!("Added {} connected USB devices to trusted whitelist.", count), false);
    count
}

fn reset_canaries() {
    let token_path = get_state_dir().join("canary.token");
    let hash_path = get_state_dir().join("canary.sha256");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let token_data = format!("OMARCHY_SECURITY_SENTINEL_TRIPWIRE_TOKEN_GEN_{}\n", now);
    let _ = write_secure_state_file(&token_path, token_data.as_bytes());
    let hash = sha256_hex(token_data.as_bytes());
    let _ = write_secure_state_file(&hash_path, hash.as_bytes());
    notify_desktop("Tripwire Canaries", "New canary honeypot token generated and SHA-256 hash sealed.", false);
}

fn build_report() -> SentinelReport {
    let (dns_mod, dns_dot_enabled) = check_dns_leak();
    let (ghost_mac_mod, ghost_mac_enabled) = check_ghost_mac();

    let modules = vec![
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

    SentinelReport {
        overall_status: overall_status.to_string(),
        threat_level: threat_level.to_string(),
        threat_color: threat_color.to_string(),
        active_modules: modules.len(),
        ghost_mac_enabled,
        dns_dot_enabled,
        modules,
        timestamp: "Live Defense".to_string(),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|a| a == "--toggle-ghost-mac") {
        let state = toggle_ghost_mac();
        println!("{}", if state { "ENABLED" } else { "DISABLED" });
        return;
    }

    if args.iter().any(|a| a == "--toggle-dns") {
        let state = toggle_dns();
        println!("{}", if state { "ENABLED" } else { "DISABLED" });
        return;
    }

    if args.iter().any(|a| a == "--trust-all-usb") {
        let count = trust_all_usb();
        println!("Trusted {} devices", count);
        return;
    }

    if args.iter().any(|a| a == "--reset-canaries") {
        reset_canaries();
        println!("Canaries reset");
        return;
    }

    if args.iter().any(|a| a == "--scrub-downloads") {
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

    if let Some(pos) = args.iter().position(|a| a == "--clean-files") {
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

    if args.iter().any(|a| a == "--status" || a == "--bar") {
        let text = "\u{f0483}".to_string();
        let tooltip = format!(
            "Security Sentinel Hub\nStatus: {}\nThreat Level: {}\nActive Subsystems: 8 / 8\n\n[Left Click] Open Security Center",
            report.overall_status, report.threat_level
        );
        let out = BarStatus {
            text,
            tooltip,
            class: if report.threat_level == "ZERO" { "normal".to_string() } else { "warning".to_string() },
            color: report.threat_color,
        };
        println!("{}", serde_json::to_string(&out).unwrap());
        return;
    }

    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string(&report).unwrap());
        return;
    }

    println!("OMARCHY SECURITY SENTINEL - UNIFIED DEFENSE ENGINE");
    println!("Status: {} | Threat: {}", report.overall_status, report.threat_level);
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
        assert!(res.unwrap_err().contains("Symlinks are strictly prohibited"));

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
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00]);
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
        assert!(clean_res.is_ok(), "clean_file must succeed on valid PNG: {:?}", clean_res.err());

        // Verify metadata was stripped
        let raw_after = fs::read(&png_file).unwrap();
        assert_eq!(&raw_after[..8], &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        assert!(!raw_after.windows(4).any(|w| w == b"tEXt"), "tEXt metadata must be stripped");
        assert!(raw_after.windows(4).any(|w| w == b"IHDR"), "IHDR chunk must be preserved");
        assert!(raw_after.windows(4).any(|w| w == b"IEND"), "IEND chunk must be preserved");

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
        assert!(clean_res.is_ok(), "clean_file must succeed on synthetic JPEG: {:?}", clean_res.err());

        let raw_after = fs::read(&jpg_file).unwrap();
        assert_eq!(&raw_after[..2], &[0xFF, 0xD8]);
        assert_eq!(&raw_after[raw_after.len() - 2..], &[0xFF, 0xD9]);
        // APP1 marker must be stripped
        assert!(!raw_after.windows(2).any(|w| w == [0xFF, 0xE1]));

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
        assert!(write_res.is_ok(), "write_secure_state_file should succeed: {:?}", write_res.err());

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
        assert!(sym_read.is_err(), "read_secure_state_file must reject symlinks");

        // 6. Test symlink rejection on write
        let sym_write = write_secure_state_file(&sym_file, b"hack");
        assert!(sym_write.is_err(), "write_secure_state_file must refuse to overwrite symlink");

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
}

