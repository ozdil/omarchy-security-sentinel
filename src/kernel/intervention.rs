use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::subproc::run_cmd_bounded;

const O_NOFOLLOW: i32 = 0o400000;

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterventionResult {
    pub success: bool,
    pub action: String,
    pub target: String,
    pub message: String,
    pub timestamp: u64,
}

impl InterventionResult {
    pub fn ok(action: &str, target: &str, msg: &str) -> Self {
        Self {
            success: true,
            action: action.to_string(),
            target: target.to_string(),
            message: msg.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn err(action: &str, target: &str, msg: &str) -> Self {
        Self {
            success: false,
            action: action.to_string(),
            target: target.to_string(),
            message: msg.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Reads a procfs attribute file with strict take(MAX + 1) buffer ceiling
fn read_proc_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
    let mut buf = Vec::new();
    let mut handle = (&mut file).take((max_bytes + 1) as u64);
    handle.read_to_end(&mut buf).map_err(|e| format!("Read failed on {}: {}", path.display(), e))?;
    if buf.len() > max_bytes {
        return Err(format!("File {} exceeded limit of {} bytes", path.display(), max_bytes));
    }
    Ok(buf)
}

/// Immune system critical process names
const IMMUNE_PROCESSES: &[&str] = &[
    "systemd",
    "systemd-journal",
    "systemd-logind",
    "systemd-udevd",
    "polkitd",
    "dbus-daemon",
    "dbus-broker",
    "Hyprland",
    "waybar",
    "quickshell",
    "sshd",
    "sentinel-engine",
];

/// Freezes a suspect process at kernel level (SIGSTOP / 19).
/// Unlike SIGKILL, freezing suspends execution immediately without destroying
/// the memory state or socket descriptors, enabling forensic acquisition.
pub fn kernel_freeze_process(pid: i32) -> InterventionResult {
    if pid <= 2 {
        return InterventionResult::err(
            "kernel_freeze",
            &pid.to_string(),
            "Refusing to freeze system init or kernel thread manager (PID <= 2)",
        );
    }

    // Verify process exists in /proc
    let proc_path = format!("/proc/{}", pid);
    let proc_dir = Path::new(&proc_path);
    if !proc_dir.exists() {
        return InterventionResult::err("kernel_freeze", &pid.to_string(), "Target PID does not exist");
    }

    // Refuse to freeze kernel threads (empty /proc/[pid]/cmdline) with bounded read
    if let Ok(cmd) = read_proc_bounded(&proc_dir.join("cmdline"), 65536) {
        if cmd.is_empty() {
            return InterventionResult::err(
                "kernel_freeze",
                &pid.to_string(),
                "Refusing to freeze core kernel thread (empty cmdline)",
            );
        }
    }

    // Check immune critical processes with bounded read
    if let Ok(comm_bytes) = read_proc_bounded(&proc_dir.join("comm"), 256) {
        let comm = String::from_utf8_lossy(&comm_bytes).trim().to_string();
        if IMMUNE_PROCESSES.contains(&comm.as_str()) {
            return InterventionResult::err(
                "kernel_freeze",
                &pid.to_string(),
                &format!("Refusing to freeze immune critical system process '{}'", comm),
            );
        }
    }

    // Attempt direct POSIX SIGSTOP
    // SAFETY: Validated PID > 2, verified not kernel thread, verified not immune. SIGSTOP is signal 19.
    let ret = unsafe { kill(pid, 19) };
    if ret == 0 {
        capture_forensic_evidence(pid);
        InterventionResult::ok(
            "kernel_freeze",
            &pid.to_string(),
            &format!("Process {} successfully frozen at kernel level (SIGSTOP) with forensic hash capture", pid),
        )
    } else {
        // Fallback: try via kill with bounded execution, then pkexec if needed
        let pid_str = pid.to_string();
        let deadline = Instant::now() + Duration::from_secs(3);
        let out = run_cmd_bounded(
            "/usr/bin/kill",
            &["-STOP", "--", &pid_str],
            &[],
            deadline,
            4096,
        );

        if out.is_some() {
            capture_forensic_evidence(pid);
            return InterventionResult::ok(
                "kernel_freeze",
                &pid_str,
                &format!("Process {} frozen via kernel signal with forensic capture", pid),
            );
        }

        // Try pkexec fallback
        if Path::new("/usr/bin/pkexec").exists() {
            let pk_deadline = Instant::now() + Duration::from_secs(10);
            let pk_out = run_cmd_bounded(
                "/usr/bin/pkexec",
                &["/usr/bin/kill", "-STOP", "--", &pid_str],
                &[],
                pk_deadline,
                4096,
            );
            if pk_out.is_some() {
                capture_forensic_evidence(pid);
                return InterventionResult::ok(
                    "kernel_freeze",
                    &pid_str,
                    &format!("Process {} frozen via privileged kernel signal with forensic capture", pid),
                );
            }
        }

        InterventionResult::err(
            "kernel_freeze",
            &pid_str,
            "Permission denied or failure sending SIGSTOP signal",
        )
    }
}

/// Terminates a malicious or uncooperative process at kernel level.
/// Sends SIGTERM (15) first, followed by SIGKILL (9) to ensure full eradication.
pub fn kernel_terminate_process(pid: i32) -> InterventionResult {
    if pid <= 2 {
        return InterventionResult::err(
            "kernel_terminate",
            &pid.to_string(),
            "Refusing to terminate system init or kernel thread manager (PID <= 2)",
        );
    }

    let proc_path = format!("/proc/{}", pid);
    let proc_dir = Path::new(&proc_path);
    if !proc_dir.exists() {
        return InterventionResult::err("kernel_terminate", &pid.to_string(), "Target PID does not exist");
    }

    if let Ok(cmd) = read_proc_bounded(&proc_dir.join("cmdline"), 65536) {
        if cmd.is_empty() {
            return InterventionResult::err(
                "kernel_terminate",
                &pid.to_string(),
                "Refusing to terminate core kernel thread (empty cmdline)",
            );
        }
    }

    if let Ok(comm_bytes) = read_proc_bounded(&proc_dir.join("comm"), 256) {
        let comm = String::from_utf8_lossy(&comm_bytes).trim().to_string();
        if IMMUNE_PROCESSES.contains(&comm.as_str()) {
            return InterventionResult::err(
                "kernel_terminate",
                &pid.to_string(),
                &format!("Refusing to terminate immune critical system process '{}'", comm),
            );
        }
    }

    let pid_str = pid.to_string();

    // 1. Direct SIGTERM
    // SAFETY: Validated PID > 2, verified not kernel thread, verified not immune. SIGTERM is signal 15.
    let ret = unsafe { kill(pid, 15) };
    if ret == 0 {
        std::thread::sleep(Duration::from_millis(15));
        if Path::new(&proc_path).exists() {
            // SAFETY: SIGKILL is signal 9.
            unsafe { kill(pid, 9) };
        }
        return InterventionResult::ok(
            "kernel_terminate",
            &pid_str,
            &format!("Process {} terminated via kernel signal (SIGTERM/SIGKILL)", pid),
        );
    }

    // 2. Fallback via /usr/bin/kill
    let deadline = Instant::now() + Duration::from_secs(3);
    let out = run_cmd_bounded(
        "/usr/bin/kill",
        &["-TERM", "--", &pid_str],
        &[],
        deadline,
        4096,
    );
    if out.is_some() {
        std::thread::sleep(Duration::from_millis(15));
        if Path::new(&proc_path).exists() {
            let kill_deadline = Instant::now() + Duration::from_secs(2);
            let _ = run_cmd_bounded(
                "/usr/bin/kill",
                &["-KILL", "--", &pid_str],
                &[],
                kill_deadline,
                4096,
            );
        }
        return InterventionResult::ok(
            "kernel_terminate",
            &pid_str,
            &format!("Process {} terminated via signal", pid),
        );
    }

    // 3. Privileged fallback via pkexec
    if Path::new("/usr/bin/pkexec").exists() {
        let pk_deadline = Instant::now() + Duration::from_secs(10);
        let pk_out = run_cmd_bounded(
            "/usr/bin/pkexec",
            &["/usr/bin/kill", "-KILL", "--", &pid_str],
            &[],
            pk_deadline,
            4096,
        );
        if pk_out.is_some() {
            return InterventionResult::ok(
                "kernel_terminate",
                &pid_str,
                &format!("Process {} terminated via privileged kernel signal", pid),
            );
        }
    }

    InterventionResult::err(
        "kernel_terminate",
        &pid_str,
        "Permission denied or failure sending termination signals",
    )
}

/// Thaws (resumes) a previously frozen process (SIGCONT / 18).
pub fn kernel_thaw_process(pid: i32) -> InterventionResult {
    if pid <= 2 {
        return InterventionResult::err("kernel_thaw", &pid.to_string(), "Invalid PID (<= 2)");
    }

    // SAFETY: Validated PID > 2. SIGCONT is signal 18.
    let ret = unsafe { kill(pid, 18) };
    if ret == 0 {
        InterventionResult::ok(
            "kernel_thaw",
            &pid.to_string(),
            &format!("Process {} resumed (SIGCONT)", pid),
        )
    } else {
        let pid_str = pid.to_string();
        let deadline = Instant::now() + Duration::from_secs(3);
        let out = run_cmd_bounded(
            "/usr/bin/kill",
            &["-CONT", "--", &pid_str],
            &[],
            deadline,
            4096,
        );

        match out {
            Some(_) => InterventionResult::ok(
                "kernel_thaw",
                &pid_str,
                &format!("Process {} resumed via signal", pid),
            ),
            None => InterventionResult::err(
                "kernel_thaw",
                &pid_str,
                "Failed to send SIGCONT to process",
            ),
        }
    }
}

/// Severs an active network socket using kernel sock_diag (ss -K).
/// Resets TCP connection directly inside Linux network stack.
pub fn kernel_sever_socket(target: &str) -> InterventionResult {
    let target = target.trim();
    if target.is_empty() {
        return InterventionResult::err("kernel_sever_socket", target, "Target endpoint cannot be empty");
    }

    // Validate if port or IP
    let deadline = Instant::now() + Duration::from_secs(3);

    // If target is purely digits (port)
    if let Ok(port) = target.parse::<u16>() {
        if port == 0 {
            return InterventionResult::err("kernel_sever_socket", target, "Port 0 is invalid");
        }
        let filter = format!("sport = :{} or dport = :{}", port, port);
        let out = run_cmd_bounded(
            "/usr/bin/ss",
            &["-K", "-t", "-a", &filter],
            &[],
            deadline,
            8192,
        );

        return match out {
            Some(_) => InterventionResult::ok(
                "kernel_sever_socket",
                target,
                &format!("Kernel sock_diag TCP reset signal sent for port {}", port),
            ),
            None => InterventionResult::err(
                "kernel_sever_socket",
                target,
                "Failed to execute ss -K socket termination (requires root or CAP_NET_ADMIN)",
            ),
        };
    }

    // If target is IP
    if let Ok(ip) = target.parse::<IpAddr>() {
        if ip.is_loopback() || ip.is_unspecified() {
            return InterventionResult::err(
                "kernel_sever_socket",
                target,
                "Refusing to sever internal loopback or unspecified address",
            );
        }
        let filter = format!("dst {}", target);
        let out = run_cmd_bounded(
            "/usr/bin/ss",
            &["-K", "-t", "-a", &filter],
            &[],
            deadline,
            8192,
        );

        return match out {
            Some(_) => InterventionResult::ok(
                "kernel_sever_socket",
                target,
                &format!("Kernel sock_diag TCP reset signal sent for IP {}", target),
            ),
            None => InterventionResult::err(
                "kernel_sever_socket",
                target,
                "Failed to execute ss -K socket termination",
            ),
        };
    }

    InterventionResult::err(
        "kernel_sever_socket",
        target,
        "Target must be a valid numeric port or IPv4/IPv6 address",
    )
}

/// De-authorizes a USB device at the kernel sysfs level, instantly severing hardware communication.
/// Writes '0' to /sys/bus/usb/devices/{bus_id}/authorized.
pub fn kernel_deauth_usb(bus_id: &str) -> InterventionResult {
    let clean_id = bus_id.trim();

    // Strict validation: bus_id must only consist of alphanumeric characters, hyphens, and dots.
    // Prevent path traversal and hidden file injection.
    if clean_id.is_empty()
        || clean_id.len() > 32
        || clean_id.contains("..")
        || clean_id.starts_with('.')
        || !clean_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == ':')
    {
        return InterventionResult::err("kernel_deauth_usb", clean_id, "Invalid USB Bus ID format");
    }

    let auth_path = format!("/sys/bus/usb/devices/{}/authorized", clean_id);
    let path = Path::new(&auth_path);

    let mut file = match OpenOptions::new()
        .write(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            // Fallback to pkexec if sysfs write is denied
            if Path::new("/usr/bin/pkexec").exists() {
                let pk_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let pk_out = run_cmd_bounded(
                    "/usr/bin/pkexec",
                    &["/usr/bin/sh", "-c", &format!("echo 0 > /sys/bus/usb/devices/{}/authorized", clean_id)],
                    &[],
                    pk_deadline,
                    4096,
                );
                if pk_out.is_some() {
                    return InterventionResult::ok(
                        "kernel_deauth_usb",
                        clean_id,
                        &format!("USB device {} de-authorized at kernel hardware interface via pkexec", clean_id),
                    );
                }
            }

            return InterventionResult::err(
                "kernel_deauth_usb",
                clean_id,
                &format!("Failed to open USB authorized sysfs node: {}", e),
            );
        }
    };

    match file.write_all(b"0\n") {
        Ok(_) => InterventionResult::ok(
            "kernel_deauth_usb",
            clean_id,
            &format!("USB device {} de-authorized at kernel hardware interface", clean_id),
        ),
        Err(e) => InterventionResult::err(
            "kernel_deauth_usb",
            clean_id,
            &format!("Failed to write deauthorization: {}", e),
        ),
    }
}

/// Places an IP address into the kernel nftables quarantine table (`inet sentinel_quarantine`).
pub fn kernel_quarantine_ip(ip_str: &str) -> InterventionResult {
    let clean_ip = ip_str.trim();
    let ip: IpAddr = match clean_ip.parse() {
        Ok(addr) => addr,
        Err(_) => {
            return InterventionResult::err(
                "kernel_quarantine_ip",
                clean_ip,
                "Invalid IP address format",
            );
        }
    };

    if ip.is_loopback() || ip.is_unspecified() || clean_ip == "255.255.255.255" {
        return InterventionResult::err(
            "kernel_quarantine_ip",
            clean_ip,
            "Refusing to quarantine loopback, unspecified, or broadcast address",
        );
    }

    let deadline = Instant::now() + Duration::from_secs(3);

    // Check if nft is installed
    if !Path::new("/usr/bin/nft").exists() {
        return InterventionResult::err(
            "kernel_quarantine_ip",
            clean_ip,
            "nft binary not found in /usr/bin/nft",
        );
    }

    // Create table & chain if not exist
    let _ = run_cmd_bounded(
        "/usr/bin/nft",
        &["add", "table", "inet", "sentinel_quarantine"],
        &[],
        deadline,
        4096,
    );

    let _ = run_cmd_bounded(
        "/usr/bin/nft",
        &[
            "add",
            "chain",
            "inet",
            "sentinel_quarantine",
            "quarantine_out",
            "{ type filter hook output priority 0; policy accept; }",
        ],
        &[],
        deadline,
        4096,
    );

    let proto = if ip.is_ipv6() { "ip6" } else { "ip" };

    // Add drop rule with specific IP protocol
    let out = run_cmd_bounded(
        "/usr/bin/nft",
        &[
            "add",
            "rule",
            "inet",
            "sentinel_quarantine",
            "quarantine_out",
            proto,
            "daddr",
            clean_ip,
            "drop",
        ],
        &[],
        deadline,
        4096,
    );

    match out {
        Some(_) => InterventionResult::ok(
            "kernel_quarantine_ip",
            clean_ip,
            &format!("IP {} successfully quarantined in kernel nftables drop chain", clean_ip),
        ),
        None => InterventionResult::err(
            "kernel_quarantine_ip",
            clean_ip,
            "Failed to inject drop rule into nftables (requires root/CAP_NET_ADMIN)",
        ),
    }
}

/// Captures cryptographic forensic evidence (executable hash, cmdline, comm)
/// of a frozen process to disk with 0600 file permissions.
fn capture_forensic_evidence(pid: i32) {
    let proc_path = format!("/proc/{}", pid);
    let proc_dir = Path::new(&proc_path);
    let exe_hash = if let Ok(bytes) = read_proc_bounded(&proc_dir.join("exe"), 16 * 1024 * 1024) {
        crate::kernel::self_defense::sha256_hex(&bytes)
    } else {
        "UNREADABLE".to_string()
    };
    let cmdline = read_proc_bounded(&proc_dir.join("cmdline"), 65536)
        .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
        .unwrap_or_else(|_| "UNKNOWN".to_string());
    let comm = read_proc_bounded(&proc_dir.join("comm"), 256)
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_else(|_| "UNKNOWN".to_string());

    let state_dir = match std::env::var("HOME") {
        Ok(h) => Path::new(&h).join(".local/state/omarchy/sentinel_forensics"),
        Err(_) => Path::new("/tmp/sentinel_forensics").to_path_buf(),
    };
    let _ = std::fs::create_dir_all(&state_dir);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let evidence_file = state_dir.join(format!("forensics_{}_{}.json", pid, timestamp));
    let json = format!(
        "{{\n  \"pid\": {},\n  \"comm\": \"{}\",\n  \"cmdline\": \"{}\",\n  \"exe_sha256\": \"{}\",\n  \"timestamp\": {}\n}}\n",
        pid,
        comm.replace('"', "\\\""),
        cmdline.replace('"', "\\\""),
        exe_hash,
        timestamp
    );
    let _ = std::fs::write(&evidence_file, json.as_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&evidence_file, std::fs::Permissions::from_mode(0o600));
    }
}

/// Enforces an immediate emergency military network blackout (Panic Mode / Killswitch).
/// Completely drops all inbound and outbound IP traffic on all interfaces except loopback ('lo').
pub fn kernel_apply_network_blackout() -> InterventionResult {
    let deadline = Instant::now() + Duration::from_secs(4);

    if !Path::new("/usr/bin/nft").exists() {
        return InterventionResult::err(
            "network_blackout",
            "all_interfaces",
            "nft binary not found in /usr/bin/nft",
        );
    }

    let script = "table inet sentinel_blackout {\n    chain output {\n        type filter hook output priority -100; policy drop;\n        oif \"lo\" accept\n        counter reject with icmpx type admin-prohibited\n    }\n    chain input {\n        type filter hook input priority -100; policy drop;\n        iif \"lo\" accept\n        counter drop\n    }\n}\n";

    let tmp_path = format!("/tmp/.sentinel_blackout_{}.nft", std::process::id());
    let _ = std::fs::write(&tmp_path, script);

    let out = run_cmd_bounded(
        "/usr/bin/nft",
        &["-f", &tmp_path],
        &[],
        deadline,
        4096,
    );

    let _ = std::fs::remove_file(&tmp_path);

    if out.is_none() && Path::new("/usr/bin/pkexec").exists() {
        let pk_deadline = Instant::now() + Duration::from_secs(10);
        let _ = std::fs::write(&tmp_path, script);
        let pk_out = run_cmd_bounded(
            "/usr/bin/pkexec",
            &["/usr/bin/nft", "-f", &tmp_path],
            &[],
            pk_deadline,
            4096,
        );
        let _ = std::fs::remove_file(&tmp_path);
        if pk_out.is_some() {
            return InterventionResult::ok(
                "network_blackout",
                "all_interfaces",
                "Emergency military network blackout engaged via privileged nftables killswitch",
            );
        }
    }

    match out {
        Some(_) => InterventionResult::ok(
            "network_blackout",
            "all_interfaces",
            "Emergency military network blackout engaged: All non-loopback egress and ingress severed",
        ),
        None => InterventionResult::err(
            "network_blackout",
            "all_interfaces",
            "Failed to enforce network blackout (insufficient privileges or nftables error)",
        ),
    }
}

/// Clears the emergency network blackout, restoring normal networking.
pub fn kernel_clear_network_blackout() -> InterventionResult {
    let deadline = Instant::now() + Duration::from_secs(3);

    let out = run_cmd_bounded(
        "/usr/bin/nft",
        &["delete", "table", "inet", "sentinel_blackout"],
        &[],
        deadline,
        4096,
    );

    if out.is_none() && Path::new("/usr/bin/pkexec").exists() {
        let pk_deadline = Instant::now() + Duration::from_secs(10);
        let pk_out = run_cmd_bounded(
            "/usr/bin/pkexec",
            &["/usr/bin/nft", "delete", "table", "inet", "sentinel_blackout"],
            &[],
            pk_deadline,
            4096,
        );
        if pk_out.is_some() {
            return InterventionResult::ok(
                "network_blackout",
                "all_interfaces",
                "Emergency network blackout cleared via privileged nftables command",
            );
        }
    }

    match out {
        Some(_) => InterventionResult::ok(
            "network_blackout",
            "all_interfaces",
            "Emergency network blackout cleared: Normal network connectivity restored",
        ),
        None => InterventionResult::err(
            "network_blackout",
            "all_interfaces",
            "Failed to delete blackout table (table may not exist or permission denied)",
        ),
    }
}

/// Checks if the emergency network blackout table is currently active in the kernel.
pub fn kernel_is_network_blackout_active() -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    let out = run_cmd_bounded(
        "/usr/bin/nft",
        &["list", "table", "inet", "sentinel_blackout"],
        &[],
        deadline,
        4096,
    );
    out.is_some()
}
