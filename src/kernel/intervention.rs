use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::subproc::{run_cmd_bounded, run_cmd_write_stdin_bounded};

const O_NOFOLLOW: i32 = 0o400000;

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn getuid() -> u32;
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

/// Trusted install prefixes for immune system binaries.
const TRUSTED_EXE_PREFIXES: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"];

/// Returns the process name if the target is an immune critical system process.
///
/// `comm` alone is attacker-controlled (any process can rename itself to "sshd" via
/// prctl(PR_SET_NAME) or argv[0]), so a name match only grants immunity when the
/// executable also lives under a trusted system prefix. If the exe link is unreadable
/// (foreign-owned or root process), the name match is honoured conservatively.
fn immune_process_name(proc_dir: &Path) -> Option<String> {
    let comm_bytes = read_proc_bounded(&proc_dir.join("comm"), 256).ok()?;
    let comm = String::from_utf8_lossy(&comm_bytes).trim().to_string();
    if !IMMUNE_PROCESSES.contains(&comm.as_str()) {
        return None;
    }
    match std::fs::read_link(proc_dir.join("exe")) {
        Ok(exe) => {
            let exe = exe.to_string_lossy();
            let trusted = !exe.ends_with(" (deleted)")
                && TRUSTED_EXE_PREFIXES.iter().any(|p| exe.starts_with(p));
            if trusted {
                Some(comm)
            } else {
                None
            }
        }
        Err(_) => Some(comm),
    }
}

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
    if let Some(comm) = immune_process_name(proc_dir) {
        return InterventionResult::err(
            "kernel_freeze",
            &pid.to_string(),
            &format!("Refusing to freeze immune critical system process '{}'", comm),
        );
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

    if let Some(comm) = immune_process_name(proc_dir) {
        return InterventionResult::err(
            "kernel_terminate",
            &pid.to_string(),
            &format!("Refusing to terminate immune critical system process '{}'", comm),
        );
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

    // Check if nft is installed
    if !Path::new("/usr/bin/nft").exists() {
        return InterventionResult::err(
            "kernel_quarantine_ip",
            clean_ip,
            "nft binary not found in /usr/bin/nft",
        );
    }

    // One atomic, idempotent nft transaction fed through stdin: the table, sets and
    // set-based chains are (re)declared, the chains are flushed and refilled with a
    // single rule per family, and the address is added as a set element. Repeated
    // quarantines therefore never stack duplicate rules, and both directions are dropped.
    let script = quarantine_script(ip);
    let deadline = Instant::now() + Duration::from_secs(3);
    if run_cmd_write_stdin_bounded("/usr/bin/nft", &["-f", "-"], &[], script.as_bytes(), deadline) {
        return InterventionResult::ok(
            "kernel_quarantine_ip",
            clean_ip,
            &format!("IP {} successfully quarantined in kernel nftables drop set", clean_ip),
        );
    }

    if Path::new("/usr/bin/pkexec").exists() {
        let pk_deadline = Instant::now() + Duration::from_secs(30);
        if run_cmd_write_stdin_bounded(
            "/usr/bin/pkexec",
            &["/usr/bin/nft", "-f", "-"],
            &[],
            script.as_bytes(),
            pk_deadline,
        ) {
            return InterventionResult::ok(
                "kernel_quarantine_ip",
                clean_ip,
                &format!("IP {} quarantined in kernel nftables drop set via pkexec", clean_ip),
            );
        }
    }

    InterventionResult::err(
        "kernel_quarantine_ip",
        clean_ip,
        "Failed to inject drop rule into nftables (requires root/CAP_NET_ADMIN)",
    )
}

/// Builds the nftables transaction used by [`kernel_quarantine_ip`].
pub fn quarantine_script(ip: IpAddr) -> String {
    let set = if ip.is_ipv6() { "blocked6" } else { "blocked4" };
    format!(
        "table inet sentinel_quarantine {{\n\
         \x20   set blocked4 {{ type ipv4_addr; }}\n\
         \x20   set blocked6 {{ type ipv6_addr; }}\n\
         \x20   chain quarantine_set_out {{ type filter hook output priority 0; policy accept; }}\n\
         \x20   chain quarantine_set_in {{ type filter hook input priority 0; policy accept; }}\n\
         }}\n\
         flush chain inet sentinel_quarantine quarantine_set_out\n\
         flush chain inet sentinel_quarantine quarantine_set_in\n\
         add rule inet sentinel_quarantine quarantine_set_out ip daddr @blocked4 drop\n\
         add rule inet sentinel_quarantine quarantine_set_out ip6 daddr @blocked6 drop\n\
         add rule inet sentinel_quarantine quarantine_set_in ip saddr @blocked4 drop\n\
         add rule inet sentinel_quarantine quarantine_set_in ip6 saddr @blocked6 drop\n\
         add element inet sentinel_quarantine {} {{ {} }}\n",
        set, ip
    )
}

/// Retrieves and verifies the secure private state directory (~/.local/state/omarchy/sentinel),
/// strictly validating permissions (0700) and rejecting symlink anomalies or foreign ownership.
fn get_private_state_dir() -> Result<PathBuf, String> {
    let state_dir = if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        if !state.is_empty() {
            PathBuf::from(state).join("omarchy/sentinel")
        } else {
            let home = std::env::var("HOME").map_err(|_| "HOME environment variable is not set".to_string())?;
            PathBuf::from(home).join(".local/state/omarchy/sentinel")
        }
    } else {
        let home = std::env::var("HOME").map_err(|_| "HOME environment variable is not set".to_string())?;
        PathBuf::from(home).join(".local/state/omarchy/sentinel")
    };

    if state_dir.exists() {
        let meta = std::fs::symlink_metadata(&state_dir)
            .map_err(|e| format!("Failed to read state dir metadata: {}", e))?;
        if meta.file_type().is_symlink() {
            return Err(format!("State directory {} is a symlink", state_dir.display()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != unsafe { getuid() } {
                return Err(format!("State directory {} is not owned by current user", state_dir.display()));
            }
        }
    } else {
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| format!("Failed to create private state directory: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700));
        }
    }

    Ok(state_dir)
}

/// Captures cryptographic forensic evidence (executable hash, cmdline, comm)
/// of a frozen process to disk with 0600 file permissions in private state storage.
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

    let state_dir = match get_private_state_dir() {
        Ok(d) => d.join("forensics"),
        Err(_) => return,
    };
    let _ = std::fs::create_dir_all(&state_dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700));
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let evidence_file = state_dir.join(format!("forensics_{}_{}.json", pid, timestamp));
    // serde_json escapes backslashes and control characters too; cmdline/comm are
    // attacker-controlled and must never be spliced into JSON by hand.
    let json = match serde_json::to_string_pretty(&serde_json::json!({
        "pid": pid,
        "comm": comm,
        "cmdline": cmdline,
        "exe_sha256": exe_hash,
        "timestamp": timestamp,
    })) {
        Ok(j) => j + "\n",
        Err(_) => return,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = OpenOptions::new();
        opts.write(true)
            .create(true)
            .truncate(true)
            .custom_flags(O_NOFOLLOW)
            .mode(0o600);
        if let Ok(mut file) = opts.open(&evidence_file) {
            let _ = file.write_all(json.as_bytes());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(&evidence_file, json.as_bytes());
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

    let state_dir = match get_private_state_dir() {
        Ok(d) => d,
        Err(e) => {
            return InterventionResult::err(
                "network_blackout",
                "all_interfaces",
                &format!("Failed to initialize private rule storage: {}", e),
            );
        }
    };

    let script = "table inet sentinel_blackout {\n    chain output {\n        type filter hook output priority -100; policy drop;\n        oif \"lo\" accept\n        counter reject with icmpx type admin-prohibited\n    }\n    chain input {\n        type filter hook input priority -100; policy drop;\n        iif \"lo\" accept\n        counter drop\n    }\n}\n";

    let rule_file_path = state_dir.join(format!("sentinel_blackout_{}.nft", std::process::id()));

    // Write rule file to private storage with mode 0600 and O_NOFOLLOW
    let write_res = (|| -> Result<(), String> {
        if rule_file_path.exists() {
            let meta = std::fs::symlink_metadata(&rule_file_path)
                .map_err(|e| format!("Symlink check failed: {}", e))?;
            if meta.file_type().is_symlink() {
                let _ = std::fs::remove_file(&rule_file_path);
            }
        }

        #[cfg(unix)]
        {
            let mut opts = OpenOptions::new();
            opts.write(true)
                .create(true)
                .truncate(true)
                .custom_flags(O_NOFOLLOW)
                .mode(0o600);
            let mut file = opts
                .open(&rule_file_path)
                .map_err(|e| format!("Failed to create private rule file: {}", e))?;
            file.write_all(script.as_bytes())
                .map_err(|e| format!("Failed to write rule content: {}", e))?;
            file.sync_all()
                .map_err(|e| format!("Failed to sync rule file: {}", e))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&rule_file_path, script)
                .map_err(|e| format!("Failed to write rule file: {}", e))?;
        }

        // Verify written file is regular and owned by current user
        let meta = std::fs::symlink_metadata(&rule_file_path)
            .map_err(|e| format!("Verification failed: {}", e))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err("Rule file is not a regular file".to_string());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != unsafe { getuid() } {
                return Err("Rule file is not owned by current user".to_string());
            }
        }

        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&rule_file_path);
        return InterventionResult::err(
            "network_blackout",
            "all_interfaces",
            &format!("Aborting blackout: Failed to safely write rule file: {}", err),
        );
    }

    let rule_str = rule_file_path.to_string_lossy().to_string();

    let out = run_cmd_bounded(
        "/usr/bin/nft",
        &["-f", &rule_str],
        &[],
        deadline,
        4096,
    );

    let res = if out.is_some() {
        InterventionResult::ok(
            "network_blackout",
            "all_interfaces",
            "Emergency military network blackout engaged: All non-loopback egress and ingress severed",
        )
    } else if Path::new("/usr/bin/pkexec").exists() {
        let pk_deadline = Instant::now() + Duration::from_secs(10);
        let pk_out = run_cmd_bounded(
            "/usr/bin/pkexec",
            &["/usr/bin/nft", "-f", &rule_str],
            &[],
            pk_deadline,
            4096,
        );
        if pk_out.is_some() {
            InterventionResult::ok(
                "network_blackout",
                "all_interfaces",
                "Emergency military network blackout engaged via privileged nftables killswitch",
            )
        } else {
            InterventionResult::err(
                "network_blackout",
                "all_interfaces",
                "Failed to enforce network blackout via privileged nftables",
            )
        }
    } else {
        InterventionResult::err(
            "network_blackout",
            "all_interfaces",
            "Failed to enforce network blackout (insufficient privileges or nftables error)",
        )
    };

    let _ = std::fs::remove_file(&rule_file_path);
    if res.success {
        record_blackout_marker(&state_dir);
    }
    res
}

const BLACKOUT_MARKER: &str = "network_blackout.active";

/// Current kernel boot id, used to invalidate the blackout marker after a reboot
/// (nftables rulesets are not persistent across boots).
fn current_boot_id() -> Option<String> {
    read_proc_bounded(Path::new("/proc/sys/kernel/random/boot_id"), 128)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Records that a blackout was engaged during this boot. Unprivileged users cannot
/// `nft list` the ruleset, so without this marker the UI would always report the
/// killswitch as inactive after a pkexec-elevated blackout.
fn record_blackout_marker(state_dir: &Path) {
    let Some(boot_id) = current_boot_id() else { return };
    let mut opts = OpenOptions::new();
    opts.write(true)
        .create(true)
        .truncate(true)
        .custom_flags(O_NOFOLLOW)
        .mode(0o600);
    if let Ok(mut file) = opts.open(state_dir.join(BLACKOUT_MARKER)) {
        let _ = file.write_all(boot_id.as_bytes());
    }
}

fn clear_blackout_marker() {
    if let Ok(dir) = get_private_state_dir() {
        let _ = std::fs::remove_file(dir.join(BLACKOUT_MARKER));
    }
}

fn blackout_marker_matches_boot() -> bool {
    let Ok(dir) = get_private_state_dir() else { return false };
    let marker = dir.join(BLACKOUT_MARKER);
    match std::fs::symlink_metadata(&marker) {
        Ok(meta) if meta.is_file() => {}
        _ => return false,
    }
    match (read_proc_bounded(&marker, 128), current_boot_id()) {
        (Ok(bytes), Some(boot_id)) => String::from_utf8_lossy(&bytes).trim() == boot_id,
        _ => false,
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
            clear_blackout_marker();
            return InterventionResult::ok(
                "network_blackout",
                "all_interfaces",
                "Emergency network blackout cleared via privileged nftables command",
            );
        }
    }

    match out {
        Some(_) => {
            clear_blackout_marker();
            InterventionResult::ok(
            "network_blackout",
            "all_interfaces",
            "Emergency network blackout cleared: Normal network connectivity restored",
            )
        }
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
    // Root can query the ruleset directly; unprivileged callers fall back to the
    // per-boot marker written when the blackout was engaged.
    out.is_some() || blackout_marker_matches_boot()
}
