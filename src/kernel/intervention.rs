use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
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

    // Refuse to freeze kernel threads (empty /proc/[pid]/cmdline)
    if let Ok(cmd) = std::fs::read(proc_dir.join("cmdline")) {
        if cmd.is_empty() {
            return InterventionResult::err(
                "kernel_freeze",
                &pid.to_string(),
                "Refusing to freeze core kernel thread (empty cmdline)",
            );
        }
    }

    // Check immune critical processes
    if let Ok(comm_bytes) = std::fs::read(proc_dir.join("comm")) {
        let comm = String::from_utf8_lossy(&comm_bytes).trim().to_string();
        let immune_list = [
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
        if immune_list.contains(&comm.as_str()) {
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
        InterventionResult::ok(
            "kernel_freeze",
            &pid.to_string(),
            &format!("Process {} successfully frozen at kernel level (SIGSTOP)", pid),
        )
    } else {
        // Fallback: try via pkexec / kill with bounded execution
        let pid_str = pid.to_string();
        let deadline = Instant::now() + Duration::from_secs(3);
        let out = run_cmd_bounded(
            "/usr/bin/kill",
            &["-STOP", "--", &pid_str],
            &[],
            deadline,
            4096,
        );

        match out {
            Some(_) => InterventionResult::ok(
                "kernel_freeze",
                &pid_str,
                &format!("Process {} frozen via kernel signal", pid),
            ),
            None => InterventionResult::err(
                "kernel_freeze",
                &pid_str,
                "Permission denied or failure sending SIGSTOP signal",
            ),
        }
    }
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

    // Direct open with O_NOFOLLOW to avoid TOCTOU race conditions
    let mut file = match OpenOptions::new()
        .write(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
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
