use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::subproc::{run_cmd_bounded, run_cmd_bounded_status, run_cmd_write_stdin_bounded};

const O_NOFOLLOW: i32 = 0o400000;

const SIGKILL: i32 = 9;
const SIGTERM: i32 = 15;
const SIGCONT: i32 = 18;
const SIGSTOP: i32 = 19;

const ESRCH: i32 = 3;
const ENOSYS: i32 = 38;

// Generic syscall table numbers (identical on x86_64 and aarch64)
const SYS_PIDFD_SEND_SIGNAL: i64 = 424;
const SYS_PIDFD_OPEN: i64 = 434;

const PKEXEC: &str = "/usr/bin/pkexec";
const NFT: &str = "/usr/bin/nft";

/// The packaged, root-owned engine that the shipped polkit policy
/// (`io.omarchy.sentinel.*`) authorizes. Privileged operations are routed through it.
pub const PRIVILEGED_ENGINE: &str = "/usr/bin/sentinel-engine";
/// CLI flag for the `io.omarchy.sentinel.intervention` polkit action.
pub const PRIVILEGED_INTERVENTION_FLAG: &str = "--privileged-intervention";
/// CLI flag for the `io.omarchy.sentinel.network` polkit action.
pub const PRIVILEGED_NETWORK_FLAG: &str = "--privileged-network";

/// Generous deadline for anything that may wait on a polkit password prompt.
const PKEXEC_TIMEOUT: Duration = Duration::from_secs(120);

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn getuid() -> u32;
    fn close(fd: i32) -> i32;
    fn syscall(num: i64, ...) -> i64;
}

static PRIVILEGED_MODE: AtomicBool = AtomicBool::new(false);

/// Marks this process as the root-side polkit helper. In this mode no further
/// escalation is attempted and nothing is written to (root's) state directory.
pub fn enter_privileged_mode() {
    PRIVILEGED_MODE.store(true, Ordering::SeqCst);
}

fn in_privileged_mode() -> bool {
    PRIVILEGED_MODE.load(Ordering::SeqCst)
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
    let mut file =
        File::open(path).map_err(|e| format!("Failed to open {}: {}", path.display(), e))?;
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
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Privilege escalation
// ---------------------------------------------------------------------------

/// True when the packaged engine exists as a root-owned regular file that only root
/// can modify, so handing it to pkexec cannot run user-controlled code as root.
fn trusted_privileged_engine() -> bool {
    match std::fs::symlink_metadata(PRIVILEGED_ENGINE) {
        Ok(meta) => meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        Err(_) => false,
    }
}

/// Re-runs one operation as root through `pkexec /usr/bin/sentinel-engine <flag> <args>`,
/// which matches the shipped polkit actions (custom message, `auth_admin_keep`).
/// Returns `None` when the helper is unavailable so callers can use the legacy path.
fn escalate_via_helper(flag: &str, args: &[&str]) -> Option<InterventionResult> {
    if in_privileged_mode() || !Path::new(PKEXEC).exists() || !trusted_privileged_engine() {
        return None;
    }
    let mut argv = vec![PRIVILEGED_ENGINE, flag];
    argv.extend_from_slice(args);
    let deadline = Instant::now() + PKEXEC_TIMEOUT;
    let action = format!(
        "{} {}",
        flag.trim_start_matches('-'),
        args.first().unwrap_or(&"")
    );
    let target = args.get(1).copied().unwrap_or("");
    match run_cmd_bounded_status(PKEXEC, &argv, &[], deadline, 16384) {
        Some((_, out)) => Some(
            serde_json::from_slice::<InterventionResult>(&out).unwrap_or_else(|_| {
                InterventionResult::err(
                    &action,
                    target,
                    "Privileged helper failed or authentication was cancelled",
                )
            }),
        ),
        None => Some(InterventionResult::err(
            &action,
            target,
            "Privileged helper timed out waiting for authentication",
        )),
    }
}

/// Legacy escalation for source installs without a root-owned `/usr/bin/sentinel-engine`:
/// pkexec runs the system tool directly (generic polkit prompt).
fn legacy_pkexec(argv: &[&str], stdin: Option<&[u8]>) -> bool {
    if in_privileged_mode() || !Path::new(PKEXEC).exists() {
        return false;
    }
    let deadline = Instant::now() + PKEXEC_TIMEOUT;
    match stdin {
        Some(data) => run_cmd_write_stdin_bounded(PKEXEC, argv, &[], data, deadline),
        None => run_cmd_bounded(PKEXEC, argv, &[], deadline, 16384).is_some(),
    }
}

// ---------------------------------------------------------------------------
// Process signalling (pidfd)
// ---------------------------------------------------------------------------

/// A pidfd pins the exact process that was validated: if it exits and the PID is
/// reused before the signal is sent, the kernel returns ESRCH instead of signalling
/// the unrelated new process.
struct ProcessHandle {
    pid: i32,
    pidfd: Option<i32>,
}

impl ProcessHandle {
    /// Must be called *before* inspecting /proc/<pid>, so the checks and the signal
    /// are guaranteed to refer to the same process.
    fn open(pid: i32) -> Self {
        // SAFETY: pidfd_open(pid, flags=0) takes two integer arguments and returns a new fd or -1.
        let fd = unsafe { syscall(SYS_PIDFD_OPEN, pid as i64, 0i64) };
        Self {
            pid,
            pidfd: if fd >= 0 { Some(fd as i32) } else { None },
        }
    }

    /// Sends `sig`; returns the errno on failure.
    fn signal(&self, sig: i32) -> Result<(), i32> {
        let ret = match self.pidfd {
            // SAFETY: valid pidfd owned by self; info=NULL and flags=0 are permitted.
            Some(fd) => unsafe {
                syscall(SYS_PIDFD_SEND_SIGNAL, fd as i64, sig as i64, 0i64, 0i64)
            },
            // SAFETY: plain kill(2) fallback for kernels without pidfd (< 5.3)
            None => unsafe { kill(self.pid, sig) as i64 },
        };
        if ret == 0 {
            return Ok(());
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == ENOSYS && self.pidfd.is_some() {
            // SAFETY: as above
            if unsafe { kill(self.pid, sig) } == 0 {
                return Ok(());
            }
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        Err(errno)
    }

    fn is_alive(&self) -> bool {
        self.signal(0).is_ok()
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if let Some(fd) = self.pidfd {
            // SAFETY: fd was returned by pidfd_open and is closed exactly once.
            unsafe {
                close(fd);
            }
        }
    }
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

/// Shared safety gate for freeze/terminate: refuses init, kernel threads and immune
/// system daemons. Returns the error message on refusal.
fn validate_signal_target(pid: i32, verb: &str) -> Result<(), String> {
    if pid <= 2 {
        return Err(format!(
            "Refusing to {} system init or kernel thread manager (PID <= 2)",
            verb
        ));
    }
    let proc_path = format!("/proc/{}", pid);
    let proc_dir = Path::new(&proc_path);
    if !proc_dir.exists() {
        return Err("Target PID does not exist".to_string());
    }
    if let Ok(cmd) = read_proc_bounded(&proc_dir.join("cmdline"), 65536) {
        if cmd.is_empty() {
            return Err(format!(
                "Refusing to {} core kernel thread (empty cmdline)",
                verb
            ));
        }
    }
    if let Some(comm) = immune_process_name(proc_dir) {
        return Err(format!(
            "Refusing to {} immune critical system process '{}'",
            verb, comm
        ));
    }
    Ok(())
}

/// Freezes a suspect process at kernel level (SIGSTOP / 19).
/// Unlike SIGKILL, freezing suspends execution immediately without destroying
/// the memory state or socket descriptors, enabling forensic acquisition.
pub fn kernel_freeze_process(pid: i32) -> InterventionResult {
    let pid_str = pid.to_string();
    if pid <= 2 {
        return InterventionResult::err(
            "kernel_freeze",
            &pid_str,
            "Refusing to freeze system init or kernel thread manager (PID <= 2)",
        );
    }
    let handle = ProcessHandle::open(pid);
    if let Err(msg) = validate_signal_target(pid, "freeze") {
        return InterventionResult::err("kernel_freeze", &pid_str, &msg);
    }

    match handle.signal(SIGSTOP) {
        Ok(()) => {
            capture_forensic_evidence(pid);
            return InterventionResult::ok(
                "kernel_freeze",
                &pid_str,
                &format!(
                    "Process {} successfully frozen at kernel level (SIGSTOP) with forensic hash capture",
                    pid
                ),
            );
        }
        Err(ESRCH) => {
            return InterventionResult::err(
                "kernel_freeze",
                &pid_str,
                "Target process exited before it could be frozen",
            );
        }
        Err(_) => {}
    }

    // Permission denied: escalate
    if let Some(res) = escalate_via_helper(PRIVILEGED_INTERVENTION_FLAG, &["stop", &pid_str]) {
        if res.success {
            capture_forensic_evidence(pid);
        }
        return res;
    }
    if legacy_pkexec(&["/usr/bin/kill", "-STOP", "--", &pid_str], None) {
        capture_forensic_evidence(pid);
        return InterventionResult::ok(
            "kernel_freeze",
            &pid_str,
            &format!(
                "Process {} frozen via privileged kernel signal with forensic capture",
                pid
            ),
        );
    }

    InterventionResult::err(
        "kernel_freeze",
        &pid_str,
        "Permission denied or failure sending SIGSTOP signal",
    )
}

/// Terminates a malicious or uncooperative process at kernel level.
/// Sends SIGTERM (15) first, followed by SIGKILL (9) to ensure full eradication.
pub fn kernel_terminate_process(pid: i32) -> InterventionResult {
    let pid_str = pid.to_string();
    if pid <= 2 {
        return InterventionResult::err(
            "kernel_terminate",
            &pid_str,
            "Refusing to terminate system init or kernel thread manager (PID <= 2)",
        );
    }
    let handle = ProcessHandle::open(pid);
    if let Err(msg) = validate_signal_target(pid, "terminate") {
        return InterventionResult::err("kernel_terminate", &pid_str, &msg);
    }

    match handle.signal(SIGTERM) {
        Ok(()) => {
            // Give the process a brief chance to exit cleanly, then make sure it is gone.
            // The pidfd guarantees the SIGKILL cannot hit a recycled PID.
            for _ in 0..10 {
                if !handle.is_alive() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            if handle.is_alive() {
                let _ = handle.signal(SIGKILL);
            }
            return InterventionResult::ok(
                "kernel_terminate",
                &pid_str,
                &format!(
                    "Process {} terminated via kernel signal (SIGTERM/SIGKILL)",
                    pid
                ),
            );
        }
        Err(ESRCH) => {
            return InterventionResult::err(
                "kernel_terminate",
                &pid_str,
                "Target process exited before it could be terminated",
            );
        }
        Err(_) => {}
    }

    if let Some(res) = escalate_via_helper(PRIVILEGED_INTERVENTION_FLAG, &["terminate", &pid_str]) {
        return res;
    }
    if legacy_pkexec(&["/usr/bin/kill", "-KILL", "--", &pid_str], None) {
        return InterventionResult::ok(
            "kernel_terminate",
            &pid_str,
            &format!("Process {} terminated via privileged kernel signal", pid),
        );
    }

    InterventionResult::err(
        "kernel_terminate",
        &pid_str,
        "Permission denied or failure sending termination signals",
    )
}

/// Thaws (resumes) a previously frozen process (SIGCONT / 18).
pub fn kernel_thaw_process(pid: i32) -> InterventionResult {
    let pid_str = pid.to_string();
    if pid <= 2 {
        return InterventionResult::err("kernel_thaw", &pid_str, "Invalid PID (<= 2)");
    }

    match ProcessHandle::open(pid).signal(SIGCONT) {
        Ok(()) => {
            return InterventionResult::ok(
                "kernel_thaw",
                &pid_str,
                &format!("Process {} resumed (SIGCONT)", pid),
            );
        }
        Err(ESRCH) => {
            return InterventionResult::err("kernel_thaw", &pid_str, "Target PID does not exist")
        }
        Err(_) => {}
    }

    // A process frozen through pkexec is root-owned or foreign; resuming needs the same rights
    if let Some(res) = escalate_via_helper(PRIVILEGED_INTERVENTION_FLAG, &["continue", &pid_str]) {
        return res;
    }
    if legacy_pkexec(&["/usr/bin/kill", "-CONT", "--", &pid_str], None) {
        return InterventionResult::ok(
            "kernel_thaw",
            &pid_str,
            &format!("Process {} resumed via signal", pid),
        );
    }
    InterventionResult::err("kernel_thaw", &pid_str, "Failed to send SIGCONT to process")
}

// ---------------------------------------------------------------------------
// Sockets
// ---------------------------------------------------------------------------

/// Counts connected (non-listening) TCP sockets matching an `ss` filter expression.
fn count_connected_tcp(filter: &str) -> Option<usize> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let out = run_cmd_bounded(
        "/usr/bin/ss",
        &["-H", "-t", "-n", "state", "connected", filter],
        &[],
        deadline,
        1024 * 1024,
    )?;
    Some(
        String::from_utf8_lossy(&out)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count(),
    )
}

fn ss_kill(filter: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    // Only connected sockets: severing must never tear down a service's listener
    run_cmd_bounded(
        "/usr/bin/ss",
        &["-K", "-t", "state", "connected", filter],
        &[],
        deadline,
        65536,
    )
    .is_some()
}

/// Severs active TCP connections using kernel sock_diag (ss -K).
///
/// `ss -K` exits 0 even when it lacks CAP_NET_ADMIN or the kernel was built without
/// CONFIG_INET_DIAG_DESTROY, so success is decided by re-counting the connections.
pub fn kernel_sever_socket(target: &str) -> InterventionResult {
    let target = target.trim();
    if target.is_empty() {
        return InterventionResult::err(
            "kernel_sever_socket",
            target,
            "Target endpoint cannot be empty",
        );
    }

    let filter = if let Ok(port) = target.parse::<u16>() {
        if port == 0 {
            return InterventionResult::err("kernel_sever_socket", target, "Port 0 is invalid");
        }
        format!("sport = :{} or dport = :{}", port, port)
    } else if let Ok(ip) = target.parse::<IpAddr>() {
        if ip.is_loopback() || ip.is_unspecified() {
            return InterventionResult::err(
                "kernel_sever_socket",
                target,
                "Refusing to sever internal loopback or unspecified address",
            );
        }
        match ip {
            IpAddr::V4(v4) => format!("dst {}", v4),
            // ss needs brackets to tell an IPv6 address from a host:port pair
            IpAddr::V6(v6) => format!("dst [{}]", v6),
        }
    } else {
        return InterventionResult::err(
            "kernel_sever_socket",
            target,
            "Target must be a valid numeric port or IPv4/IPv6 address",
        );
    };

    let before = match count_connected_tcp(&filter) {
        Some(n) => n,
        None => {
            return InterventionResult::err(
                "kernel_sever_socket",
                target,
                "Failed to query sockets via /usr/bin/ss",
            );
        }
    };
    if before == 0 {
        return InterventionResult::err(
            "kernel_sever_socket",
            target,
            "No active TCP connections match the target",
        );
    }

    let _ = ss_kill(&filter);
    let mut remaining = count_connected_tcp(&filter).unwrap_or(before);
    if remaining > 0 {
        if let Some(res) =
            escalate_via_helper(PRIVILEGED_INTERVENTION_FLAG, &["sever-socket", target])
        {
            return res;
        }
        if legacy_pkexec(
            &["/usr/bin/ss", "-K", "-t", "state", "connected", &filter],
            None,
        ) {
            remaining = count_connected_tcp(&filter).unwrap_or(remaining);
        }
    }

    if remaining == 0 {
        InterventionResult::ok(
            "kernel_sever_socket",
            target,
            &format!(
                "Kernel sock_diag reset {} TCP connection(s) for {}",
                before, target
            ),
        )
    } else {
        InterventionResult::err(
            "kernel_sever_socket",
            target,
            &format!(
                "{} of {} connection(s) still active (requires root/CAP_NET_ADMIN and CONFIG_INET_DIAG_DESTROY)",
                remaining, before
            ),
        )
    }
}

// ---------------------------------------------------------------------------
// USB
// ---------------------------------------------------------------------------

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
        || !clean_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == ':')
    {
        return InterventionResult::err("kernel_deauth_usb", clean_id, "Invalid USB Bus ID format");
    }

    let auth_path = format!("/sys/bus/usb/devices/{}/authorized", clean_id);
    let path = Path::new(&auth_path);

    let open_err = match OpenOptions::new()
        .write(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
    {
        Ok(mut file) => {
            return match file.write_all(b"0\n") {
                Ok(_) => InterventionResult::ok(
                    "kernel_deauth_usb",
                    clean_id,
                    &format!(
                        "USB device {} de-authorized at kernel hardware interface",
                        clean_id
                    ),
                ),
                Err(e) => InterventionResult::err(
                    "kernel_deauth_usb",
                    clean_id,
                    &format!("Failed to write deauthorization: {}", e),
                ),
            };
        }
        Err(e) => e,
    };

    if !path.exists() {
        return InterventionResult::err(
            "kernel_deauth_usb",
            clean_id,
            "USB device not found in sysfs",
        );
    }
    if let Some(res) = escalate_via_helper(PRIVILEGED_INTERVENTION_FLAG, &["deauth-usb", clean_id])
    {
        return res;
    }
    // tee writes stdin to the validated path without a shell in between
    if legacy_pkexec(&["/usr/bin/tee", &auth_path], Some(b"0\n")) {
        return InterventionResult::ok(
            "kernel_deauth_usb",
            clean_id,
            &format!(
                "USB device {} de-authorized at kernel hardware interface via pkexec",
                clean_id
            ),
        );
    }

    InterventionResult::err(
        "kernel_deauth_usb",
        clean_id,
        &format!("Failed to open USB authorized sysfs node: {}", open_err),
    )
}

// ---------------------------------------------------------------------------
// nftables
// ---------------------------------------------------------------------------

fn nft_apply(script: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(4);
    run_cmd_write_stdin_bounded(NFT, &["-f", "-"], &[], script.as_bytes(), deadline)
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

    if !Path::new(NFT).exists() {
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
    if nft_apply(&script) {
        return InterventionResult::ok(
            "kernel_quarantine_ip",
            clean_ip,
            &format!(
                "IP {} successfully quarantined in kernel nftables drop set",
                clean_ip
            ),
        );
    }

    if let Some(res) = escalate_via_helper(PRIVILEGED_NETWORK_FLAG, &["quarantine", clean_ip]) {
        return res;
    }
    if legacy_pkexec(&[NFT, "-f", "-"], Some(script.as_bytes())) {
        return InterventionResult::ok(
            "kernel_quarantine_ip",
            clean_ip,
            &format!(
                "IP {} quarantined in kernel nftables drop set via pkexec",
                clean_ip
            ),
        );
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

/// Ruleset for the emergency blackout: drops everything except loopback.
pub const BLACKOUT_SCRIPT: &str = "table inet sentinel_blackout {\n    chain output {\n        type filter hook output priority -100; policy drop;\n        oif \"lo\" accept\n        counter reject with icmpx type admin-prohibited\n    }\n    chain input {\n        type filter hook input priority -100; policy drop;\n        iif \"lo\" accept\n        counter drop\n    }\n}\n";

/// Enforces an immediate emergency military network blackout (Panic Mode / Killswitch).
/// Completely drops all inbound and outbound IP traffic on all interfaces except loopback ('lo').
///
/// The ruleset is piped to `nft -f -`, so no rule file is ever written to disk where
/// it could be swapped between being written and being read by a root `nft`.
pub fn kernel_apply_network_blackout() -> InterventionResult {
    if !Path::new(NFT).exists() {
        return InterventionResult::err(
            "network_blackout",
            "all_interfaces",
            "nft binary not found in /usr/bin/nft",
        );
    }

    let res = if nft_apply(BLACKOUT_SCRIPT) {
        InterventionResult::ok(
            "network_blackout",
            "all_interfaces",
            "Emergency military network blackout engaged: All non-loopback egress and ingress severed",
        )
    } else if let Some(res) = escalate_via_helper(PRIVILEGED_NETWORK_FLAG, &["blackout-apply"]) {
        res
    } else if legacy_pkexec(&[NFT, "-f", "-"], Some(BLACKOUT_SCRIPT.as_bytes())) {
        InterventionResult::ok(
            "network_blackout",
            "all_interfaces",
            "Emergency military network blackout engaged via privileged nftables killswitch",
        )
    } else {
        InterventionResult::err(
            "network_blackout",
            "all_interfaces",
            "Failed to enforce network blackout (insufficient privileges or nftables error)",
        )
    };

    if res.success {
        record_blackout_marker();
    }
    res
}

/// Clears the emergency network blackout, restoring normal networking.
pub fn kernel_clear_network_blackout() -> InterventionResult {
    let deadline = Instant::now() + Duration::from_secs(3);
    let args = ["delete", "table", "inet", "sentinel_blackout"];

    let res = if run_cmd_bounded(NFT, &args, &[], deadline, 4096).is_some() {
        InterventionResult::ok(
            "network_blackout",
            "all_interfaces",
            "Emergency network blackout cleared: Normal network connectivity restored",
        )
    } else if let Some(res) = escalate_via_helper(PRIVILEGED_NETWORK_FLAG, &["blackout-clear"]) {
        res
    } else if legacy_pkexec(&[NFT, "delete", "table", "inet", "sentinel_blackout"], None) {
        InterventionResult::ok(
            "network_blackout",
            "all_interfaces",
            "Emergency network blackout cleared via privileged nftables command",
        )
    } else {
        InterventionResult::err(
            "network_blackout",
            "all_interfaces",
            "Failed to delete blackout table (table may not exist or permission denied)",
        )
    };

    if res.success {
        clear_blackout_marker();
    }
    res
}

/// Checks if the emergency network blackout table is currently active in the kernel.
pub fn kernel_is_network_blackout_active() -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    let out = run_cmd_bounded(
        NFT,
        &["list", "table", "inet", "sentinel_blackout"],
        &[],
        deadline,
        4096,
    );
    // Root can query the ruleset directly; unprivileged callers fall back to the
    // per-boot marker written when the blackout was engaged.
    out.is_some() || blackout_marker_matches_boot()
}

// ---------------------------------------------------------------------------
// Private state (forensics, blackout marker)
// ---------------------------------------------------------------------------

/// Retrieves and verifies the private state directory shared with the rest of the
/// engine (`$XDG_STATE_HOME/omarchy/security-sentinel`), rejecting symlinks and
/// foreign ownership. Never used by the root-side helper.
fn get_private_state_dir() -> Result<PathBuf, String> {
    if in_privileged_mode() {
        return Err("State storage is disabled in privileged helper mode".to_string());
    }
    let base = match std::env::var("XDG_STATE_HOME") {
        Ok(state) if !state.is_empty() => PathBuf::from(state),
        _ => {
            let home = std::env::var("HOME")
                .map_err(|_| "HOME environment variable is not set".to_string())?;
            PathBuf::from(home).join(".local/state")
        }
    };
    let state_dir = base.join("omarchy/security-sentinel");

    if state_dir.exists() {
        let meta = std::fs::symlink_metadata(&state_dir)
            .map_err(|e| format!("Failed to read state dir metadata: {}", e))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "State directory {} is a symlink",
                state_dir.display()
            ));
        }
        // SAFETY: getuid has no preconditions
        if meta.uid() != unsafe { getuid() } {
            return Err(format!(
                "State directory {} is not owned by current user",
                state_dir.display()
            ));
        }
    } else {
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| format!("Failed to create private state directory: {}", e))?;
        let _ = std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700));
    }

    Ok(state_dir)
}

fn write_private_file(path: &Path, content: &[u8]) {
    let mut opts = OpenOptions::new();
    opts.write(true)
        .create(true)
        .truncate(true)
        .custom_flags(O_NOFOLLOW)
        .mode(0o600);
    if let Ok(mut file) = opts.open(path) {
        let _ = file.write_all(content);
    }
}

/// Captures cryptographic forensic evidence (executable hash, cmdline, comm)
/// of a frozen process to disk with 0600 file permissions in private state storage.
fn capture_forensic_evidence(pid: i32) {
    let Ok(base) = get_private_state_dir() else {
        return;
    };
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

    let state_dir = base.join("forensics");
    let _ = std::fs::create_dir_all(&state_dir);
    let _ = std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700));
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
    write_private_file(&evidence_file, json.as_bytes());
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
fn record_blackout_marker() {
    let (Ok(dir), Some(boot_id)) = (get_private_state_dir(), current_boot_id()) else {
        return;
    };
    write_private_file(&dir.join(BLACKOUT_MARKER), boot_id.as_bytes());
}

fn clear_blackout_marker() {
    if let Ok(dir) = get_private_state_dir() {
        let _ = std::fs::remove_file(dir.join(BLACKOUT_MARKER));
    }
}

fn blackout_marker_matches_boot() -> bool {
    let Ok(dir) = get_private_state_dir() else {
        return false;
    };
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

// ---------------------------------------------------------------------------
// Root-side helper entry point
// ---------------------------------------------------------------------------

/// Executes one operation requested through pkexec. Every argument is re-validated
/// by the same functions the unprivileged path uses (PID gates, immune list, bus-id
/// and IP parsing), so the helper never trusts its caller.
pub fn run_privileged_operation(flag: &str, op: &str, arg: Option<&str>) -> InterventionResult {
    let action = format!("{} {}", flag.trim_start_matches('-'), op);
    // SAFETY: getuid has no preconditions
    if unsafe { getuid() } != 0 {
        return InterventionResult::err(
            &action,
            arg.unwrap_or(""),
            "Privileged helper must be started via pkexec",
        );
    }
    enter_privileged_mode();

    let parse_pid = |a: Option<&str>| a.and_then(|s| s.trim().parse::<i32>().ok());
    match (flag, op) {
        (PRIVILEGED_INTERVENTION_FLAG, "stop") => match parse_pid(arg) {
            Some(pid) => kernel_freeze_process(pid),
            None => InterventionResult::err(&action, "", "Numeric PID required"),
        },
        (PRIVILEGED_INTERVENTION_FLAG, "terminate") => match parse_pid(arg) {
            Some(pid) => kernel_terminate_process(pid),
            None => InterventionResult::err(&action, "", "Numeric PID required"),
        },
        (PRIVILEGED_INTERVENTION_FLAG, "continue") => match parse_pid(arg) {
            Some(pid) => kernel_thaw_process(pid),
            None => InterventionResult::err(&action, "", "Numeric PID required"),
        },
        (PRIVILEGED_INTERVENTION_FLAG, "deauth-usb") => kernel_deauth_usb(arg.unwrap_or("")),
        (PRIVILEGED_INTERVENTION_FLAG, "sever-socket") => kernel_sever_socket(arg.unwrap_or("")),
        (PRIVILEGED_NETWORK_FLAG, "quarantine") => kernel_quarantine_ip(arg.unwrap_or("")),
        (PRIVILEGED_NETWORK_FLAG, "blackout-apply") => kernel_apply_network_blackout(),
        (PRIVILEGED_NETWORK_FLAG, "blackout-clear") => kernel_clear_network_blackout(),
        _ => InterventionResult::err(&action, arg.unwrap_or(""), "Unknown privileged operation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pidfd_refuses_to_signal_a_reaped_process() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let handle = ProcessHandle::open(child.id() as i32);
        assert!(handle.is_alive());
        let _ = child.kill();
        let _ = child.wait();
        // Once reaped the PID may be recycled; the pidfd must not follow it
        if handle.pidfd.is_some() {
            assert_eq!(handle.signal(0), Err(ESRCH));
        }
    }

    #[test]
    fn test_privileged_operation_requires_root() {
        // SAFETY: getuid has no preconditions
        if unsafe { getuid() } == 0 {
            return;
        }
        let res = run_privileged_operation(PRIVILEGED_NETWORK_FLAG, "blackout-apply", None);
        assert!(!res.success);
        assert!(res.message.contains("pkexec"));
        assert!(!in_privileged_mode());
    }

    #[test]
    fn test_privileged_operation_rejects_unknown_ops() {
        // SAFETY: getuid has no preconditions
        if unsafe { getuid() } != 0 {
            return;
        }
        let res = run_privileged_operation(PRIVILEGED_INTERVENTION_FLAG, "rm-rf", Some("/"));
        assert!(!res.success);
        let res = run_privileged_operation(PRIVILEGED_INTERVENTION_FLAG, "stop", Some("1"));
        assert!(!res.success && res.message.contains("PID <= 2"));
    }
}
