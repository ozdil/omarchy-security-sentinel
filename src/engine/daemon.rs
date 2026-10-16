//! `--daemon`: session-scoped monitor with USB uevents and the cached report.

use super::*;

pub(crate) const DAEMON_REPORT_INTERVAL: Duration = Duration::from_secs(20);
/// Hot-plug produces a burst of uevents (device, then each interface); wait for quiet
pub(crate) const DAEMON_USB_SETTLE: Duration = Duration::from_millis(750);
pub(crate) const DAEMON_ENUMERATION_RECHECK: Duration = Duration::from_secs(1);
pub(crate) const DAEMON_MAX_ENUMERATION_RECHECKS: u32 = 15;
pub(crate) const DAEMON_INTEGRITY_REFRESH: Duration = Duration::from_secs(300);
/// Without a uevent socket, poll the USB device list this often instead
pub(crate) const DAEMON_USB_POLL_FALLBACK: Duration = Duration::from_secs(2);

pub(crate) const LOCK_EX: i32 = 2;
pub(crate) const LOCK_NB: i32 = 4;
pub(crate) const PR_SET_PDEATHSIG: i32 = 1;
pub(crate) const SIGTERM: u64 = 15;

extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
    fn getppid() -> i32;
}

/// Long-running monitor started by the panel: reacts to USB hot-plug within a second
/// and keeps `report.json` fresh so the UI does not spawn a full scan every 20 s.
/// Runs inside the graphical session (not as a systemd service) so polkit's
/// `allow_active` still applies to the pkexec prompts armor de-authorization needs.
pub(crate) fn run_daemon() -> i32 {
    let Some(runtime_dir) = get_runtime_dir() else {
        eprintln!("sentinel daemon: XDG_RUNTIME_DIR is unavailable");
        return 1;
    };
    let lock_path = runtime_dir.join("daemon.lock");
    let lock_file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("sentinel daemon: cannot open lock: {}", e);
            return 1;
        }
    };
    // SAFETY: valid fd owned by lock_file, which lives until the function returns
    if unsafe { flock(lock_file.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
        // Another panel or dashboard already runs the daemon; its cache serves us too
        return 0;
    }
    // Exit with the panel that started us instead of lingering after a shell restart.
    // SAFETY: PR_SET_PDEATHSIG with a valid signal number has no memory effects
    unsafe { prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) };
    // SAFETY: getppid has no preconditions
    if unsafe { getppid() } == 1 {
        return 0; // parent already gone before PDEATHSIG was armed
    }

    let uevents = match sentinel_engine::uevent::UEventSocket::open() {
        Ok(sock) => Some(sock),
        Err(e) => {
            eprintln!(
                "sentinel daemon: uevent socket unavailable ({}), polling USB every {:?}",
                e, DAEMON_USB_POLL_FALLBACK
            );
            None
        }
    };

    let mut integrity_hash = String::new();
    let mut integrity_at: Option<Instant> = None;
    let mut next_report = Instant::now();
    let mut usb_check_at: Option<Instant> = None;
    let mut enumeration_rechecks = 0u32;
    let mut notified: HashSet<String> = HashSet::new();
    let mut usb_signature = usb_device_signature();

    loop {
        let now = Instant::now();
        let usb_due = usb_check_at.is_some_and(|t| t <= now);
        if usb_due || next_report <= now {
            if integrity_at.is_none_or(|t| now.duration_since(t) >= DAEMON_INTEGRITY_REFRESH) {
                integrity_hash = kernel::calculate_self_exe_sha256()
                    .unwrap_or_else(|_| "UNVERIFIED".to_string());
                integrity_at = Some(now);
            }
            let scan = scan_badusb();
            notify_new_untrusted_usb(&scan.untrusted, &mut notified);
            usb_check_at = if scan.pending_enumeration
                && enumeration_rechecks < DAEMON_MAX_ENUMERATION_RECHECKS
            {
                enumeration_rechecks += 1;
                Some(Instant::now() + DAEMON_ENUMERATION_RECHECK)
            } else {
                enumeration_rechecks = 0;
                None
            };
            let report = assemble_report(scan.module, integrity_hash.clone());
            write_report_cache(&report);
            next_report = Instant::now() + DAEMON_REPORT_INTERVAL;
            continue;
        }

        let deadline = usb_check_at.map_or(next_report, |t| t.min(next_report));
        let wait = deadline.saturating_duration_since(now);
        let usb_changed = match &uevents {
            Some(sock) => sock
                .wait(wait)
                .iter()
                .any(|ev| ev.is_usb_arrival() || ev.is_usb_removal()),
            None => {
                std::thread::sleep(wait.min(DAEMON_USB_POLL_FALLBACK));
                let sig = usb_device_signature();
                let changed = sig != usb_signature;
                usb_signature = sig;
                changed
            }
        };
        if usb_changed {
            usb_check_at = Some(Instant::now() + DAEMON_USB_SETTLE);
            enumeration_rechecks = 0;
        }
    }
}

/// Cheap change detector for the polling fallback: the sorted list of USB bus ids
pub(crate) fn usb_device_signature() -> Vec<String> {
    let mut ids: Vec<String> = fs::read_dir("/sys/bus/usb/devices")
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}

/// Raises one critical notification per untrusted device while it stays connected
pub(crate) fn notify_new_untrusted_usb(untrusted: &[String], notified: &mut HashSet<String>) {
    notified.retain(|id| untrusted.contains(id));
    let fresh: Vec<&String> = untrusted
        .iter()
        .filter(|id| !notified.contains(*id))
        .collect();
    if fresh.is_empty() {
        return;
    }
    let armor = is_usb_armor_enabled();
    let body = format!(
        "{} untrusted USB device(s) connected{}: {}",
        fresh.len(),
        if armor { " and de-authorized" } else { "" },
        fresh
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    notify_desktop("BadUSB Defense", &body, true);
    for id in fresh {
        notified.insert(id.clone());
    }
}
