//! Module 2: BadUSB Defense (fingerprint baseline, USB Armor).

use super::*;

pub(crate) fn is_usb_armor_enabled() -> bool {
    get_state_dir().join("usb_armor.enabled").exists()
}

pub(crate) fn toggle_usb_armor() -> Result<bool, String> {
    let flag = get_state_dir().join("usb_armor.enabled");
    if flag.exists() {
        fs::remove_file(&flag).map_err(|e| format!("Cannot disable USB Armor: {}", e))?;
        Ok(false)
    } else {
        write_secure_state_file(&flag, b"1")
            .map_err(|e| format!("Cannot enable USB Armor: {}", e))?;
        Ok(true)
    }
}

/// Sanitizes USB hardware product strings to prevent HTML tag injection,
/// control character evasion, and excessive length in telemetry displays.
pub(crate) fn sanitize_usb_product(raw: &str) -> String {
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

pub(crate) fn load_trusted_usb(path: &Path) -> Option<TrustStore> {
    let bytes = read_secure_state_file(path, 256 * 1024).ok()?;
    TrustStore::parse(&bytes)
}

pub(crate) fn save_trusted_usb(path: &Path, store: &TrustStore) -> Result<(), String> {
    let data = store
        .to_json()
        .ok_or_else(|| "Cannot serialize the USB baseline".to_string())?;
    write_secure_state_file(path, &data)
}

/// (mtime ns, size) of the baseline, to notice "Trust Devices" rewriting it mid-scan
fn baseline_stamp(path: &Path) -> Option<(i128, u64)> {
    fs::symlink_metadata(path).ok().map(|m| {
        (
            m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
            m.len(),
        )
    })
}

/// Connected USB devices as (bus id, sysfs dir, fingerprint)
pub(crate) fn connected_usb_devices() -> Vec<(String, PathBuf, UsbFingerprint)> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(fp) = usb::read_fingerprint(&p) {
                out.push((entry.file_name().to_string_lossy().to_string(), p, fp));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Result of one BadUSB pass. The daemon uses the extra fields to re-check devices
/// that were still enumerating and to notify only about newly seen untrusted ones.
pub(crate) struct BadUsbScan {
    pub(crate) module: ModuleStatus,
    pub(crate) pending_enumeration: bool,
    /// Stable identity (bus id + fingerprint id) of every untrusted device
    pub(crate) untrusted: Vec<String>,
    /// The subset of `untrusted` that is de-authorized after this pass
    pub(crate) blocked: Vec<String>,
}

pub(crate) fn check_badusb() -> ModuleStatus {
    scan_badusb().module
}

pub(crate) fn scan_badusb() -> BadUsbScan {
    let mut hid_count = 0;
    let mut unapproved_bus_ids = Vec::new();
    let mut deauth_targets = Vec::new();
    let mut items = Vec::new();

    let trusted_file = get_state_dir().join("trusted_usb.json");
    let file_existed = trusted_file.exists();
    let loaded_stamp = baseline_stamp(&trusted_file);
    // An existing but unreadable/corrupt baseline must not be treated as "trust nothing":
    // with USB Armor on that would de-authorize every device, keyboard and mouse included.
    let loaded = if file_existed {
        load_trusted_usb(&trusted_file)
    } else {
        None
    };
    let baseline_corrupt = file_existed && loaded.is_none();
    let mut store = loaded.unwrap_or_default();
    let mut store_changed = false;
    let mut pending_enumeration = false;
    let mut untrusted = Vec::new();
    // Untrusted devices as (bus id, identity, high risk): high risk is anything that
    // can type (HID), a HID+storage composite, or a clone that changed its interfaces
    let mut untrusted_devices: Vec<(String, String, bool)> = Vec::new();

    let devices = connected_usb_devices();
    let total_usb = devices.len();

    // Legacy VID:PID-only entries are upgraded to full fingerprints from every
    // settled device at once, so identical units connected together all keep
    // their trust. Blocked or enumerating devices have no complete interface set
    // yet and are left for a later pass.
    if file_existed && !baseline_corrupt {
        let settled: Vec<&UsbFingerprint> = devices
            .iter()
            .filter(|(_, path, _)| !usb::is_enumerating(path))
            .map(|(_, _, fp)| fp)
            .collect();
        store_changed |= store.upgrade_legacy(&settled);
    }

    for (bus_id, path, fp) in &devices {
        if fp.is_hid() {
            hid_count += 1;
        }
        let already_blocked = read_file_bounded(&path.join("authorized"), 16)
            .map(|a| a.trim() == "0")
            .unwrap_or(false);
        // A half-enumerated device has an incomplete interface set: judging or
        // trusting it now would record (or compare) the wrong fingerprint and get the
        // finished device blocked on the next pass. Re-check once it settles.
        if !already_blocked && usb::is_enumerating(path) {
            let prod = sanitize_usb_product(fp.product.as_deref().unwrap_or("USB Device"));
            items.push(format!("{} [{}] [ENUMERATING, re-checking]", prod, fp.id()));
            pending_enumeration = true;
            continue;
        }

        // First run: the devices present now become the baseline (trust on first use)
        if !file_existed {
            store_changed |= store.trust(fp);
        }

        let verdict = baseline_verdict(baseline_corrupt, &store, fp);
        let is_trusted = matches!(verdict, None | Some(TrustVerdict::Trusted));

        let tag = match &verdict {
            None => "UNVERIFIED".to_string(),
            Some(TrustVerdict::Trusted) => "Approved".to_string(),
            Some(TrustVerdict::Unknown) => "UNAPPROVED".to_string(),
            Some(TrustVerdict::FingerprintMismatch { gained_hid: true }) => {
                "UNAPPROVED, CLONED ID WITH NEW KEYBOARD/HID INTERFACE".to_string()
            }
            Some(TrustVerdict::FingerprintMismatch { gained_hid: false }) => {
                "UNAPPROVED, FINGERPRINT MISMATCH".to_string()
            }
        };
        let tag = if !is_trusted && already_blocked {
            format!("{}, BLOCKED", tag)
        } else {
            tag
        };
        let kind_tag = if fp.is_hid_storage_composite() {
            " (HID + Storage)"
        } else if fp.is_hid() {
            " (HID)"
        } else {
            ""
        };
        let prod = sanitize_usb_product(fp.product.as_deref().unwrap_or("USB Device"));
        items.push(format!("{} [{}]{} [{}]", prod, fp.id(), kind_tag, tag));

        if !is_trusted {
            if is_deauth_target(bus_id, fp, already_blocked) {
                deauth_targets.push((bus_id.clone(), format!("{} {}", bus_id, fp.id())));
            }
            unapproved_bus_ids.push(bus_id.clone());
            let ident = format!("{} {} {}", bus_id, fp.id(), prod);
            let high_risk =
                fp.is_hid() || matches!(verdict, Some(TrustVerdict::FingerprintMismatch { .. }));
            untrusted_devices.push((bus_id.clone(), ident.clone(), high_risk));
            untrusted.push(ident);
        }
    }

    // The first baseline waits until no device is mid-enumeration; saving it early
    // would leave that device out and flag it as unapproved from then on.
    // A blocked device (or hub, hiding everything behind it) cannot be fingerprinted
    // either, so the first baseline also waits until nothing is de-authorized.
    let any_blocked = devices.iter().any(|(_, path, _)| is_deauthorized(path));
    let first_run_ready =
        !file_existed && !baseline_corrupt && !pending_enumeration && !any_blocked;
    let wants_save = (store_changed && file_existed) || first_run_ready;

    // Prune declined-prompt entries of unplugged devices on every pass, so a device
    // that comes back on the same port is judged (and blocked) afresh
    let connected: Vec<&str> = devices.iter().map(|(b, _, _)| b.as_str()).collect();
    load_deauth_declined(&connected, unix_now());

    let untrusted_count = unapproved_bus_ids.len();
    let armor_active = is_usb_armor_enabled();

    // The daemon, panel and dashboard scan independently, and "Trust Devices" holds
    // the same lock while it rewrites the baseline. Only the holder may save the
    // baseline or raise a block; the others skip both this pass, so one hot-plug
    // never opens several dialogs and a stale scan never overwrites new trust.
    let wants_block = armor_active && !deauth_targets.is_empty();
    let armor_lock = if wants_save || wants_block {
        armor_lock(false)
    } else {
        None
    };
    // The baseline must still be the one this scan loaded: "Trust Devices" may have
    // rewritten it after we read it and released the lock before we got it
    if wants_save && armor_lock.is_some() && baseline_stamp(&trusted_file) == loaded_stamp {
        if let Err(e) = save_trusted_usb(&trusted_file, &store) {
            items.push(format!("[WARNING] Cannot save USB baseline: {}", e));
        }
    }

    let mut block_failed = 0;
    if wants_block && armor_lock.is_some() {
        // A cancelled or failed block is retried after DEAUTH_RETRY_SECS, not
        // remembered until replug: a keystroke injector must not be able to dismiss
        // the prompt once and stay authorized for good.
        // Another scan may have recorded a failure while we waited
        let now = unix_now();
        let mut declined = load_deauth_declined(&connected, now);
        let mut declined_changed = false;
        for (b_id, key) in &deauth_targets {
            if declined.iter().any(|(k, _)| k == key) {
                continue;
            }
            // Another scan may have blocked it while we waited for the lock
            let auth = Path::new("/sys/bus/usb/devices")
                .join(b_id)
                .join("authorized");
            if read_file_bounded(&auth, 16).is_ok_and(|a| a.trim() == "0") {
                continue;
            }
            if !kernel::kernel_deauth_usb(b_id).success {
                declined.push((key.clone(), now));
                declined_changed = true;
            }
        }
        if declined_changed {
            save_deauth_declined(&declined);
        }
    }

    // Report what the kernel says now, not what was attempted
    let blocked: Vec<String> = untrusted_devices
        .iter()
        .filter(|(b, _, _)| is_deauthorized(&Path::new("/sys/bus/usb/devices").join(b)))
        .map(|(_, ident, _)| ident.clone())
        .collect();
    let unblocked_high_risk = untrusted_devices
        .iter()
        .filter(|(_, ident, high)| *high && !blocked.contains(ident))
        .count();
    if armor_active {
        let blockable: Vec<&str> = deauth_targets.iter().map(|(b, _)| b.as_str()).collect();
        block_failed = untrusted_devices
            .iter()
            .filter(|(b, ident, _)| blockable.contains(&b.as_str()) && !blocked.contains(ident))
            .count();
    }
    if !blocked.is_empty() {
        items.push(format!(
            "USB Armor: {} untrusted device(s) de-authorized",
            blocked.len()
        ));
    }
    if block_failed > 0 {
        items.push(format!(
            "[ALERT] USB Armor could not block {} device(s) (authorization cancelled, failed or another scan holds the lock); retrying in {} s",
            block_failed, DEAUTH_RETRY_SECS
        ));
    }

    let legacy_left = store.devices.iter().filter(|d| d.is_legacy()).count();
    if legacy_left > 0 && !baseline_corrupt {
        items.push(format!(
            "Baseline: {} legacy VID:PID-only entries will be upgraded to full fingerprints when those devices are next connected",
            legacy_left
        ));
    }

    if baseline_corrupt {
        items.push(format!(
            "[WARNING] Trusted baseline {} is unreadable or corrupt; auto-blocking suspended. Use 'Trust Devices' to rebuild it.",
            trusted_file.display()
        ));
        let module = ModuleStatus {
            id: "badusb".to_string(),
            name: "BadUSB Defense".to_string(),
            status: Status::Warning,
            summary: format!("{} Devices (Baseline Unreadable)", total_usb),
            detail: "Trusted USB baseline could not be verified; devices are listed but not auto-blocked.".to_string(),
            is_toggleable: true,
            toggle_state: armor_active,
            items,
        };
        return BadUsbScan {
            module,
            pending_enumeration,
            untrusted,
            blocked,
        };
    }

    // A device that can type and is not blocked, or a block that failed, is an
    // active threat. Other untrusted devices (an audio DAC, a blocked keyboard) only
    // need the user's decision.
    let status = if unblocked_high_risk > 0 || block_failed > 0 {
        Status::Alert
    } else if untrusted_count > 0 {
        Status::Warning
    } else {
        Status::Secure
    };
    let module = ModuleStatus {
        id: "badusb".to_string(),
        name: "BadUSB Defense".to_string(),
        status,
        summary: if untrusted_count > 0 {
            if blocked.is_empty() {
                format!("{} untrusted device(s)", untrusted_count)
            } else {
                format!("{} untrusted, {} blocked", untrusted_count, blocked.len())
            }
        } else {
            format!("{} devices, {} HID, all trusted", total_usb, hid_count)
        },
        detail: if untrusted_count > 0 {
            if block_failed > 0 {
                "USB Armor could not block every untrusted device. Unplug it if it is not yours."
                    .to_string()
            } else if armor_active {
                "USB Armor blocked the untrusted devices. Trust them if they are yours.".to_string()
            } else {
                "Untrusted USB device attached. Trust it if it is yours, or turn on USB Armor to block it.".to_string()
            }
        } else {
            "All attached devices match their approved fingerprint (ID, serial, interface classes)"
                .to_string()
        },
        is_toggleable: true,
        toggle_state: armor_active,
        items,
    };
    BadUsbScan {
        module,
        pending_enumeration,
        untrusted,
        blocked,
    }
}

/// Exclusive lock held for an armor pass, or while "Trust Devices" restores and
/// approves devices; released when dropped. Scans never wait for it, they skip
/// blocking for that pass instead.
fn armor_lock(wait: bool) -> Option<fs::File> {
    let dir = get_runtime_dir().unwrap_or_else(get_state_dir);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(dir.join("usb_armor.lock"))
        .ok()?;
    let op = if wait { LOCK_EX } else { LOCK_EX | LOCK_NB };
    // SAFETY: valid fd owned by `file`, which the caller keeps alive while locked
    (unsafe { flock(file.as_raw_fd(), op) } == 0).then_some(file)
}

fn deauth_declined_path() -> PathBuf {
    get_runtime_dir()
        .unwrap_or_else(get_state_dir)
        .join("usb_deauth_declined")
}

/// How long a failed or cancelled block is held back before Armor tries again
const DEAUTH_RETRY_SECS: u64 = 60;

/// Devices whose de-authorization failed recently, as (key, unix time), pruned to the
/// ones still connected and still inside the retry window
fn load_deauth_declined(connected: &[&str], now: u64) -> Vec<(String, u64)> {
    let path = deauth_declined_path();
    let raw = read_secure_state_file(&path, 64 * 1024).unwrap_or_default();
    let text = String::from_utf8_lossy(&raw);
    let all: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    let kept = parse_declined(&all, connected, now);
    if kept.len() != all.len() {
        save_deauth_declined(&kept);
    }
    kept
}

fn parse_declined(lines: &[&str], connected: &[&str], now: u64) -> Vec<(String, u64)> {
    lines
        .iter()
        .filter_map(|l| {
            // Lines without a timestamp come from older versions: drop them
            let (key, ts) = l.rsplit_once('\t')?;
            let ts: u64 = ts.parse().ok()?;
            let bus = key.split(' ').next()?;
            (connected.contains(&bus) && now.saturating_sub(ts) < DEAUTH_RETRY_SECS)
                .then(|| (key.to_string(), ts))
        })
        .collect()
}

fn save_deauth_declined(keys: &[(String, u64)]) {
    let text: Vec<String> = keys.iter().map(|(k, t)| format!("{}\t{}", k, t)).collect();
    let _ = write_secure_state_file(&deauth_declined_path(), text.join("\n").as_bytes());
}

fn is_deauthorized(path: &Path) -> bool {
    read_file_bounded(&path.join("authorized"), 16).is_ok_and(|a| a.trim() == "0")
}

/// The baseline's verdict on a device, or `None` when the baseline is corrupt. An
/// unreadable baseline must not mean "trust nothing": with USB Armor on that would
/// de-authorize every device, keyboard and mouse included.
fn baseline_verdict(
    baseline_corrupt: bool,
    store: &TrustStore,
    fp: &UsbFingerprint,
) -> Option<TrustVerdict> {
    if baseline_corrupt {
        None
    } else {
        Some(store.verdict(fp))
    }
}

/// Whether USB Armor may de-authorize an untrusted device. Hubs (root hubs
/// included) are never auto-severed: that would also cut off every trusted keyboard
/// and mouse behind them, and each device on the hub is judged on its own anyway.
/// Devices already de-authorized are skipped so each poll does not re-trigger sysfs
/// writes or pkexec prompts.
fn is_deauth_target(bus_id: &str, fp: &UsbFingerprint, already_blocked: bool) -> bool {
    !already_blocked && !bus_id.starts_with("usb") && !fp.is_hub()
}

/// One connected device as "Trust Devices" sees it.
struct ObservedDevice<'a> {
    fp: &'a UsbFingerprint,
    blocked: bool,
    enumerating: bool,
}

/// Adds the connected devices to `store` and returns how many entries were added or
/// updated. Existing entries are kept, so approved devices that are unplugged right
/// now are not silently dropped.
fn merge_into_baseline(store: &mut TrustStore, devices: &[ObservedDevice]) -> usize {
    let settled: Vec<&UsbFingerprint> = devices
        .iter()
        .filter(|d| !d.enumerating)
        .map(|d| d.fp)
        .collect();
    let mut added = usize::from(store.upgrade_legacy(&settled));
    for d in devices {
        // A device still blocked (re-authorization cancelled) is trusted with its
        // interfaces unknown; the entry is completed the next time it is seen
        // authorized. Only skip devices still enumerating.
        if !d.blocked && d.enumerating {
            continue;
        }
        if store.trust(d.fp) {
            added += 1;
        }
    }
    added
}

pub(crate) fn trust_all_usb() -> Result<usize, String> {
    // Hold off Armor until the restored devices are approved: a scan in between
    // would see them re-enabled but not yet trusted and block them again.
    let _armor_guard = armor_lock(true);
    // Give back every device Armor blocked first. A blocked device has no active
    // configuration (its interfaces are unknown), and a blocked hub hides every
    // device behind it, so trusting before re-authorizing would record an
    // incomplete baseline that Armor then enforces against the user's own
    // keyboard and mouse.
    let blocked_ids: Vec<String> = connected_usb_devices()
        .into_iter()
        .filter(|(_, path, _)| is_deauthorized(path))
        .map(|(bus_id, _, _)| bus_id)
        .collect();
    let restored = blocked_ids
        .iter()
        .filter(|b| kernel::kernel_reauth_usb(b).success)
        .count();
    let failed = blocked_ids.len() - restored;
    if restored > 0 {
        // Wait for re-authorized devices (and those behind re-enabled hubs) to
        // finish enumerating, so their full fingerprints are what gets trusted.
        let deadline = Instant::now() + Duration::from_secs(5);
        std::thread::sleep(Duration::from_millis(500));
        while Instant::now() < deadline
            && connected_usb_devices()
                .iter()
                .any(|(_, path, _)| !is_deauthorized(path) && usb::is_enumerating(path))
        {
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    let devices = connected_usb_devices();
    let trusted_file = get_state_dir().join("trusted_usb.json");
    // Merge with the existing baseline so devices that are approved but currently
    // unplugged are not silently dropped. A corrupt baseline is rebuilt from scratch.
    let mut store = load_trusted_usb(&trusted_file).unwrap_or_default();
    let observed: Vec<ObservedDevice> = devices
        .iter()
        .map(|(_, path, fp)| ObservedDevice {
            fp,
            blocked: is_deauthorized(path),
            enumerating: usb::is_enumerating(path),
        })
        .collect();
    let added = merge_into_baseline(&mut store, &observed);
    if let Err(e) = save_trusted_usb(&trusted_file, &store) {
        notify_desktop(
            "BadUSB Defense",
            &format!("Could not save the trusted USB baseline: {}", e),
            true,
        );
        return Err(e);
    }
    // Trusted devices are no longer Armor targets; forget declined prompts
    save_deauth_declined(&[]);
    notify_desktop(
        "BadUSB Defense",
        &format!(
            "Trusted {} connected USB devices ({} new or updated fingerprints){}.",
            devices.len(),
            added,
            if failed > 0 {
                format!("; {} blocked device(s) need a replug to work again", failed)
            } else if restored > 0 {
                format!("; {} blocked device(s) re-enabled", restored)
            } else {
                String::new()
            }
        ),
        false,
    );
    Ok(devices.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_declined_block_is_retried_after_window() {
        let lines = [
            "1-2 1234:5678 Ducky\t1000",
            "1-3 aaaa:bbbb Gone\t1000",
            "1-4 cccc:dddd Legacy line without timestamp",
        ];
        let connected = ["1-2", "1-4"];
        let kept = parse_declined(&lines, &connected, 1000 + DEAUTH_RETRY_SECS - 1);
        assert_eq!(kept, vec![("1-2 1234:5678 Ducky".to_string(), 1000)]);
        // A cancelled prompt does not exempt the device for good
        assert!(parse_declined(&lines, &connected, 1000 + DEAUTH_RETRY_SECS).is_empty());
    }

    fn fp(vid: &str, pid: &str, ifs: &[&str]) -> UsbFingerprint {
        UsbFingerprint {
            vid: vid.to_string(),
            pid: pid.to_string(),
            serial: None,
            interfaces: Some(ifs.iter().map(|s| s.to_string()).collect()),
            product: None,
        }
    }

    const KEYBOARD: &[&str] = &["03:01:01"];
    const HUB: &[&str] = &["09:00:00"];

    #[test]
    fn test_corrupt_baseline_produces_no_deauth_targets() {
        let store = TrustStore::default();
        let keyboard = fp("046d", "c31c", KEYBOARD);
        let verdict = baseline_verdict(true, &store, &keyboard);
        assert_eq!(verdict, None);
        // The scan treats a missing verdict as trusted, so nothing is blocked
        assert!(matches!(verdict, None | Some(TrustVerdict::Trusted)));
        // With a readable but empty baseline the same device is unknown
        assert_eq!(
            baseline_verdict(false, &store, &keyboard),
            Some(TrustVerdict::Unknown)
        );
    }

    #[test]
    fn test_hubs_and_blocked_devices_are_never_deauth_targets() {
        let keyboard = fp("046d", "c31c", KEYBOARD);
        let hub = fp("05e3", "0610", HUB);
        assert!(is_deauth_target("1-2", &keyboard, false));
        assert!(!is_deauth_target("1-2", &keyboard, true), "already blocked");
        assert!(!is_deauth_target("1-1", &hub, false), "external hub");
        assert!(
            !is_deauth_target("usb1", &keyboard, false),
            "root hub bus id"
        );
        assert!(!is_deauth_target("usb2", &hub, false), "root hub");
    }

    #[test]
    fn test_trusting_keeps_unplugged_devices() {
        let unplugged = fp("0781", "5567", &["08:06:50"]);
        let keyboard = fp("046d", "c31c", KEYBOARD);
        let mut store = TrustStore::default();
        store.trust(&unplugged);

        let added = merge_into_baseline(
            &mut store,
            &[ObservedDevice {
                fp: &keyboard,
                blocked: false,
                enumerating: false,
            }],
        );
        assert_eq!(added, 1);
        assert_eq!(store.verdict(&unplugged), TrustVerdict::Trusted);
        assert_eq!(store.verdict(&keyboard), TrustVerdict::Trusted);
    }

    #[test]
    fn test_trusting_skips_enumerating_but_not_blocked_devices() {
        let enumerating = fp("1234", "0001", KEYBOARD);
        let blocked = fp("1234", "0002", KEYBOARD);
        let mut store = TrustStore::default();
        merge_into_baseline(
            &mut store,
            &[
                ObservedDevice {
                    fp: &enumerating,
                    blocked: false,
                    enumerating: true,
                },
                ObservedDevice {
                    fp: &blocked,
                    blocked: true,
                    enumerating: true,
                },
            ],
        );
        assert_eq!(store.verdict(&enumerating), TrustVerdict::Unknown);
        assert_eq!(store.verdict(&blocked), TrustVerdict::Trusted);
    }
}
