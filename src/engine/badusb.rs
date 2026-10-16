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

pub(crate) fn save_trusted_usb(path: &Path, store: &TrustStore) {
    if let Some(data) = store.to_json() {
        let _ = write_secure_state_file(path, &data);
    }
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

        let verdict = if baseline_corrupt {
            None
        } else {
            Some(store.verdict(fp))
        };
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
            // Hubs (root hubs included) are never auto-severed: that would also cut
            // off every trusted keyboard and mouse behind them, and each device on
            // the hub is judged on its own anyway. Devices already de-authorized are
            // skipped so each poll does not re-trigger sysfs writes or pkexec prompts.
            if !already_blocked && !bus_id.starts_with("usb") && !fp.is_hub() {
                deauth_targets.push((bus_id.clone(), format!("{} {}", bus_id, fp.id())));
            }
            unapproved_bus_ids.push(bus_id.clone());
            untrusted.push(format!("{} {} {}", bus_id, fp.id(), prod));
        }
    }

    // The first baseline waits until no device is mid-enumeration; saving it early
    // would leave that device out and flag it as unapproved from then on.
    // A blocked device (or hub, hiding everything behind it) cannot be fingerprinted
    // either, so the first baseline also waits until nothing is de-authorized.
    let any_blocked = devices.iter().any(|(_, path, _)| is_deauthorized(path));
    let first_run_ready =
        !file_existed && !baseline_corrupt && !pending_enumeration && !any_blocked;
    if (store_changed && file_existed) || first_run_ready {
        save_trusted_usb(&trusted_file, &store);
    }

    let untrusted_count = unapproved_bus_ids.len();
    let armor_active = is_usb_armor_enabled();

    // The daemon, panel and dashboard scan independently. Only the one holding the
    // armor lock may raise a polkit prompt; the others skip blocking this pass, so
    // one hot-plug never opens several password dialogs at once.
    let armor_lock = if armor_active && !deauth_targets.is_empty() {
        try_armor_lock()
    } else {
        None
    };
    if armor_active && untrusted_count > 0 && armor_lock.is_some() {
        // A cancelled or failed polkit prompt is remembered per device (bus id +
        // VID:PID) until it is unplugged; otherwise every scan from the daemon,
        // panel and dashboard would raise the password dialog again.
        let connected: Vec<&str> = devices.iter().map(|(b, _, _)| b.as_str()).collect();
        let mut declined = load_deauth_declined(&connected);
        let mut declined_changed = false;
        let mut blocked_now = 0;
        for (b_id, key) in &deauth_targets {
            if declined.contains(key) {
                continue;
            }
            // Another scan may have blocked it while we waited for the lock
            let auth = Path::new("/sys/bus/usb/devices")
                .join(b_id)
                .join("authorized");
            if read_file_bounded(&auth, 16).is_ok_and(|a| a.trim() == "0") {
                continue;
            }
            if kernel::kernel_deauth_usb(b_id).success {
                blocked_now += 1;
            } else {
                declined.push(key.clone());
                declined_changed = true;
            }
        }
        if declined_changed {
            save_deauth_declined(&declined);
        }
        if blocked_now > 0 {
            items.push("USB Armor: untrusted devices were de-authorized".to_string());
        }
        if !declined.is_empty() {
            items.push(
                "[WARNING] USB Armor could not block a device (authorization cancelled or failed); it will not ask again until the device is replugged"
                    .to_string(),
            );
        }
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
        };
    }

    let status = if untrusted_count > 0 {
        Status::Alert
    } else {
        Status::Secure
    };
    let module = ModuleStatus {
        id: "badusb".to_string(),
        name: "BadUSB Defense".to_string(),
        status,
        summary: if untrusted_count > 0 {
            if armor_active {
                format!("{} untrusted, blocked", untrusted_count)
            } else {
                format!("{} untrusted device(s)", untrusted_count)
            }
        } else {
            format!("{} devices, {} HID, all trusted", total_usb, hid_count)
        },
        detail: if untrusted_count > 0 {
            if armor_active {
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
    }
}

/// Non-blocking exclusive lock held for the armor pass; released when dropped
fn try_armor_lock() -> Option<fs::File> {
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
    // SAFETY: valid fd owned by `file`, which the caller keeps alive while locked
    (unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } == 0).then_some(file)
}

fn deauth_declined_path() -> PathBuf {
    get_runtime_dir()
        .unwrap_or_else(get_state_dir)
        .join("usb_deauth_declined")
}

/// Devices whose de-authorization was declined, pruned to the ones still connected
fn load_deauth_declined(connected: &[&str]) -> Vec<String> {
    let path = deauth_declined_path();
    let raw = read_secure_state_file(&path, 64 * 1024).unwrap_or_default();
    let all: Vec<String> = String::from_utf8_lossy(&raw)
        .lines()
        .map(str::to_string)
        .collect();
    let kept: Vec<String> = all
        .iter()
        .filter(|k| {
            k.split(' ')
                .next()
                .is_some_and(|bus| connected.contains(&bus))
        })
        .cloned()
        .collect();
    if kept.len() != all.len() {
        save_deauth_declined(&kept);
    }
    kept
}

fn save_deauth_declined(keys: &[String]) {
    let _ = write_secure_state_file(&deauth_declined_path(), keys.join("\n").as_bytes());
}

fn is_deauthorized(path: &Path) -> bool {
    read_file_bounded(&path.join("authorized"), 16).is_ok_and(|a| a.trim() == "0")
}

pub(crate) fn trust_all_usb() -> usize {
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
    let settled: Vec<&UsbFingerprint> = devices
        .iter()
        .filter(|(_, path, _)| !usb::is_enumerating(path))
        .map(|(_, _, fp)| fp)
        .collect();
    let mut added = usize::from(store.upgrade_legacy(&settled));
    for (_, path, fp) in &devices {
        // A device still blocked (re-authorization cancelled) is trusted with its
        // interfaces unknown; the entry is completed the next time it is seen
        // authorized. Only skip devices still enumerating.
        if !is_deauthorized(path) && usb::is_enumerating(path) {
            continue;
        }
        if store.trust(fp) {
            added += 1;
        }
    }
    save_trusted_usb(&trusted_file, &store);
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
    devices.len()
}
