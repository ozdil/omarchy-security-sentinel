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

    for (bus_id, path, fp) in &devices {
        if fp.is_hid() {
            hid_count += 1;
        }
        // First run: the devices present now become the baseline (trust on first use).
        // Legacy VID:PID-only entries are upgraded to full fingerprints when seen.
        if !file_existed {
            store_changed |= store.trust(fp);
        } else if !baseline_corrupt {
            store_changed |= store.upgrade_legacy(fp);
        }

        let verdict = if baseline_corrupt {
            None
        } else {
            Some(store.verdict(fp))
        };
        let is_trusted = matches!(verdict, None | Some(TrustVerdict::Trusted));
        let already_blocked = read_file_bounded(&path.join("authorized"), 16)
            .map(|a| a.trim() == "0")
            .unwrap_or(false);
        if !already_blocked && usb::is_enumerating(path) {
            let prod = sanitize_usb_product(fp.product.as_deref().unwrap_or("USB Device"));
            items.push(format!("{} [{}] [ENUMERATING, re-checking]", prod, fp.id()));
            pending_enumeration = true;
            continue;
        }

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
            // Root hubs (usbN) are never auto-severed: that would drop every port on
            // the bus. Devices already de-authorized are skipped so each 20 s poll
            // does not re-trigger sysfs writes or pkexec prompts.
            if !already_blocked && !bus_id.starts_with("usb") {
                deauth_targets.push(bus_id.clone());
            }
            unapproved_bus_ids.push(bus_id.clone());
            untrusted.push(format!("{} {} {}", bus_id, fp.id(), prod));
        }
    }

    if store_changed || (!file_existed && !baseline_corrupt) {
        save_trusted_usb(&trusted_file, &store);
    }

    let untrusted_count = unapproved_bus_ids.len();
    let armor_active = is_usb_armor_enabled();

    if armor_active && untrusted_count > 0 {
        for b_id in &deauth_targets {
            let _ = kernel::kernel_deauth_usb(b_id);
        }
        items.push("USB Armor: untrusted devices were de-authorized".to_string());
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

pub(crate) fn trust_all_usb() -> usize {
    let devices = connected_usb_devices();
    let trusted_file = get_state_dir().join("trusted_usb.json");
    // Merge with the existing baseline so devices that are approved but currently
    // unplugged are not silently dropped. A corrupt baseline is rebuilt from scratch.
    let mut store = load_trusted_usb(&trusted_file).unwrap_or_default();
    let mut added = 0;
    for (_, _, fp) in &devices {
        if store.trust(fp) {
            added += 1;
        }
    }
    save_trusted_usb(&trusted_file, &store);
    notify_desktop(
        "BadUSB Defense",
        &format!(
            "Trusted {} connected USB devices ({} new or updated fingerprints).",
            devices.len(),
            added
        ),
        false,
    );
    devices.len()
}
