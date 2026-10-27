//! Builds the full `SentinelReport` from all modules.

use super::*;

pub(crate) fn build_report() -> SentinelReport {
    // BadUSB runs first so an armored de-authorization is not delayed by the slower modules
    let badusb_mod = check_badusb();
    let self_integrity_hash =
        kernel::calculate_self_exe_sha256().unwrap_or_else(|_| "UNVERIFIED".to_string());
    assemble_report(badusb_mod, self_integrity_hash)
}

pub(crate) fn assemble_report(
    badusb_mod: ModuleStatus,
    self_integrity_hash: String,
) -> SentinelReport {
    let (ai_mod, ai_threat_score, ai_anomalies) = check_ai_behavior();
    let (dns_mod, dns_dot_enabled) = check_dns_leak();
    let (ghost_mac_mod, ghost_mac_enabled) = check_ghost_mac();

    let modules = vec![
        ai_mod,
        check_network_sockets(),
        badusb_mod,
        check_cve(),
        check_auth_watch(),
        check_tripwire(),
        dns_mod,
        ghost_mac_mod,
        check_opsec_cleaner(),
    ];

    let threat_level = ThreatLevel::from_modules(&modules);

    let usb_armor_enabled = is_usb_armor_enabled();
    let blackout = kernel::kernel_network_blackout_state();

    let kernel_capabilities = probe_kernel_capabilities();

    SentinelReport {
        overall_status: threat_level.overall_status().to_string(),
        threat_level,
        threat_color: threat_level.color().to_string(),
        active_modules: modules.len(),
        ghost_mac_enabled,
        dns_dot_enabled,
        usb_armor_enabled,
        network_blackout_active: blackout.active,
        network_blackout_confirmed: blackout.confirmed,
        self_integrity_hash,
        ai_threat_score,
        ai_anomalies,
        kernel_capabilities,
        modules,
        timestamp: utc_timestamp(unix_now()),
        generated_at: unix_now(),
    }
}

/// What this host can actually do, instead of a fixed list of claims
fn probe_kernel_capabilities() -> Vec<String> {
    let exists = |p: &str| Path::new(p).exists();
    let mut caps = vec![
        // Signals go through pidfd_send_signal (Linux 5.3+), with kill(2) as fallback
        "pidfd_sigstop".to_string(),
        "forensic_hash_capture".to_string(),
    ];
    if kernel::enforce_anti_tamper() {
        caps.push("prctl_anti_dumpable".to_string());
    }
    if exists("/usr/bin/ss") {
        caps.push("sock_diag_tcp_reset".to_string());
    }
    if exists("/sys/bus/usb/devices") {
        caps.push("sysfs_usb_deauthorization".to_string());
    }
    if exists("/usr/bin/nft") {
        caps.push("nftables_ip_quarantine".to_string());
        caps.push("nftables_panic_blackout".to_string());
    }
    if kernel::privileged_helper_available() {
        caps.push("polkit_privileged_helper".to_string());
    }
    caps
}

/// RFC 3339 UTC time for a Unix timestamp (civil-from-days, no time zone database)
fn utc_timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utc_timestamp() {
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_timestamp(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_timestamp(1_793_093_400), "2026-10-27T09:30:00Z");
    }
}
