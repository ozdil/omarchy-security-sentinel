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

    let kernel_capabilities = vec![
        "cgroups_v2_freeze".to_string(),
        "posix_kernel_sigstop".to_string(),
        "sock_diag_tcp_reset".to_string(),
        "sysfs_usb_deauthorization".to_string(),
        "nftables_ip_quarantine".to_string(),
        "nftables_panic_blackout".to_string(),
        "prctl_anti_dumpable".to_string(),
        "forensic_hash_capture".to_string(),
    ];

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
        timestamp: "Live Defense".to_string(),
        generated_at: unix_now(),
    }
}
