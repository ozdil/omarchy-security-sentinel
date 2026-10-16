//! Module 6: DNS Leak Guard.

use super::*;

pub(crate) fn check_dns_leak() -> (ModuleStatus, bool) {
    let deadline = Instant::now() + Duration::from_millis(1500);
    let current_provider =
        if let Some(out) = run_cmd_bounded("omarchy-dns", &[], &[], deadline, 4096) {
            String::from_utf8_lossy(&out).trim().to_string()
        } else {
            "DHCP".to_string()
        };

    let is_dot = current_provider == "Cloudflare" || current_provider == "Google";
    let status = if is_dot {
        Status::Secure
    } else {
        Status::Warning
    };

    let mut items = Vec::new();
    if is_dot {
        let resolver_ip = if current_provider == "Google" {
            "8.8.8.8"
        } else {
            "1.1.1.1"
        };
        items.push(format!(
            "Active Resolver: {} DNS ({} / 853)",
            current_provider, resolver_ip
        ));
        items.push("Protocol: DNS-over-TLS (DoT Encrypted Tunnel)".to_string());
        items.push("Privacy Status: Zero plaintext query leakage to ISP".to_string());
    } else {
        items.push("Active Resolver: Standard Gateway DHCP DNS".to_string());
        items.push("Protocol: Cleartext UDP (Port 53 Unencrypted)".to_string());
        items.push("Warning: DNS queries exposed to local network & ISP inspection".to_string());
    }

    let mod_status = ModuleStatus {
        id: "dns".to_string(),
        name: "DNS Leak Guard (DoT)".to_string(),
        status,
        summary: if is_dot {
            format!("DoT Active ({})", current_provider)
        } else {
            "Unencrypted ISP DNS (DHCP)".to_string()
        },
        detail: if is_dot {
            "Encrypted DNS-over-TLS tunnel active | Zero ISP plaintext leak".to_string()
        } else {
            "DNS queries sent in cleartext | Toggle switch to enable DoT".to_string()
        },
        is_toggleable: true,
        toggle_state: is_dot,
        items,
    };

    (mod_status, is_dot)
}

pub(crate) fn toggle_dns() -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_millis(1500);
    let current = run_cmd_bounded("omarchy-dns", &[], &[], deadline, 4096)
        .map(|o| String::from_utf8_lossy(&o).trim().to_string())
        .ok_or("omarchy-dns is not available")?;

    let enable = !(current == "Cloudflare" || current == "Google");
    let target = if enable { "Cloudflare" } else { "DHCP" };
    if !run_ok("omarchy-dns", &[target], Duration::from_secs(5)) {
        return Err(format!("omarchy-dns {} failed", target));
    }
    notify_desktop(
        "DNS Leak Guard",
        if enable {
            "DNS-over-TLS enabled (Cloudflare)."
        } else {
            "Switched to standard ISP DNS (DHCP) mode."
        },
        false,
    );
    Ok(enable)
}
