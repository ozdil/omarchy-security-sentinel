//! Module 3: CVE Vulnerability Radar (arch-audit + checkupdates).

use super::*;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CveCache {
    timestamp: u64,
    pkg_count: usize,
    pending_pkgs: Vec<String>,
    #[serde(default)]
    check_failed: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ArchAuditCache {
    timestamp: u64,
    installed: bool,
    failed: bool,
    advisories: Vec<Advisory>,
}

pub(crate) enum AuditOutcome {
    NotInstalled,
    Failed,
    Done(Vec<Advisory>),
}

pub(crate) const ARCH_AUDIT_BIN: &str = "/usr/bin/arch-audit";

/// Queries the Arch Security Tracker through `arch-audit`. Advisories change slowly
/// and the lookup hits the network, so results are cached for hours.
pub(crate) fn arch_audit_advisories() -> AuditOutcome {
    const TTL_SECS: u64 = 6 * 3600;
    const FAILED_TTL_SECS: u64 = 600;
    let cache_file = get_state_dir().join("arch_audit_cache.json");
    let now = unix_now();
    let installed = Path::new(ARCH_AUDIT_BIN).exists();

    if let Some(cache) = read_secure_state_file(&cache_file, 512 * 1024)
        .ok()
        .and_then(|b| serde_json::from_slice::<ArchAuditCache>(&b).ok())
    {
        let ttl = if cache.failed {
            FAILED_TTL_SECS
        } else {
            TTL_SECS
        };
        // An install or removal of arch-audit invalidates the cache immediately
        if cache.installed == installed && now.saturating_sub(cache.timestamp) < ttl {
            return match (cache.installed, cache.failed) {
                (false, _) => AuditOutcome::NotInstalled,
                (true, true) => AuditOutcome::Failed,
                (true, false) => AuditOutcome::Done(cache.advisories),
            };
        }
    }

    let (outcome, failed, advisories) = if !installed {
        (AuditOutcome::NotInstalled, false, Vec::new())
    } else {
        let deadline = Instant::now() + Duration::from_secs(15);
        match run_cmd_bounded_status(
            ARCH_AUDIT_BIN,
            &["--format", cve::ARCH_AUDIT_FORMAT],
            &[],
            deadline,
            256 * 1024,
        ) {
            Some((0, stdout)) => {
                let adv = cve::parse_arch_audit(&String::from_utf8_lossy(&stdout));
                (AuditOutcome::Done(adv.clone()), false, adv)
            }
            _ => (AuditOutcome::Failed, true, Vec::new()),
        }
    };
    let cache = ArchAuditCache {
        timestamp: now,
        installed,
        failed,
        advisories,
    };
    if let Ok(bytes) = serde_json::to_vec(&cache) {
        let _ = write_secure_state_file(&cache_file, &bytes);
    }
    outcome
}

pub(crate) fn advisory_item(a: &Advisory) -> String {
    let cves = match a.cves.len() {
        0 => String::new(),
        1..=3 => format!(" {}", a.cves.join(", ")),
        n => format!(" {} (+{} more)", a.cves[..3].join(", "), n - 3),
    };
    let fix = match &a.fixed {
        Some(v) => format!("fixed in {}", v),
        None => "no fix released yet".to_string(),
    };
    format!(
        "[{}] {}: {}{} ({})",
        a.severity.label(),
        a.package,
        a.kind,
        cves,
        fix
    )
}

pub(crate) fn check_cve() -> ModuleStatus {
    let pkg_count = fs::read_dir("/var/lib/pacman/local")
        .map(|entries| entries.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0);

    let cache_file = get_state_dir().join("cve_cache.json");
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    const CACHE_TTL_SECS: u64 = 900; // 15 minutes TTL
    const FAILED_CACHE_TTL_SECS: u64 = 120; // retry failed checks sooner

    let mut pending_pkgs = Vec::new();
    let mut cache_hit = false;
    let mut check_failed = false;

    if let Ok(bytes) = read_secure_state_file(&cache_file, 65536) {
        if let Ok(cache) = serde_json::from_slice::<CveCache>(&bytes) {
            let ttl = if cache.check_failed {
                FAILED_CACHE_TTL_SECS
            } else {
                CACHE_TTL_SECS
            };
            if now_secs.saturating_sub(cache.timestamp) < ttl {
                pending_pkgs = cache.pending_pkgs;
                check_failed = cache.check_failed;
                cache_hit = true;
            }
        }
    }

    // checkupdates (pacman-contrib) exits 0 with a list, 2 when there is nothing to
    // update, and 1 (or fails to spawn / times out) on error. Errors must not be
    // reported as "up to date"; they are cached briefly so a slow mirror does not
    // stall every 20 s poll.
    if !cache_hit {
        let deadline = Instant::now() + Duration::from_millis(8000);
        match run_cmd_bounded_status("/usr/bin/checkupdates", &[], &[], deadline, 65536) {
            Some((0, stdout)) => {
                let text = String::from_utf8_lossy(&stdout);
                for l in text.lines().filter(|l| !l.trim().is_empty()) {
                    pending_pkgs.push(l.trim().to_string());
                }
            }
            Some((2, _)) => {}
            _ => check_failed = true,
        }
        let cache = CveCache {
            timestamp: now_secs,
            pkg_count,
            pending_pkgs: pending_pkgs.clone(),
            check_failed,
        };
        if let Ok(json_bytes) = serde_json::to_vec(&cache) {
            let _ = write_secure_state_file(&cache_file, &json_bytes);
        }
    }

    let pending_count = pending_pkgs.len();
    let audit = arch_audit_advisories();

    let mut items = Vec::new();
    items.push(format!(
        "Audited Packages: {} local packages in /var/lib/pacman/local",
        pkg_count
    ));

    // Security Tracker findings first: they are what the module is named after
    let mut fixable_critical = 0;
    let mut fixable_high = 0;
    let mut advisory_count = 0;
    let mut cve_count = 0;
    match &audit {
        AuditOutcome::Done(advisories) => {
            advisory_count = advisories.len();
            cve_count = advisories.iter().map(|a| a.cves.len()).sum();
            for a in advisories.iter().filter(|a| a.fix_available()) {
                match a.severity {
                    Severity::Critical => fixable_critical += 1,
                    Severity::High => fixable_high += 1,
                    _ => {}
                }
            }
            if advisories.is_empty() {
                items.push("Arch Security Tracker: no known vulnerable packages installed".to_string());
            } else {
                items.push(format!(
                    "Arch Security Tracker: {} vulnerable packages, {} CVEs ({} fixable now)",
                    advisory_count,
                    cve_count,
                    advisories.iter().filter(|a| a.fix_available()).count()
                ));
                items.extend(advisories.iter().take(8).map(advisory_item));
            }
        }
        AuditOutcome::Failed => items.push(
            "[WARNING] arch-audit failed (security.archlinux.org unreachable?); CVE data unavailable"
                .to_string(),
        ),
        AuditOutcome::NotInstalled => items.push(
            "Install arch-audit (pacman -S arch-audit) to match packages against the Arch Security Tracker"
                .to_string(),
        ),
    }

    if check_failed {
        items.push("[WARNING] checkupdates failed or is not installed (pacman-contrib); update status unknown".to_string());
    } else if pending_count == 0 {
        items.push("Pending Updates: none reported by checkupdates".to_string());
    } else {
        items.push(format!(
            "Updates Available: {} packages pending update",
            pending_count
        ));
        for p in pending_pkgs.iter().take(5) {
            items.push(format!("Update -> {}", p));
        }
    }

    // A fixable critical advisory means a known hole that one `pacman -Syu` closes
    let status = if fixable_critical > 0 {
        Status::Alert
    } else if fixable_high > 0 || check_failed || pending_count > 10 {
        Status::Warning
    } else {
        Status::Secure
    };
    let summary = match &audit {
        AuditOutcome::Done(_) if advisory_count > 0 => format!(
            "{} Packages ({} Vulnerable, {} CVEs)",
            pkg_count, advisory_count, cve_count
        ),
        _ if check_failed => format!("{} Packages (Update Check Unavailable)", pkg_count),
        _ if pending_count > 0 => {
            format!("{} Packages ({} Updates Pending)", pkg_count, pending_count)
        }
        AuditOutcome::Done(_) => format!("{} Packages (No Known CVEs)", pkg_count),
        _ => format!("{} Packages (All Up to Date)", pkg_count),
    };
    let detail = if fixable_critical + fixable_high > 0 {
        format!(
            "{} critical / {} high severity vulnerabilities have fixes available: run a system update",
            fixable_critical, fixable_high
        )
    } else if check_failed {
        "Could not query pending updates; install pacman-contrib or check network".to_string()
    } else if pending_count > 0 {
        format!(
            "{} system updates pending package manager sync",
            pending_count
        )
    } else {
        "checkupdates verified | No pending package updates".to_string()
    };
    ModuleStatus {
        id: "cve".to_string(),
        name: "CVE Vulnerability Radar".to_string(),
        status,
        summary,
        detail,
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}
