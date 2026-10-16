//! Module 4: Authentication Watch.

use super::*;

pub(crate) fn check_auth_watch() -> ModuleStatus {
    let mut failed_count = 0;
    let mut fail_entries = Vec::new();

    let journal_bin = if Path::new("/usr/bin/journalctl").exists() {
        "/usr/bin/journalctl"
    } else {
        "/bin/journalctl"
    };

    // Bounded execution: producer-side limit (-n 200), buffer cap 64 KiB. The version
    // probe and the query get separate deadlines: a filtered query may scan the whole
    // day's journal, and a slow probe must not eat into its budget.
    // Filtering in journald (--grep) makes -n 200 mean "the last 200 auth failures in
    // 24h" instead of "the last 200 log lines", which on a busy system covered minutes.
    // Builds without PCRE2 reject --grep, so fall back to the unfiltered tail there.
    const AUTH_PATTERN: &str = "authentication failure|failed password|incorrect password attempt";
    let base_args = ["-n", "200", "--since", "24 hours ago", "-q", "-o", "cat"];
    let probe_deadline = Instant::now() + Duration::from_millis(1000);
    let has_pcre2 = run_cmd_bounded(journal_bin, &["--version"], &[], probe_deadline, 4096)
        .map(|v| String::from_utf8_lossy(&v).contains("+PCRE2"))
        .unwrap_or(false);
    let deadline = Instant::now() + Duration::from_millis(4000);
    let journal_out = if has_pcre2 {
        let mut grep_args = base_args.to_vec();
        grep_args.extend_from_slice(&["--case-sensitive=false", "--grep", AUTH_PATTERN]);
        match run_cmd_bounded_status(journal_bin, &grep_args, &[], deadline, 65536) {
            // journalctl exits 1 with empty output when --grep matches nothing
            Some((0, out)) => Some(out),
            Some((1, out)) if out.is_empty() => Some(out),
            _ => None,
        }
    } else {
        run_cmd_bounded(journal_bin, &base_args, &[], deadline, 65536)
    };
    let journal_read = journal_out.is_some();
    if let Some(stdout) = journal_out {
        let text = String::from_utf8_lossy(&stdout);
        for line in text.lines() {
            let lower = line.to_lowercase();
            if lower.contains("authentication failure")
                || lower.contains("failed password")
                || lower.contains("incorrect password attempt")
            {
                failed_count += 1;
                if fail_entries.len() < 4 {
                    fail_entries.push(line.trim().to_string());
                }
            }
        }
    }

    let mut items = Vec::new();
    items
        .push("Log Target: systemd-journald & Linux PAM (24h scope, last 200 matches)".to_string());

    // A query that failed or timed out has not shown the logs are clean
    if !journal_read {
        items.push(
            "Journal query failed or timed out; authentication logs were not checked".to_string(),
        );
        return ModuleStatus {
            id: "auth".to_string(),
            name: "Authentication Watch".to_string(),
            status: Status::Warning,
            summary: "Auth logs unavailable".to_string(),
            detail:
                "The systemd journal could not be read in time, so failed logins were not checked"
                    .to_string(),
            is_toggleable: false,
            toggle_state: false,
            items,
        };
    }

    items.push(format!(
        "Failed Authentication Events: {} recorded",
        failed_count
    ));
    if failed_count == 0 {
        items.push("Integrity: No brute-force or unauthorized auth/ssh attempts".to_string());
    } else {
        for fe in fail_entries {
            items.push(format!("Alert -> {}", fe));
        }
    }

    let status = if failed_count > 0 {
        Status::Warning
    } else {
        Status::Secure
    };
    ModuleStatus {
        id: "auth".to_string(),
        name: "Authentication Watch".to_string(),
        status,
        summary: if failed_count > 0 {
            format!("[ALERT] {} Failed Logins (24h)", failed_count)
        } else {
            "0 Failed Logins (24h)".to_string()
        },
        detail: if failed_count > 0 {
            format!(
                "PAM & systemd journal recorded {} failed auth attempts!",
                failed_count
            )
        } else {
            "Journald & PAM authentication logs verified clean".to_string()
        },
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}
