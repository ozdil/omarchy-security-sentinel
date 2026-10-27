//! AI behavioral process analysis module.

use super::*;

/// Flagged processes carried in the report (most suspicious first)
const MAX_REPORTED_ANOMALIES: usize = 16;

pub(crate) fn check_ai_behavior() -> (ModuleStatus, u32, Vec<ai::ProcessAnomaly>) {
    let anomalies = ai::analyze_all_processes();
    let max_score = anomalies.iter().map(|a| a.score).max().unwrap_or(0);

    let (status, summary, detail) = if max_score >= 80 {
        (
            Status::Alert,
            format!(
                "{} suspicious processes (top score {})",
                anomalies.len(),
                max_score
            ),
            "Review the processes below; freeze one if it is not yours.".to_string(),
        )
    } else if max_score >= 40 {
        (
            Status::Warning,
            format!(
                "{} processes worth a look (top score {})",
                anomalies.len(),
                max_score
            ),
            "Unusual command lines or binaries running from untrusted paths.".to_string(),
        )
    } else {
        (
            Status::Secure,
            "No suspicious processes".to_string(),
            "Command lines, execution paths and reverse-shell patterns look normal.".to_string(),
        )
    };

    let items = anomalies
        .iter()
        .take(8)
        .map(|a| {
            format!(
                "[PID {} - {}] Score {}: {}",
                a.pid,
                a.name,
                a.score,
                a.reasons.join(", ")
            )
        })
        .collect();

    // The panel and dashboard parse the whole report; an unbounded list of flagged
    // processes would let one noisy (or hostile) host push it past their limit
    let mut anomalies = anomalies;
    anomalies.truncate(MAX_REPORTED_ANOMALIES);

    (
        ModuleStatus {
            id: "ai_behavior".to_string(),
            name: "AI Behavioral Threat Shield".to_string(),
            status,
            summary,
            detail,
            is_toggleable: false,
            toggle_state: true,
            items,
        },
        max_score,
        anomalies,
    )
}
