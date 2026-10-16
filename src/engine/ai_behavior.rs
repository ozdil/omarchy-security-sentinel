//! AI behavioral process analysis module.

use super::*;

pub(crate) fn check_ai_behavior() -> (ModuleStatus, u32, Vec<ai::ProcessAnomaly>) {
    let anomalies = ai::analyze_all_processes();
    let max_score = anomalies.iter().map(|a| a.score).max().unwrap_or(0);

    let (status, summary, detail) = if max_score >= 80 {
        (
            Status::Alert,
            format!(
                "CRITICAL: {} suspicious behavioral anomalies detected (Highest Threat Score: {})",
                anomalies.len(),
                max_score
            ),
            "Immediate kernel intervention recommended (freeze process / sever active socket)."
                .to_string(),
        )
    } else if max_score >= 40 {
        (
            Status::Warning,
            format!("ELEVATED: {} behavioral process anomalies flagged (Score: {})", anomalies.len(), max_score),
            "Suspicious process behavior, commandline obfuscation, or untrusted filesystem execution detected.".to_string(),
        )
    } else {
        (
            Status::Secure,
            "Zero process anomalies or covert shell behaviors detected".to_string(),
            "Shannon entropy, memory injection, reverse shell heuristics, and execution paths verified normal.".to_string(),
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
