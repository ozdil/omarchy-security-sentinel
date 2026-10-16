//! Report data model shared by every module, the CLI and the UI JSON.

use super::*;

/// Per-module verdict. Serialized exactly as the strings the UI already matches on.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum Status {
    /// Idle tool module (e.g. OpSec Cleaner): nothing to evaluate
    Ready,
    Secure,
    Warning,
    Alert,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Status::Ready => "READY",
            Status::Secure => "SECURE",
            Status::Warning => "WARNING",
            Status::Alert => "ALERT",
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum ThreatLevel {
    Zero,
    Elevated,
    Critical,
}

impl ThreatLevel {
    /// The worst module verdict decides the overall level
    pub fn from_modules(modules: &[ModuleStatus]) -> Self {
        match modules.iter().map(|m| m.status).max() {
            Some(Status::Alert) => ThreatLevel::Critical,
            Some(Status::Warning) => ThreatLevel::Elevated,
            _ => ThreatLevel::Zero,
        }
    }

    pub fn overall_status(self) -> &'static str {
        match self {
            ThreatLevel::Critical => "THREAT DETECTED",
            ThreatLevel::Elevated => "ATTENTION REQUIRED",
            ThreatLevel::Zero => "ALL SYSTEMS SECURE",
        }
    }

    pub fn color(self) -> &'static str {
        match self {
            ThreatLevel::Critical => "#ef4444",
            ThreatLevel::Elevated => "#f59e0b",
            ThreatLevel::Zero => "#22c55e",
        }
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            ThreatLevel::Zero => "ZERO",
            ThreatLevel::Elevated => "ELEVATED",
            ThreatLevel::Critical => "CRITICAL",
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct ModuleStatus {
    pub id: String,
    pub name: String,
    pub status: Status,
    pub summary: String,
    pub detail: String,
    pub is_toggleable: bool,
    pub toggle_state: bool,
    pub items: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SentinelReport {
    pub overall_status: String,
    pub threat_level: ThreatLevel,
    pub threat_color: String,
    pub active_modules: usize,
    pub ghost_mac_enabled: bool,
    pub dns_dot_enabled: bool,
    pub usb_armor_enabled: bool,
    pub network_blackout_active: bool,
    /// False when `network_blackout_active` comes from our own marker rather than the
    /// kernel ruleset (unprivileged runs), so the UI must not present it as fact
    pub network_blackout_confirmed: bool,
    pub self_integrity_hash: String,
    pub ai_threat_score: u32,
    pub ai_anomalies: Vec<ai::ProcessAnomaly>,
    pub kernel_capabilities: Vec<String>,
    pub modules: Vec<ModuleStatus>,
    pub timestamp: String,
    /// Unix time the report was built; lets the UI tell a fresh daemon cache from a stale one
    #[serde(default)]
    pub generated_at: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BarStatus {
    pub text: String,
    pub tooltip: String,
    pub class: String,
    pub color: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_wire_format_and_threat_level() {
        // The panel and dashboard match on these exact strings
        assert_eq!(
            serde_json::to_string(&Status::Secure).unwrap(),
            "\"SECURE\""
        );
        assert_eq!(serde_json::to_string(&Status::Ready).unwrap(), "\"READY\"");
        assert_eq!(
            serde_json::to_string(&ThreatLevel::Elevated).unwrap(),
            "\"ELEVATED\""
        );
        assert_eq!(format!("{:<8}|", Status::Alert), "ALERT   |");

        let module = |status| ModuleStatus {
            id: String::new(),
            name: String::new(),
            status,
            summary: String::new(),
            detail: String::new(),
            is_toggleable: false,
            toggle_state: false,
            items: Vec::new(),
        };
        let mods = vec![module(Status::Ready), module(Status::Secure)];
        assert_eq!(ThreatLevel::from_modules(&mods), ThreatLevel::Zero);
        let mods = vec![module(Status::Warning), module(Status::Secure)];
        assert_eq!(ThreatLevel::from_modules(&mods), ThreatLevel::Elevated);
        let mods = vec![module(Status::Warning), module(Status::Alert)];
        assert_eq!(ThreatLevel::from_modules(&mods), ThreatLevel::Critical);
        assert_eq!(ThreatLevel::Critical.overall_status(), "THREAT DETECTED");
    }
}
