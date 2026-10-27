//! Arch Security Tracker advisories via `arch-audit`.
//!
//! `arch-audit` matches installed package versions against security.archlinux.org
//! and prints one line per affected package. The engine asks for a fixed,
//! tab-separated format so the parser never depends on the human-readable text.

use serde::{Deserialize, Serialize};

/// `--format` placeholders: name, severity, type, fixed version, CVE list
pub const ARCH_AUDIT_FORMAT: &str = "%n\t%s\t%t\t%v\t%c";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// arch-audit prints "High risk", "Medium risk" etc.; only the first word counts
    fn parse(s: &str) -> Self {
        let word = s.split_whitespace().next().unwrap_or("");
        match word.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    pub package: String,
    pub severity: Severity,
    pub kind: String,
    /// Version that fixes it, when the repositories already ship one
    pub fixed: Option<String>,
    pub cves: Vec<String>,
}

impl Advisory {
    pub fn fix_available(&self) -> bool {
        self.fixed.is_some()
    }
}

/// Keeps only characters that can appear in the given kind of identifier; the
/// tracker feed is remote input that ends up in the UI.
fn clean(s: &str, allowed: impl Fn(char) -> bool, max: usize) -> String {
    s.trim().chars().filter(|&c| allowed(c)).take(max).collect()
}

fn is_cve_id(s: &str) -> bool {
    let mut parts = s.splitn(3, '-');
    parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|y| y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|n| n.len() >= 4 && n.len() <= 12 && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Parses `arch-audit --format ARCH_AUDIT_FORMAT` output, most severe first
pub fn parse_arch_audit(output: &str) -> Vec<Advisory> {
    let mut out: Vec<Advisory> = output
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 5 {
                return None;
            }
            let package = clean(
                f[0],
                |c| c.is_ascii_alphanumeric() || "@._+-".contains(c),
                64,
            );
            if package.is_empty() {
                return None;
            }
            let fixed = clean(
                f[3],
                |c| c.is_ascii_alphanumeric() || ".:_+-~".contains(c),
                64,
            );
            let mut cves: Vec<String> = f[4]
                .split([',', ' '])
                .map(str::trim)
                .filter(|c| is_cve_id(c))
                .map(str::to_string)
                .collect();
            cves.sort();
            cves.dedup();
            Some(Advisory {
                package,
                severity: Severity::parse(f[1]),
                kind: clean(f[2], |c| c.is_ascii_alphanumeric() || c == ' ', 48),
                fixed: (!fixed.is_empty() && fixed != "-").then_some(fixed),
                cves,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.fix_available().cmp(&a.fix_available()))
            .then(a.package.cmp(&b.package))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_arch_audit() {
        let out = "openssl\tHigh\tarbitrary code execution\t3.3.2-1\tCVE-2024-1111,CVE-2024-2222\n\
                   libxml2\tMedium\tdenial of service\t\tCVE-2023-9999\n\
                   glibc\tCritical\tprivilege escalation\t2.40-2\tCVE-2025-0001\n\
                   broken line without tabs\n\
                   evil<script>\tLow\tx\t-\tCVE-2024-1234 javascript:alert(1)\n";
        let adv = parse_arch_audit(out);
        assert_eq!(adv.len(), 4);
        assert_eq!(adv[0].package, "glibc");
        assert_eq!(adv[0].severity, Severity::Critical);
        assert_eq!(adv[0].fixed.as_deref(), Some("2.40-2"));
        assert_eq!(adv[1].package, "openssl");
        assert_eq!(adv[1].cves, vec!["CVE-2024-1111", "CVE-2024-2222"]);
        assert_eq!(adv[2].package, "libxml2");
        assert!(!adv[2].fix_available());
        assert_eq!(adv[3].package, "evilscript");
        assert!(adv[3].fixed.is_none());
        assert_eq!(adv[3].cves, vec!["CVE-2024-1234"]);
    }

    #[test]
    fn test_parse_real_arch_audit_output() {
        // Captured from arch-audit 0.2.0 with ARCH_AUDIT_FORMAT
        let out = "libxml2\tHigh risk\tdenial of service\t2.14.6-1\tCVE-2025-6021\n\
                   apr\tMedium risk\tinformation disclosure\t\tCVE-2023-49582\n\
                   pam\tCritical risk\tprivilege escalation\t1.7.1-1\tCVE-2025-6020\n\
                   zlib\tLow risk\tdenial of service\t-\tCVE-2023-45853\n";
        let adv = parse_arch_audit(out);
        let sev: Vec<Severity> = adv.iter().map(|a| a.severity).collect();
        assert_eq!(
            sev,
            vec![
                Severity::Critical,
                Severity::High,
                Severity::Medium,
                Severity::Low
            ]
        );
        assert_eq!(adv[0].package, "pam");
    }

    #[test]
    fn test_cve_id_validation() {
        assert!(is_cve_id("CVE-2024-12345"));
        assert!(!is_cve_id("CVE-24-1234"));
        assert!(!is_cve_id("CVE-2024-12"));
        assert!(!is_cve_id("AVG-1234"));
    }
}
