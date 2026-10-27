use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;

const MAX_CMDLINE_READ_BYTES: u64 = 65536; // 64 KiB ceiling
/// Command line kept in the report; the analysis itself sees up to 64 KiB
const MAX_REPORTED_CMDLINE_CHARS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAnomaly {
    pub pid: i32,
    pub name: String,
    pub cmdline: String,
    pub score: u32,
    pub severity: AnomalySeverity,
    pub reasons: Vec<String>,
    pub recommended_action: String,
    /// Kernel start time (clock ticks since boot), so an action taken from an older
    /// report cannot hit a different process that reused the PID
    #[serde(default)]
    pub start_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketAnomaly {
    pub pid: Option<i32>,
    pub process_name: String,
    pub protocol: String,
    pub local_address: String,
    pub port: u16,
    pub score: u32,
    pub severity: AnomalySeverity,
    pub reasons: Vec<String>,
}

pub struct BehaviorAnalyzer;

impl BehaviorAnalyzer {
    /// Computes Shannon entropy of string slice
    pub fn calculate_entropy(input: &str) -> f64 {
        if input.is_empty() {
            return 0.0;
        }

        let mut counts = HashMap::new();
        let mut total = 0usize;

        for ch in input.chars() {
            *counts.entry(ch).or_insert(0usize) += 1;
            total += 1;
        }

        let total_f = total as f64;
        let mut entropy = 0.0f64;

        for &count in counts.values() {
            let p = count as f64 / total_f;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Evaluates a process commandline and environment to calculate threat score
    pub fn evaluate_process(
        pid: i32,
        name: &str,
        exe_path: Option<&str>,
        cmdline: &str,
    ) -> Option<ProcessAnomaly> {
        let mut score = 0u32;
        let mut reasons = Vec::new();

        let lower_cmd = cmdline.to_lowercase();
        let lower_exe = exe_path.map(|s| s.to_lowercase()).unwrap_or_default();

        // 1. Check if executing from volatile / memory-only / suspicious directories
        let is_suspicious_location = lower_exe.starts_with("/tmp")
            || lower_exe.starts_with("/dev/shm")
            || lower_exe.starts_with("/var/tmp");

        let has_suspicious_script_arg = (lower_cmd.contains("/tmp/")
            || lower_cmd.contains("/dev/shm/"))
            && (lower_cmd.ends_with(".sh")
                || lower_cmd.ends_with(".py")
                || lower_cmd.ends_with(".elf")
                || lower_cmd.ends_with(".bin")
                || lower_cmd.contains("sh ")
                || lower_cmd.contains("bash ")
                || lower_cmd.contains("chmod +x"));

        if is_suspicious_location {
            score += 45;
            reasons.push("Process binary executed directly from temporary or memory filesystem (/tmp or /dev/shm)".to_string());
        } else if has_suspicious_script_arg {
            score += 30;
            reasons.push(
                "Process argument executes script or binary from temporary directory".to_string(),
            );
        }

        // 2. Check for deleted executable in memory (process ghosting vs system upgrade)
        if lower_exe.contains("(deleted)") {
            let is_system_binary = lower_exe.starts_with("/usr/") || lower_exe.starts_with("/opt/");
            if is_system_binary {
                score += 15;
                reasons.push("Running executable has been unlinked on disk (pending restart after system package update)".to_string());
            } else {
                score += 55;
                reasons.push("Severe: Non-system running executable unlinked from disk (stealth process ghosting)".to_string());
            }
        }

        // 3. Reverse shell heuristics
        let is_reverse_shell = (lower_cmd.contains("/dev/tcp/") && (lower_cmd.contains("sh") || lower_cmd.contains("bash")))
            || (lower_cmd.contains("nc ") && (lower_cmd.contains(" -e ") || lower_cmd.contains(" -c ")))
            || (lower_cmd.contains("ncat ") && (lower_cmd.contains(" -e ") || lower_cmd.contains(" -c ")))
            || (lower_cmd.contains("socat ") && lower_cmd.contains("exec:"))
            || (lower_cmd.contains("bash -i") && lower_cmd.contains("&> /dev/"))
            || (lower_cmd.contains("sh -i") && lower_cmd.contains(">&"))
            || (lower_cmd.contains("python") && lower_cmd.contains("socket.connect"))
            // Needles must be lowercase: they are matched against the lowercased cmdline
            || (lower_cmd.contains("perl") && lower_cmd.contains("socket;") && lower_cmd.contains("connect("))
            || (lower_cmd.contains("ruby") && lower_cmd.contains("tcpsocket.open"));

        if is_reverse_shell {
            score += 65;
            reasons.push(
                "Signature match: Interactive reverse-shell execution pattern detected".to_string(),
            );
        }

        // 4. Remote code execution pipe into shell
        if (lower_cmd.contains("curl ") || lower_cmd.contains("wget "))
            && (lower_cmd.contains("| sh")
                || lower_cmd.contains("| bash")
                || lower_cmd.contains("| sudo"))
        {
            score += 45;
            reasons.push(
                "Direct unauthenticated remote code pipe into shell (curl/wget | sh/bash)"
                    .to_string(),
            );
        }

        // 5. Obfuscation & Base64 decoding piped to interpreter
        if (lower_cmd.contains("base64 -d")
            || lower_cmd.contains("base64 --decode")
            || lower_cmd.contains("openssl enc -d"))
            && (lower_cmd.contains("| sh")
                || lower_cmd.contains("| bash")
                || lower_cmd.contains("| python"))
        {
            score += 50;
            reasons.push("Obfuscated payload decoding directly into shell/interpreter".to_string());
        }

        // 6. Memory dumping & credential harvesting indicators
        if lower_cmd.contains("/proc/kcore")
            || lower_cmd.contains("/dev/mem")
            || lower_cmd.contains("/dev/kmem")
            || (lower_cmd.contains("/etc/shadow")
                && !lower_cmd.contains("passwd")
                && !lower_cmd.contains("useradd"))
        {
            score += 40;
            reasons.push(
                "Suspicious low-level memory or shadow credential access pattern".to_string(),
            );
        }

        // 7. Hidden cryptocurrency mining signatures
        if lower_cmd.contains("stratum+tcp://")
            || lower_cmd.contains("stratum+ssl://")
            || lower_cmd.contains("xmrig")
            || lower_cmd.contains("minergate")
        {
            score += 60;
            reasons.push("Mining protocol signature: Stratum mining daemon detected".to_string());
        }

        // 8. Shannon entropy check on arguments
        if cmdline.len() > 60 {
            let entropy = Self::calculate_entropy(cmdline);
            if entropy > 5.2 {
                score += 25;
                reasons.push(format!("High information entropy ({:.2} bits) indicates encrypted or obfuscated command arguments", entropy));
            }
        }

        if score == 0 {
            return None;
        }

        let clamped_score = score.min(100);
        let (severity, recommended_action) = match clamped_score {
            80..=100 => (
                AnomalySeverity::Critical,
                "IMMEDIATE KERNEL FREEZE OR TERMINATION".to_string(),
            ),
            50..=79 => (
                AnomalySeverity::High,
                "KERNEL FREEZE & SEVER ACTIVE SOCKETS".to_string(),
            ),
            25..=49 => (
                AnomalySeverity::Medium,
                "AUDIT PROCESS TREE & NETWORK MONITORING".to_string(),
            ),
            _ => (AnomalySeverity::Low, "MONITOR".to_string()),
        };

        Some(ProcessAnomaly {
            pid,
            name: name.to_string(),
            cmdline: truncate_chars(cmdline, MAX_REPORTED_CMDLINE_CHARS),
            score: clamped_score,
            severity,
            reasons,
            recommended_action,
            start_time: 0,
        })
    }

    /// Evaluates listening or open network sockets
    pub fn evaluate_socket(
        pid: Option<i32>,
        process_name: &str,
        protocol: &str,
        local_address: &str,
        port: u16,
    ) -> Option<SocketAnomaly> {
        let mut score = 0u32;
        let mut reasons = Vec::new();

        // 1. High-risk backdoor ports
        // Same list as the network radar, so a socket is never "critical" in one view
        // and unremarkable in the other (8888/9999 are everyday Jupyter/dev ports)
        if crate::net::is_suspicious_port(port) {
            score += 45;
            reasons.push(format!(
                "Listening on well-known exploit or reverse backdoor port {}",
                port
            ));
        }

        // 2. Sensitive ports exposed to 0.0.0.0 or wildcard
        // Exact match: a prefix test would treat ::1 (loopback) as the :: wildcard
        let is_wildcard = crate::net::is_wildcard_address(local_address);
        if is_wildcard {
            if port == 22 && process_name != "sshd" && !process_name.is_empty() {
                score += 50;
                reasons.push(format!(
                    "Non-sshd binary '{}' listening on standard SSH port 22",
                    process_name
                ));
            } else if (port == 80 || port == 443)
                && !["nginx", "caddy", "apache2", "httpd", "lighttpd"].contains(&process_name)
                && !process_name.is_empty()
            {
                score += 30;
                reasons.push(format!(
                    "Non-standard web server '{}' bound to public web port {}",
                    process_name, port
                ));
            } else if port == 23 || port == 21 {
                score += 40;
                reasons.push(format!(
                    "Insecure plaintext service listening on port {}",
                    port
                ));
            }
        }

        // 3. Process name check for listener
        if ["nc", "netcat", "ncat", "socat"].contains(&process_name) {
            score += 55;
            reasons.push(format!(
                "Raw socket utility '{}' listening for incoming connections",
                process_name
            ));
        }

        if score == 0 {
            return None;
        }

        let clamped_score = score.min(100);
        let severity = match clamped_score {
            75..=100 => AnomalySeverity::Critical,
            45..=74 => AnomalySeverity::High,
            20..=44 => AnomalySeverity::Medium,
            _ => AnomalySeverity::Low,
        };

        Some(SocketAnomaly {
            pid,
            process_name: process_name.to_string(),
            protocol: protocol.to_string(),
            local_address: local_address.to_string(),
            port,
            score: clamped_score,
            severity,
            reasons,
        })
    }
}

/// Scans all processes under /proc adhering strictly to bounded reading
pub fn analyze_all_processes() -> Vec<ProcessAnomaly> {
    let mut anomalies = Vec::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(_) => return anomalies,
    };

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<i32>() {
            if pid <= 1 {
                continue;
            }

            let pid_path = entry.path();

            // Read /proc/[pid]/cmdline bounded
            let cmdline_path = pid_path.join("cmdline");
            let mut cmdline = String::new();
            let mut oversized = false;
            if let Ok(mut f) = File::open(&cmdline_path) {
                let mut buf = Vec::new();
                let _ = f
                    .by_ref()
                    .take(MAX_CMDLINE_READ_BYTES + 1)
                    .read_to_end(&mut buf);
                // Padding argv past the limit must not hide the command: analyze the
                // first 64 KiB and score the oversize itself
                oversized = buf.len() > MAX_CMDLINE_READ_BYTES as usize;
                buf.truncate(MAX_CMDLINE_READ_BYTES as usize);
                {
                    // Split null bytes into spaces
                    cmdline = buf
                        .split(|&b| b == 0)
                        .filter(|part| !part.is_empty())
                        .map(|part| String::from_utf8_lossy(part).to_string())
                        .collect::<Vec<_>>()
                        .join(" ");
                }
            }

            // Read process comm / name
            let comm_path = pid_path.join("comm");
            let mut proc_name = String::new();
            if let Ok(mut f) = File::open(&comm_path) {
                let mut buf = String::new();
                let _ = f.by_ref().take(256).read_to_string(&mut buf);
                proc_name = buf.trim().to_string();
            }

            // Read exe link
            let exe_path_buf = fs::read_link(pid_path.join("exe")).ok();
            let exe_str = exe_path_buf.as_ref().and_then(|p| p.to_str());

            let mut found = BehaviorAnalyzer::evaluate_process(pid, &proc_name, exe_str, &cmdline);
            if oversized {
                let a = found.get_or_insert_with(|| ProcessAnomaly {
                    pid,
                    name: proc_name.clone(),
                    cmdline: truncate_chars(&cmdline, MAX_REPORTED_CMDLINE_CHARS),
                    score: 0,
                    severity: AnomalySeverity::Low,
                    reasons: Vec::new(),
                    recommended_action: "AUDIT PROCESS TREE & NETWORK MONITORING".to_string(),
                    start_time: 0,
                });
                a.score = (a.score + 40).min(100);
                a.severity = a.severity.max(AnomalySeverity::Medium);
                a.reasons.push(
                    "Command line over 64 KiB: argv padding is a known way to hide a command"
                        .to_string(),
                );
            }
            if let Some(mut anomaly) = found {
                anomaly.start_time = crate::kernel::process_start_time(pid).unwrap_or(0);
                anomalies.push(anomaly);
            }
        }
    }

    anomalies.sort_by_key(|a| std::cmp::Reverse(a.score));
    anomalies
}

/// Analyzes socket anomalies from ss or /proc/net
pub fn analyze_socket_anomalies(
    open_sockets: &[(&str, &str, u16, Option<i32>, &str)],
) -> Vec<SocketAnomaly> {
    let mut results = Vec::new();
    for (proto, local_addr, port, pid, proc_name) in open_sockets {
        if let Some(anomaly) =
            BehaviorAnalyzer::evaluate_socket(*pid, proc_name, proto, local_addr, *port)
        {
            results.push(anomaly);
        }
    }
    results.sort_by_key(|a| std::cmp::Reverse(a.score));
    results
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}
