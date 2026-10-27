//! Module 1: Network & Sockets Radar.

use super::*;

pub(crate) fn check_network_sockets() -> ModuleStatus {
    let mut total = 0;
    let mut listen = 0;
    let mut estab = 0;
    let mut flagged = 0;
    let mut warned = 0;
    let mut alert_items = Vec::new();
    let mut listen_items = Vec::new();
    let mut estab_items = Vec::new();

    let mut sockets = Vec::new();
    let mut unreadable = Vec::new();
    for (path, proto) in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp6"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp6"),
    ] {
        // ~150 bytes per socket: 16 MiB covers about 100k sockets per table
        match read_file_bounded(Path::new(path), 16 * 1024 * 1024) {
            Ok(content) => sockets.extend(
                content
                    .lines()
                    .skip(1)
                    .filter_map(|l| net::parse_proc_net_line(l, proto)),
            ),
            // A missing tcp6/udp6 just means IPv6 is disabled
            Err(_) if !Path::new(path).exists() => {}
            Err(_) => unreadable.push(path),
        }
    }
    let owners = net::socket_owners();
    let owner_label = |inode: u64| match owners.get(&inode) {
        Some(o) => format!("{} pid {}", o.name, o.pid),
        None => "other user".to_string(),
    };

    // Listeners go through the behavior analyzer, which needs the owning process
    // name to tell e.g. sshd on :22 from an impostor.
    let listeners: Vec<&net::SocketEntry> = sockets.iter().filter(|s| s.is_listener()).collect();
    let analyzer_input: Vec<(&str, &str, u16, Option<i32>, &str)> = listeners
        .iter()
        .map(|s| {
            let owner = owners.get(&s.inode);
            (
                s.proto,
                s.local_ip.as_str(),
                s.local_port,
                owner.map(|o| o.pid),
                owner.map_or("", |o| o.name.as_str()),
            )
        })
        .collect();
    for anomaly in ai::analyze_socket_anomalies(&analyzer_input) {
        let severe = anomaly.severity >= ai::AnomalySeverity::High;
        if severe {
            flagged += 1;
        } else {
            warned += 1;
        }
        let who = match anomaly.pid {
            Some(pid) => format!("{} pid {}", anomaly.process_name, pid),
            None => "other user".to_string(),
        };
        alert_items.push(format!(
            "[{}] {} :{} ({}) [{}] by {}: {}",
            if severe { "ALERT" } else { "WARNING" },
            anomaly.protocol.to_uppercase(),
            anomaly.port,
            net::port_service_name(anomaly.port),
            anomaly.local_address,
            who,
            anomaly.reasons.join("; ")
        ));
    }

    for s in &sockets {
        total += 1;
        if s.is_listener() {
            // UDP "listeners" include every unconnected client socket; only TCP LISTEN
            // is counted and listed, UDP still went through the analyzer above.
            if !s.proto.starts_with("tcp") {
                continue;
            }
            listen += 1;
            if listen_items.len() < 5 {
                listen_items.push(format!(
                    "LISTEN :{} ({}) [{}] {}",
                    s.local_port,
                    net::port_service_name(s.local_port),
                    s.local_ip,
                    owner_label(s.inode)
                ));
            }
        } else if s.is_established() {
            estab += 1;
            if net::is_suspicious_port(s.remote_port) {
                flagged += 1;
                alert_items.push(format!(
                    "[ALERT] Outbound C2/Reverse Shell to {}:{} ({}) from {}",
                    s.remote_ip,
                    s.remote_port,
                    net::port_service_name(s.remote_port),
                    owner_label(s.inode)
                ));
            }
            if estab_items.len() < 5 {
                estab_items.push(format!(
                    "ESTAB -> {}:{} ({}) {}",
                    s.remote_ip,
                    s.remote_port,
                    net::port_service_name(s.remote_port),
                    owner_label(s.inode)
                ));
            }
        }
    }

    let mut items = Vec::new();
    items.extend(alert_items);
    items.extend(listen_items);
    items.extend(estab_items);
    // A table that could not be read has not been checked
    for path in &unreadable {
        items.insert(
            0,
            format!(
                "[WARNING] {} could not be read; its sockets were not checked",
                path
            ),
        );
    }
    if items.is_empty() {
        items.push("No active listening sockets found".to_string());
    }

    let status = if flagged > 0 {
        Status::Alert
    } else if warned > 0 || !unreadable.is_empty() {
        Status::Warning
    } else {
        Status::Secure
    };
    ModuleStatus {
        id: "network".to_string(),
        name: "Network & Sockets Radar".to_string(),
        status,
        summary: format!("{} Active ({} Listen, {} Estab)", total, listen, estab),
        detail: if flagged > 0 {
            format!("[ALERT] {} Suspicious connections detected!", flagged)
        } else if warned > 0 {
            format!("{} listener(s) worth a look; see the list", warned)
        } else if !unreadable.is_empty() {
            "Some socket tables could not be read; see the list".to_string()
        } else {
            "All outbound connections verified".to_string()
        },
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}
