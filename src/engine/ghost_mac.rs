//! Module 7: Ghost MAC.

use super::*;

pub(crate) fn check_ghost_mac() -> (ModuleStatus, bool) {
    let mut is_randomized = false;
    let mut current_mac = "Unknown".to_string();
    let mut conn_name = String::new();
    let mut dev_name = String::new();

    let deadline = Instant::now() + Duration::from_millis(1500);
    if let Some(out) = run_cmd_bounded(
        "nmcli",
        &[
            "-t",
            "-f",
            "NAME,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ],
        &[],
        deadline,
        8192,
    ) {
        let text = String::from_utf8_lossy(&out);
        for line in text.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 && parts[1] == "802-11-wireless" {
                conn_name = parts[0].to_string();
                dev_name = parts[2].to_string();

                if !dev_name.is_empty()
                    && dev_name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
                    && !dev_name.contains("..")
                {
                    let addr_path = Path::new("/sys/class/net").join(&dev_name).join("address");
                    if let Ok(addr) = read_file_bounded(&addr_path, 64) {
                        current_mac = addr.trim().to_string();
                    }
                }

                let sub_deadline = Instant::now() + Duration::from_millis(1500);
                if let Some(c_out) = run_cmd_bounded(
                    "nmcli",
                    &[
                        "-t",
                        "-f",
                        "802-11-wireless.cloned-mac-address",
                        "connection",
                        "show",
                        &conn_name,
                    ],
                    &[],
                    sub_deadline,
                    4096,
                ) {
                    let c_val = String::from_utf8_lossy(&c_out).trim().to_string();
                    if c_val.contains("random") || c_val.contains("stable-random") {
                        is_randomized = true;
                    }
                }
            }
        }
    }

    let mut items = Vec::new();
    items.push(format!(
        "Active MAC: {} ({})",
        current_mac,
        if is_randomized {
            "Randomized / Cloaked"
        } else {
            "Hardware Permanent"
        }
    ));
    items.push(format!(
        "Connection: {} on interface {}",
        if conn_name.is_empty() {
            "None"
        } else {
            &conn_name
        },
        if dev_name.is_empty() {
            "wlo1"
        } else {
            &dev_name
        }
    ));
    items.push(if is_randomized {
        "Privacy Mode: NetworkManager assigns random MAC on every connection".to_string()
    } else {
        "Privacy Mode: Real hardware vendor MAC is exposed to local access points".to_string()
    });

    let status = if is_randomized {
        Status::Secure
    } else {
        Status::Warning
    };
    let mod_status = ModuleStatus {
        id: "ghost_mac".to_string(),
        name: "Ghost MAC (Wi-Fi Randomizer)".to_string(),
        status,
        summary: if is_randomized {
            format!("Randomized ({})", current_mac)
        } else {
            format!("Hardware MAC ({})", current_mac)
        },
        detail: if is_randomized {
            "Hardware MAC hidden | Random address generated per connection".to_string()
        } else {
            "Hardware vendor MAC exposed to local APs | Toggle switch to randomize".to_string()
        },
        is_toggleable: true,
        toggle_state: is_randomized,
        items,
    };

    (mod_status, is_randomized)
}

/// Runs a short configuration command and reports whether it exited 0
pub(crate) fn run_ok(program: &str, args: &[&str], timeout: Duration) -> bool {
    matches!(
        run_cmd_bounded_status(program, args, &[], Instant::now() + timeout, 4096),
        Some((0, _))
    )
}

/// Toggles Wi-Fi MAC randomization on the active wireless connection.
/// Returns the new state, or an error the UI uses to roll back its optimistic switch.
pub(crate) fn toggle_ghost_mac() -> Result<bool, String> {
    let deadline = Instant::now() + Duration::from_millis(1500);
    let out = run_cmd_bounded(
        "nmcli",
        &["-t", "-f", "NAME,TYPE", "connection", "show", "--active"],
        &[],
        deadline,
        8192,
    )
    .ok_or("nmcli is unavailable or NetworkManager is not running")?;
    let text = String::from_utf8_lossy(&out);
    // nmcli -t escapes ':' inside names as '\:'; the type is always the last field
    let conn = text
        .lines()
        .find_map(|line| {
            let (name, ty) = line.rsplit_once(':')?;
            (ty == "802-11-wireless").then(|| name.replace("\\:", ":"))
        })
        .ok_or("No active Wi-Fi connection to randomize")?;

    let current_cloned = run_cmd_bounded(
        "nmcli",
        &[
            "-t",
            "-f",
            "802-11-wireless.cloned-mac-address",
            "connection",
            "show",
            &conn,
        ],
        &[],
        Instant::now() + Duration::from_millis(1500),
        4096,
    )
    .map(|o| String::from_utf8_lossy(&o).trim().to_string())
    .unwrap_or_default();
    let enable = !current_cloned.contains("random");
    let value = if enable { "random" } else { "permanent" };

    if !run_ok(
        "nmcli",
        &[
            "connection",
            "modify",
            &conn,
            "802-11-wireless.cloned-mac-address",
            value,
        ],
        Duration::from_secs(3),
    ) {
        return Err(format!(
            "nmcli could not change the MAC setting of '{}'",
            conn
        ));
    }
    // Reconnecting applies the new MAC; Wi-Fi association can take several seconds
    let reapplied = run_ok(
        "nmcli",
        &["connection", "up", &conn],
        Duration::from_secs(15),
    );
    let what = if enable {
        "Wi-Fi MAC randomization enabled (random MAC per connection)."
    } else {
        "Reverted to Wi-Fi hardware (original) MAC address."
    };
    let body = if reapplied {
        what.to_string()
    } else {
        format!("{} It takes effect on the next reconnect.", what)
    };
    notify_desktop("Ghost MAC", &body, false);
    Ok(enable)
}
