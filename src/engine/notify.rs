//! Desktop notifications (omarchy-notification-send, then notify-send).

use super::*;

pub(crate) fn notify_desktop(title: &str, body: &str, is_critical: bool) {
    let urgency = if is_critical { "critical" } else { "normal" };
    let deadline = Instant::now() + Duration::from_millis(1500);

    let mut extra_envs = Vec::new();
    let dbus = env::var("DBUS_SESSION_BUS_ADDRESS").unwrap_or_default();
    if !dbus.is_empty() {
        extra_envs.push(("DBUS_SESSION_BUS_ADDRESS", dbus.as_str()));
    }
    let wayland = env::var("WAYLAND_DISPLAY").unwrap_or_default();
    if !wayland.is_empty() {
        extra_envs.push(("WAYLAND_DISPLAY", wayland.as_str()));
    }
    let display = env::var("DISPLAY").unwrap_or_default();
    if !display.is_empty() {
        extra_envs.push(("DISPLAY", display.as_str()));
    }
    let runtime_dir = env::var("XDG_RUNTIME_DIR").unwrap_or_default();
    if !runtime_dir.is_empty() {
        extra_envs.push(("XDG_RUNTIME_DIR", runtime_dir.as_str()));
    }

    // Try omarchy-notification-send first with explicit shield glyph (Nerd Font) and app identity
    let glyph = "";
    let status = run_cmd_bounded(
        "omarchy-notification-send",
        &[
            "--app-name",
            "Security Sentinel",
            "-g",
            glyph,
            "-u",
            urgency,
            title,
            body,
        ],
        &extra_envs,
        deadline,
        4096,
    );

    // Fallback to notify-send with verified system icon if omarchy-notification-send is absent
    if status.is_none() {
        let icon = if is_critical {
            "dialog-warning"
        } else {
            "dialog-information"
        };
        let _ = run_cmd_bounded(
            "notify-send",
            &[
                "-a",
                "Security Sentinel",
                "-u",
                urgency,
                "-i",
                icon,
                "--",
                title,
                body,
            ],
            &extra_envs,
            deadline,
            4096,
        );
    }
}
