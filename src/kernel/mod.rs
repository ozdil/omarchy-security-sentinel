pub mod intervention;
pub mod self_defense;

pub use intervention::{
    kernel_apply_network_blackout, kernel_clear_network_blackout, kernel_deauth_usb,
    kernel_freeze_process, kernel_is_network_blackout_active, kernel_quarantine_ip,
    kernel_sever_socket, kernel_terminate_process, kernel_thaw_process, InterventionResult,
};
pub use self_defense::{
    calculate_self_exe_sha256, constant_time_eq, enforce_anti_tamper, sha256_hex, SecureBuffer,
};
