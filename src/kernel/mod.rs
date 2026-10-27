pub mod intervention;
pub mod self_defense;

pub use intervention::{
    kernel_apply_network_blackout, kernel_clear_network_blackout, kernel_deauth_usb,
    kernel_freeze_pinned, kernel_freeze_process, kernel_is_network_blackout_active,
    kernel_network_blackout_state, kernel_quarantine_ip, kernel_reauth_usb, kernel_sever_socket,
    kernel_terminate_pinned, kernel_terminate_process, kernel_thaw_pinned, kernel_thaw_process,
    parse_process_target, privileged_helper_available, process_start_time,
    run_privileged_operation, BlackoutState, InterventionResult, PRIVILEGED_INTERVENTION_FLAG,
    PRIVILEGED_NETWORK_FLAG, PRIVILEGED_USB_BLOCK_FLAG, PRIVILEGED_USB_TRUST_FLAG,
};
pub use self_defense::{
    calculate_self_exe_sha256, constant_time_eq, enforce_anti_tamper, sha256_hex, SecureBuffer,
};
