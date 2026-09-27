pub mod ai;
pub mod kernel;
pub mod subproc;

pub use ai::{
    analyze_all_processes, analyze_socket_anomalies, AnomalySeverity, BehaviorAnalyzer,
    ProcessAnomaly, SocketAnomaly,
};
pub use kernel::{
    calculate_self_exe_sha256, constant_time_eq, enforce_anti_tamper, kernel_apply_network_blackout,
    kernel_clear_network_blackout, kernel_deauth_usb, kernel_freeze_process,
    kernel_is_network_blackout_active, kernel_quarantine_ip, kernel_sever_socket,
    kernel_terminate_process, kernel_thaw_process, sha256_hex, InterventionResult, SecureBuffer,
};
