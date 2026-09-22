pub mod ai;
pub mod kernel;
pub mod subproc;

pub use ai::{
    analyze_all_processes, analyze_socket_anomalies, AnomalySeverity, BehaviorAnalyzer,
    ProcessAnomaly, SocketAnomaly,
};
pub use kernel::{
    kernel_deauth_usb, kernel_freeze_process, kernel_quarantine_ip, kernel_sever_socket,
    kernel_thaw_process, InterventionResult,
};
