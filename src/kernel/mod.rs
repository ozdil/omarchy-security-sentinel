pub mod intervention;

pub use intervention::{
    kernel_deauth_usb, kernel_freeze_process, kernel_quarantine_ip, kernel_sever_socket,
    kernel_thaw_process, InterventionResult,
};
