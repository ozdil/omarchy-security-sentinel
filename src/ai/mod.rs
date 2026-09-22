pub mod behavior_analyzer;

pub use behavior_analyzer::{
    analyze_all_processes, analyze_socket_anomalies, AnomalySeverity, BehaviorAnalyzer,
    ProcessAnomaly, SocketAnomaly,
};
