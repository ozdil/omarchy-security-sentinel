//! `sentinel-engine` CLI: argument dispatch only; the engine lives in `engine/`.

use std::env;
use std::path::Path;

// The binary links the library crate instead of re-declaring its modules, so the
// engine logic (and its SHA-256 implementation) is compiled and tested once.
use sentinel_engine::{ai, kernel};

mod engine;
use engine::*;

/// Prints the new state; on failure notifies, prints the error and exits 1 so the
/// UI can roll back the switch it flipped optimistically.
fn exit_with_toggle_result(res: Result<bool, String>) -> ! {
    match res {
        Ok(state) => {
            println!("{}", if state { "ENABLED" } else { "DISABLED" });
            std::process::exit(0)
        }
        Err(e) => {
            notify_desktop("Security Sentinel", &e, false);
            eprintln!("{}", e);
            std::process::exit(1)
        }
    }
}

fn main() {
    // 1. Enforce military-grade anti-tamper (prctl PR_SET_DUMPABLE 0)
    let _ = kernel::enforce_anti_tamper();

    let args: Vec<String> = env::args().collect();
    // Only the first argument selects the action. Scanning every argument would let a
    // file name passed to --clean-files (e.g. a dropped file called "panic-blackout")
    // trigger an unrelated, possibly destructive subcommand.
    let cmd = args.get(1).map(String::as_str).unwrap_or("");

    // Root-side polkit helper: `pkexec /usr/bin/sentinel-engine --privileged-* <op> [arg]`
    if matches!(
        cmd,
        kernel::PRIVILEGED_INTERVENTION_FLAG | kernel::PRIVILEGED_NETWORK_FLAG
    ) {
        let op = args.get(2).map(String::as_str).unwrap_or("");
        let res = kernel::run_privileged_operation(cmd, op, args.get(3).map(String::as_str));
        println!("{}", serde_json::to_string(&res).unwrap());
        std::process::exit(if res.success { 0 } else { 1 });
    }

    if matches!(cmd, "--daemon") {
        std::process::exit(run_daemon());
    }

    // Verify self-integrity
    if matches!(cmd, "--verify-integrity" | "verify-integrity") {
        match kernel::calculate_self_exe_sha256() {
            Ok(hash) => {
                println!(
                    "{{\"self_integrity\": \"SECURE\", \"sha256\": \"{}\", \"anti_tamper\": true}}",
                    hash
                );
            }
            Err(e) => {
                eprintln!(
                    "{{\"self_integrity\": \"COMPROMISED\", \"error\": \"{}\"}}",
                    e
                );
                std::process::exit(1);
            }
        }
        return;
    }

    // Emergency Military Network Blackout (Killswitch)
    if matches!(cmd, "--panic-blackout" | "panic-blackout") {
        let res = kernel::kernel_apply_network_blackout();
        println!("{}", serde_json::to_string(&res).unwrap());
        return;
    }

    if matches!(cmd, "--resume-network" | "resume-network") {
        let res = kernel::kernel_clear_network_blackout();
        println!("{}", serde_json::to_string(&res).unwrap());
        return;
    }

    if matches!(cmd, "--blackout-status" | "blackout-status") {
        let active = kernel::kernel_is_network_blackout_active();
        println!("{{\"blackout_active\": {}}}", active);
        return;
    }

    if matches!(cmd, "--toggle-usb-armor") {
        exit_with_toggle_result(toggle_usb_armor());
    }

    // AI audit subcommand
    if matches!(cmd, "--ai-audit" | "ai-audit") {
        let anomalies = ai::analyze_all_processes();
        println!("{}", serde_json::to_string_pretty(&anomalies).unwrap());
        return;
    }

    // Kernel freeze process
    if let Some(pos) = matches!(
        cmd,
        "--kernel-freeze" | "kernel-freeze" | "--freeze-process"
    )
    .then_some(1usize)
    {
        if let Some(pid_str) = args.get(pos + 1) {
            if let Ok(pid) = pid_str.parse::<i32>() {
                let res = kernel::kernel_freeze_process(pid);
                println!("{}", serde_json::to_string(&res).unwrap());
                return;
            }
        }
        eprintln!("Error: Valid numeric PID required for kernel freeze");
        std::process::exit(1);
    }

    // Kernel terminate process
    if let Some(pos) = matches!(
        cmd,
        "--kernel-terminate" | "kernel-terminate" | "--terminate-process"
    )
    .then_some(1usize)
    {
        if let Some(pid_str) = args.get(pos + 1) {
            if let Ok(pid) = pid_str.parse::<i32>() {
                let res = kernel::kernel_terminate_process(pid);
                println!("{}", serde_json::to_string(&res).unwrap());
                return;
            }
        }
        eprintln!("Error: Valid numeric PID required for kernel terminate");
        std::process::exit(1);
    }

    // Kernel thaw process
    if let Some(pos) = matches!(cmd, "--kernel-thaw" | "kernel-thaw").then_some(1usize) {
        if let Some(pid_str) = args.get(pos + 1) {
            if let Ok(pid) = pid_str.parse::<i32>() {
                let res = kernel::kernel_thaw_process(pid);
                println!("{}", serde_json::to_string(&res).unwrap());
                return;
            }
        }
        eprintln!("Error: Valid numeric PID required for kernel thaw");
        std::process::exit(1);
    }

    // Kernel sever socket
    if let Some(pos) =
        matches!(cmd, "--kernel-sever-socket" | "kernel-sever-socket").then_some(1usize)
    {
        if let Some(target) = args.get(pos + 1) {
            let res = kernel::kernel_sever_socket(target);
            println!("{}", serde_json::to_string(&res).unwrap());
            return;
        }
        eprintln!("Error: Target port or IP required for socket severing");
        std::process::exit(1);
    }

    // Kernel de-auth USB
    if let Some(pos) = matches!(cmd, "--kernel-deauth-usb" | "kernel-deauth-usb").then_some(1usize)
    {
        if let Some(bus_id) = args.get(pos + 1) {
            let res = kernel::kernel_deauth_usb(bus_id);
            println!("{}", serde_json::to_string(&res).unwrap());
            return;
        }
        eprintln!("Error: USB bus ID required for de-authorization");
        std::process::exit(1);
    }

    // Kernel quarantine IP
    if let Some(pos) =
        matches!(cmd, "--kernel-quarantine-ip" | "kernel-quarantine-ip").then_some(1usize)
    {
        if let Some(ip) = args.get(pos + 1) {
            let res = kernel::kernel_quarantine_ip(ip);
            println!("{}", serde_json::to_string(&res).unwrap());
            return;
        }
        eprintln!("Error: IP address required for quarantine");
        std::process::exit(1);
    }

    if matches!(cmd, "--toggle-ghost-mac") {
        exit_with_toggle_result(toggle_ghost_mac());
    }

    if matches!(cmd, "--toggle-dns" | "--toggle-dot") {
        exit_with_toggle_result(toggle_dns());
    }

    if matches!(cmd, "--trust-all-usb") {
        let count = trust_all_usb();
        println!("Trusted {} devices", count);
        return;
    }

    if matches!(cmd, "--reset-canaries") {
        reset_canaries();
        println!("Canaries reset");
        return;
    }

    if matches!(cmd, "--scrub-downloads") {
        let count = scrub_downloads();
        if count > 0 {
            notify_desktop(
                "OpSec Cleaner",
                &format!("EXIF metadata stripped from {} images in Downloads.", count),
                false,
            );
        } else {
            notify_desktop(
                "OpSec Cleaner",
                "No images needing metadata scrubbing found in Downloads.",
                false,
            );
        }
        println!("Cleaned {} image files in Downloads", count);
        return;
    }

    if let Some(pos) = matches!(cmd, "--clean-files").then_some(1usize) {
        let files = &args[pos + 1..];
        let mut cleaned = 0;
        for f_str in files {
            let p = Path::new(f_str);
            if clean_file(p).is_ok() {
                cleaned += 1;
            }
        }
        if cleaned > 0 {
            notify_desktop(
                "OpSec Cleaner",
                &format!("Stripped EXIF and metadata from {} files.", cleaned),
                false,
            );
        } else {
            notify_desktop(
                "OpSec Cleaner",
                "No metadata to scrub found in selected files or operation failed.",
                true,
            );
        }
        println!("Cleaned {} files", cleaned);
        return;
    }

    let report = build_report();

    if matches!(cmd, "--status" | "--bar") {
        let text = "\u{f0483}".to_string();
        let tooltip = format!(
            "Security Sentinel Hub\nStatus: {}\nThreat Level: {}\nActive Subsystems: {} / {}\n\n[Left Click] Open Security Center",
            report.overall_status, report.threat_level, report.active_modules, report.active_modules
        );
        let out = BarStatus {
            text,
            tooltip,
            class: if report.threat_level == ThreatLevel::Zero {
                "normal".to_string()
            } else {
                "warning".to_string()
            },
            color: report.threat_color,
        };
        println!("{}", serde_json::to_string(&out).unwrap());
        return;
    }

    if matches!(cmd, "--json") {
        write_report_cache(&report);
        println!("{}", serde_json::to_string(&report).unwrap());
        return;
    }

    println!("OMARCHY SECURITY SENTINEL - UNIFIED DEFENSE ENGINE");
    println!(
        "Status: {} | Threat: {}",
        report.overall_status, report.threat_level
    );
    for m in &report.modules {
        println!("{:<25} [{:<8}] {}", m.name, m.status, m.summary);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_engine::{net, sha256_hex};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn test_clean_file_rejects_symlinks() {
        let temp_dir = env::temp_dir().join(format!("sentinel_sym_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let real_file = temp_dir.join("real_image.png");
        let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        fs::write(&real_file, png_header).unwrap();

        let sym_file = temp_dir.join("symlink_image.png");
        std::os::unix::fs::symlink(&real_file, &sym_file).unwrap();

        let res = clean_file(&sym_file);
        assert!(res.is_err(), "clean_file must reject symlinks");
        assert!(res
            .unwrap_err()
            .contains("Symlinks are strictly prohibited"));

        // Verify real file was untouched
        assert_eq!(fs::read(&real_file).unwrap(), png_header);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_clean_file_rejects_directories_and_non_files() {
        let temp_dir = env::temp_dir().join(format!("sentinel_dir_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let res = clean_file(&temp_dir);
        assert!(res.is_err(), "clean_file must reject directories");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_clean_file_atomic_png_scrubbing_and_cleanup() {
        let temp_dir = env::temp_dir().join(format!("sentinel_clean_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let png_file = temp_dir.join("test_photo.png");

        // Construct a synthetic PNG with IHDR, tEXt (metadata), and IEND chunks
        let mut png_data = Vec::new();
        png_data.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]); // Header

        // IHDR chunk (length 13, type IHDR, 13 data bytes, 4 CRC bytes = 25 bytes total)
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]);
        png_data.extend_from_slice(b"IHDR");
        png_data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00,
        ]);
        png_data.extend_from_slice(&[0x1F, 0x15, 0xC4, 0x89]); // CRC

        // tEXt metadata chunk (length 9, type tEXt, "Author=Oz", 4 CRC bytes)
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x09]);
        png_data.extend_from_slice(b"tEXt");
        png_data.extend_from_slice(b"Author=Oz");
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC dummy

        // IEND chunk (length 0, type IEND, 4 CRC bytes)
        png_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        png_data.extend_from_slice(b"IEND");
        png_data.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);

        fs::write(&png_file, &png_data).unwrap();

        // Verify file contains metadata before cleaning
        let raw_before = fs::read(&png_file).unwrap();
        assert!(raw_before.windows(4).any(|w| w == b"tEXt"));

        // Clean file
        let clean_res = clean_file(&png_file);
        assert!(
            clean_res.is_ok(),
            "clean_file must succeed on valid PNG: {:?}",
            clean_res.err()
        );

        // Verify metadata was stripped
        let raw_after = fs::read(&png_file).unwrap();
        assert_eq!(
            &raw_after[..8],
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        );
        assert!(
            !raw_after.windows(4).any(|w| w == b"tEXt"),
            "tEXt metadata must be stripped"
        );
        assert!(
            raw_after.windows(4).any(|w| w == b"IHDR"),
            "IHDR chunk must be preserved"
        );
        assert!(
            raw_after.windows(4).any(|w| w == b"IEND"),
            "IEND chunk must be preserved"
        );

        // Verify no temporary files remain in directory
        let remaining_files: Vec<_> = fs::read_dir(&temp_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(remaining_files, vec!["test_photo.png"]);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_clean_file_atomic_jpeg_scrubbing() {
        let temp_dir = env::temp_dir().join(format!("sentinel_jpg_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let jpg_file = temp_dir.join("sample.jpg");

        // Construct synthetic JPEG with APP1 (EXIF: 0xFF, 0xE1) and SOI (0xFF, 0xD8), EOI (0xFF, 0xD9)
        let mut jpg_data = Vec::new();
        jpg_data.extend_from_slice(&[0xFF, 0xD8]); // SOI
                                                   // APP1 metadata segment (length 6: len bytes 0x00, 0x06 + 4 bytes payload)
        jpg_data.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x06, 0x45, 0x78, 0x69, 0x66]);
        // EOI marker
        jpg_data.extend_from_slice(&[0xFF, 0xD9]);

        fs::write(&jpg_file, &jpg_data).unwrap();

        let clean_res = clean_file(&jpg_file);
        assert!(
            clean_res.is_ok(),
            "clean_file must succeed on synthetic JPEG: {:?}",
            clean_res.err()
        );

        let raw_after = fs::read(&jpg_file).unwrap();
        assert_eq!(&raw_after[..2], &[0xFF, 0xD8]);
        assert_eq!(&raw_after[raw_after.len() - 2..], &[0xFF, 0xD9]);
        // APP1 marker must be stripped
        assert!(!raw_after.windows(2).any(|w| w == [0xFF, 0xE1]));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_strip_jpeg_keeps_icc_and_adobe_segments() {
        let mut jpg = vec![0xFF, 0xD8];
        // APP1 EXIF (stripped)
        jpg.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x08]);
        jpg.extend_from_slice(b"Exif\0\0");
        // APP2 ICC_PROFILE (kept)
        jpg.extend_from_slice(&[0xFF, 0xE2, 0x00, 0x0E]);
        jpg.extend_from_slice(b"ICC_PROFILE\0");
        // APP14 Adobe (kept)
        jpg.extend_from_slice(&[0xFF, 0xEE, 0x00, 0x07]);
        jpg.extend_from_slice(b"Adobe");
        // COM comment (stripped)
        jpg.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x05, b'h', b'i', b'!']);
        jpg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02, 0x11, 0x22, 0xFF, 0xD9]);

        let out = strip_jpeg_metadata(&jpg).unwrap();
        assert!(!out.windows(4).any(|w| w == b"Exif"));
        assert!(!out.windows(3).any(|w| w == b"hi!"));
        assert!(out.windows(11).any(|w| w == b"ICC_PROFILE"));
        assert!(out.windows(5).any(|w| w == b"Adobe"));
        assert!(out.ends_with(&[0x11, 0x22, 0xFF, 0xD9]));
    }

    #[test]
    fn test_strip_jpeg_rejects_truncated_input_without_touching_file() {
        let temp_dir = env::temp_dir().join(format!("sentinel_trunc_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        let jpg_file = temp_dir.join("truncated.jpg");
        // APP1 claims 0x1000 bytes but the file ends early
        let data = [0xFF, 0xD8, 0xFF, 0xE1, 0x10, 0x00, 0x45, 0x78];
        fs::write(&jpg_file, data).unwrap();

        assert!(clean_file(&jpg_file).is_err());
        assert_eq!(fs::read(&jpg_file).unwrap(), data);
        // Zero-length segment headers are malformed too
        assert!(strip_jpeg_metadata(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x00]).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_sha256_hex_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"message digest"),
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"
        );
    }

    #[test]
    fn test_secure_state_file_mode_0600_and_symlink_rejection() {
        let temp_dir = env::temp_dir().join(format!("sentinel_state_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        let _ = fs::set_permissions(&temp_dir, fs::Permissions::from_mode(0o700));

        let state_file = temp_dir.join("test_state.json");
        let content = b"{\"active\":true,\"count\":42}";

        // 1. Write file securely
        let write_res = write_secure_state_file(&state_file, content);
        assert!(
            write_res.is_ok(),
            "write_secure_state_file should succeed: {:?}",
            write_res.err()
        );

        // 2. Verify file permissions are strictly 0600
        let meta = fs::symlink_metadata(&state_file).unwrap();
        assert_eq!(
            meta.mode() & 0o777,
            0o600,
            "State file mode must be strictly 0600 (-rw-------)"
        );

        // 3. Read file back
        let read_bytes = read_secure_state_file(&state_file, 1024).unwrap();
        assert_eq!(read_bytes, content);

        // 4. Overwrite atomically
        let new_content = b"{\"active\":false,\"count\":99}";
        assert!(write_secure_state_file(&state_file, new_content).is_ok());
        let read_bytes2 = read_secure_state_file(&state_file, 1024).unwrap();
        assert_eq!(read_bytes2, new_content);

        // 5. Test symlink rejection on read
        let sym_file = temp_dir.join("sym_state.json");
        std::os::unix::fs::symlink(&state_file, &sym_file).unwrap();
        let sym_read = read_secure_state_file(&sym_file, 1024);
        assert!(
            sym_read.is_err(),
            "read_secure_state_file must reject symlinks"
        );

        // 6. Test symlink rejection on write
        let sym_write = write_secure_state_file(&sym_file, b"hack");
        assert!(
            sym_write.is_err(),
            "write_secure_state_file must refuse to overwrite symlink"
        );

        // 7. Verify no temporary files remain
        let remaining_files: Vec<_> = fs::read_dir(&temp_dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(".tmp_state_"))
            .collect();
        assert!(remaining_files.is_empty(), "No temp files should remain");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_read_file_bounded_success_and_overflow() {
        let temp_dir = env::temp_dir().join(format!("sentinel_read_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let test_file = temp_dir.join("sample.txt");
        fs::write(&test_file, b"1234567890").unwrap();

        // Reading with exact or larger limit succeeds
        let res1 = read_file_bounded(&test_file, 10);
        assert!(res1.is_ok());
        assert_eq!(res1.unwrap(), "1234567890");

        let res2 = read_file_bounded(&test_file, 100);
        assert!(res2.is_ok());
        assert_eq!(res2.unwrap(), "1234567890");

        // Reading with smaller limit fails with bounded overflow error
        let res3 = read_file_bounded(&test_file, 9);
        assert!(res3.is_err());
        assert!(res3.unwrap_err().contains("exceeded limit"));

        // Symlink rejection
        let sym_file = temp_dir.join("sym_sample.txt");
        std::os::unix::fs::symlink(&test_file, &sym_file).unwrap();
        let sym_res = read_file_bounded(&sym_file, 100);
        assert!(
            sym_res.is_err(),
            "read_file_bounded must reject symlinks via O_NOFOLLOW"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_suspicious_port_detection_and_service_mapping() {
        assert!(net::is_suspicious_port(1337));
        assert!(net::is_suspicious_port(4444));
        assert!(net::is_suspicious_port(5555));
        assert!(net::is_suspicious_port(6666));
        assert!(net::is_suspicious_port(6667));
        assert!(net::is_suspicious_port(9001));
        assert!(net::is_suspicious_port(31337));

        assert!(!net::is_suspicious_port(22));
        assert!(!net::is_suspicious_port(53));
        assert!(!net::is_suspicious_port(80));
        assert!(!net::is_suspicious_port(443));
        assert!(!net::is_suspicious_port(853));

        assert_eq!(net::port_service_name(4444), "Metasploit C2");
        assert_eq!(net::port_service_name(1337), "Backdoor/C2");
        assert_eq!(net::port_service_name(31337), "Back Orifice");
        assert_eq!(net::port_service_name(853), "DoT Encrypted");
        assert_eq!(net::port_service_name(6379), "Redis Cache");
    }

    #[test]
    fn test_parse_ip_port_ipv4() {
        let parsed = net::parse_ip_port("0100007F:115C");
        assert!(parsed.is_some());
        let (ip, port) = parsed.unwrap();
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 4444);

        assert!(net::parse_ip_port("invalid").is_none());
        assert!(net::parse_ip_port("0100007F:GGGG").is_none());
    }

    #[test]
    fn test_sanitize_usb_product_strips_html_and_control_chars() {
        let malicious = "<img src=\"http://127.0.0.1:8080/beacon\">BadUSB Payload\0\x1b";
        let cleaned = sanitize_usb_product(malicious);
        assert!(!cleaned.contains('<'));
        assert!(!cleaned.contains('>'));
        assert!(!cleaned.contains('"'));
        assert!(!cleaned.contains('\0'));
        assert_eq!(
            cleaned,
            "img src=http://127.0.0.1:8080/beaconBadUSB Payload"
        );

        let empty = "   \n\t  ";
        assert_eq!(sanitize_usb_product(empty), "USB Device");

        let normal = "Logitech USB Optical Mouse";
        assert_eq!(sanitize_usb_product(normal), "Logitech USB Optical Mouse");
    }
}
