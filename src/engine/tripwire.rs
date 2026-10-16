//! Module 5: Tripwire Canaries.

use super::*;

pub(crate) fn check_tripwire() -> ModuleStatus {
    let token_path = get_state_dir().join("canary.token");
    let hash_path = get_state_dir().join("canary.sha256");

    if !token_path.exists() || !hash_path.exists() {
        let token_data = b"OMARCHY_SECURITY_SENTINEL_TRIPWIRE_TOKEN_V2_INIT\n";
        let _ = write_secure_state_file(&token_path, token_data);
        let hash = sha256_hex(token_data);
        let _ = write_secure_state_file(&hash_path, hash.as_bytes());
    }

    let expected_hash = read_secure_state_file(&hash_path, 128)
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_default();

    let current_hash = read_secure_state_file(&token_path, 4096)
        .map(|b| sha256_hex(&b))
        .unwrap_or_default();

    let is_token_intact = !expected_hash.is_empty() && expected_hash == current_hash;

    // Decoy canary in /tmp to trap filesystem crawlers, wipers, and ransomware
    let tmp_canary_path = Path::new("/tmp/.omarchy_canary.token");
    if !tmp_canary_path.exists() {
        let _ = write_secure_state_file(tmp_canary_path, b"OMARCHY_MILITARY_TRIPWIRE_TMP_CANARY\n");
    }
    // /tmp is shared: a decoy pre-created (or replaced) by another user would otherwise
    // pass this check forever, so require it to be our own regular, non-symlink file.
    let tmp_intact = read_secure_state_file(tmp_canary_path, 128)
        .map(|b| String::from_utf8_lossy(&b).contains("OMARCHY_MILITARY_TRIPWIRE_TMP_CANARY"))
        .unwrap_or(false);

    let is_intact = is_token_intact && tmp_intact;
    let status = if is_intact {
        Status::Secure
    } else {
        Status::Alert
    };

    let mut items = Vec::new();
    items.push(format!("Primary Canary: {}", token_path.display()));
    items.push(format!("Decoy Canary: {}", tmp_canary_path.display()));
    let hash_display = if expected_hash.len() > 16 {
        format!(
            "{}...{}",
            &expected_hash[..8],
            &expected_hash[expected_hash.len() - 8..]
        )
    } else {
        expected_hash.clone()
    };
    items.push(format!(
        "SHA-256 Seal: {} [{}]",
        hash_display,
        if is_token_intact {
            "Intact"
        } else {
            "MISMATCH"
        }
    ));
    items.push(if is_intact {
        "Ransomware Defense: All honey-tokens intact | File baseline verified".to_string()
    } else {
        "[ALERT] Canary token modified or wiped by untrusted process!".to_string()
    });

    ModuleStatus {
        id: "tripwire".to_string(),
        name: "Tripwire Canaries".to_string(),
        status,
        summary: if is_intact {
            "Honey-tokens Intact (SHA-256 Verified)".to_string()
        } else {
            "[ALERT] TRIPWIRE TOKEN TAMPERED / ENCRYPTED!".to_string()
        },
        detail: if is_intact {
            "Canary file hash matches baseline | Ransomware early-warning active".to_string()
        } else {
            "Canary token mismatch detected! Possible filesystem compromise!".to_string()
        },
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}

pub(crate) fn reset_canaries() {
    let token_path = get_state_dir().join("canary.token");
    let hash_path = get_state_dir().join("canary.sha256");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let token_data = format!("OMARCHY_SECURITY_SENTINEL_TRIPWIRE_TOKEN_GEN_{}\n", now);
    let _ = write_secure_state_file(&token_path, token_data.as_bytes());
    let hash = sha256_hex(token_data.as_bytes());
    let _ = write_secure_state_file(&hash_path, hash.as_bytes());
    notify_desktop("Tripwire Canaries", "New canary token created.", false);
}
