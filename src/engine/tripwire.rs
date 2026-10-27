//! Module 5: Tripwire Canaries.

use super::*;

pub(crate) fn check_tripwire() -> ModuleStatus {
    // SAFETY: getuid has no preconditions
    let decoy = PathBuf::from(format!("/tmp/.omarchy_canary.{}.token", unsafe {
        getuid()
    }));
    check_tripwire_in(&get_state_dir(), &decoy)
}

const DECOY_TOKEN: &[u8] = b"OMARCHY_MILITARY_TRIPWIRE_TMP_CANARY\n";

/// Primary canary seal state, given the state directory
#[derive(Debug, PartialEq, Eq)]
enum Seal {
    Intact,
    Mismatch,
    /// Token or hash removed after the tripwire was armed (rename-then-delete ransomware)
    Missing,
}

fn primary_seal(dir: &Path) -> (Seal, String) {
    let token_path = dir.join("canary.token");
    let hash_path = dir.join("canary.sha256");
    let armed_path = dir.join("canary.armed");

    let token_exists = token_path.exists();
    let hash_exists = hash_path.exists();
    if !armed_path.exists() {
        // First run (or an upgrade from a version without the marker): arm the
        // tripwire, keeping an existing token pair as the baseline
        if !token_exists || !hash_exists {
            let token_data = b"OMARCHY_SECURITY_SENTINEL_TRIPWIRE_TOKEN_V2_INIT\n";
            let _ = write_secure_state_file(&token_path, token_data);
            let _ = write_secure_state_file(&hash_path, sha256_hex(token_data).as_bytes());
        }
        let _ = write_secure_state_file(&armed_path, b"1\n");
    } else if !token_exists || !hash_exists {
        // Only --reset-canaries may recreate an armed canary
        return (Seal::Missing, String::new());
    }

    let expected_hash = read_secure_state_file(&hash_path, 128)
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .unwrap_or_default();
    let current_hash = read_secure_state_file(&token_path, 4096)
        .map(|b| sha256_hex(&b))
        .unwrap_or_default();
    let seal = if !expected_hash.is_empty() && expected_hash == current_hash {
        Seal::Intact
    } else {
        Seal::Mismatch
    };
    (seal, expected_hash)
}

/// Decoy state: Ok(true) intact, Ok(false) tampered, Err(()) path held by someone else
fn decoy_state(decoy: &Path) -> Result<bool, ()> {
    if fs::symlink_metadata(decoy).is_err() {
        // create_new is O_EXCL: never follows or reuses a file planted in the shared /tmp
        let created = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(decoy)
            .and_then(|mut f| f.write_all(DECOY_TOKEN));
        if created.is_err() {
            return Err(());
        }
    }
    match fs::symlink_metadata(decoy) {
        // SAFETY: getuid has no preconditions
        Ok(m) if m.file_type().is_file() && m.uid() == unsafe { getuid() } => {
            Ok(read_secure_state_file(decoy, 128)
                .map(|b| b == DECOY_TOKEN)
                .unwrap_or(false))
        }
        _ => Err(()),
    }
}

fn check_tripwire_in(dir: &Path, tmp_canary_path: &Path) -> ModuleStatus {
    let token_path = dir.join("canary.token");
    let (seal, expected_hash) = primary_seal(dir);
    let is_token_intact = seal == Seal::Intact;
    let decoy = decoy_state(tmp_canary_path);
    // A decoy path owned by another user is a nuisance, not proof of tampering with ours
    let tmp_intact = decoy != Ok(false);

    let is_intact = is_token_intact && tmp_intact;
    let status = if !is_intact {
        Status::Alert
    } else if decoy.is_err() {
        Status::Warning
    } else {
        Status::Secure
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
        match seal {
            Seal::Intact => "Intact",
            Seal::Mismatch => "MISMATCH",
            Seal::Missing => "MISSING",
        }
    ));
    if decoy.is_err() {
        items.push(format!(
            "[WARNING] Decoy path {} is held by another user; decoy check skipped",
            tmp_canary_path.display()
        ));
    }
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
    let _ = write_secure_state_file(&get_state_dir().join("canary.armed"), b"1\n");
    notify_desktop("Tripwire Canaries", "New canary token created.", false);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_dir(name: &str) -> PathBuf {
        let dir =
            env::temp_dir().join(format!("sentinel_tripwire_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_tripwire_arms_then_detects_deleted_token() {
        let dir = fresh_dir("deleted");
        let decoy = dir.join("decoy.token");
        assert_eq!(check_tripwire_in(&dir, &decoy).status, Status::Secure);
        assert!(dir.join("canary.armed").exists());

        fs::remove_file(dir.join("canary.token")).unwrap();
        assert_eq!(check_tripwire_in(&dir, &decoy).status, Status::Alert);
        // Not silently regenerated on the next scan either
        assert!(!dir.join("canary.token").exists());
        assert_eq!(check_tripwire_in(&dir, &decoy).status, Status::Alert);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tripwire_detects_deleted_hash_and_modified_token() {
        let dir = fresh_dir("hash");
        let decoy = dir.join("decoy.token");
        check_tripwire_in(&dir, &decoy);
        fs::write(dir.join("canary.token"), b"encrypted").unwrap();
        assert_eq!(check_tripwire_in(&dir, &decoy).status, Status::Alert);

        let dir2 = fresh_dir("hash2");
        check_tripwire_in(&dir2, &decoy);
        fs::remove_file(dir2.join("canary.sha256")).unwrap();
        assert_eq!(check_tripwire_in(&dir2, &decoy).status, Status::Alert);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn test_tripwire_upgrade_keeps_existing_baseline() {
        let dir = fresh_dir("upgrade");
        let token = b"OLD_TOKEN\n";
        write_secure_state_file(&dir.join("canary.token"), token).unwrap();
        write_secure_state_file(&dir.join("canary.sha256"), sha256_hex(token).as_bytes()).unwrap();
        let st = check_tripwire_in(&dir, &dir.join("decoy.token"));
        assert_eq!(st.status, Status::Secure);
        assert_eq!(fs::read(dir.join("canary.token")).unwrap(), token);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tripwire_tampered_decoy_alerts() {
        let dir = fresh_dir("decoy");
        let decoy = dir.join("decoy.token");
        check_tripwire_in(&dir, &decoy);
        fs::write(&decoy, b"wiped").unwrap();
        assert_eq!(check_tripwire_in(&dir, &decoy).status, Status::Alert);
        let _ = fs::remove_dir_all(&dir);
    }
}
