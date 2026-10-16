//! Per-user state (`$XDG_STATE_HOME`) and runtime (`$XDG_RUNTIME_DIR`) files: bounded, O_NOFOLLOW reads and atomic 0600 writes.

use super::*;

pub(crate) const O_NOFOLLOW: i32 = 0o400000;

extern "C" {
    pub(crate) fn getuid() -> u32;
}

/// Enforces 0700 mode state directory per AGENTS.md Rule 4
pub(crate) fn get_state_dir() -> PathBuf {
    let base = env::var("XDG_STATE_HOME")
        .unwrap_or_else(|_| format!("{}/.local/state", env::var("HOME").unwrap_or_default()));
    let dir = Path::new(&base).join("omarchy/security-sentinel");
    let _ = fs::create_dir_all(&dir);
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    dir
}

/// Atomically writes sensitive state file with mode 0600, sync_all, and O_NOFOLLOW per AGENTS.md Rule 4
pub(crate) fn write_secure_state_file(path: &Path, content: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Invalid state file parent path".to_string())?;
    if !parent.exists() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create parent dir: {}", e))?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = parent.join(format!(".tmp_state_{}_{}", std::process::id(), nanos));

    struct StateFileGuard<'a> {
        path: &'a Path,
        active: bool,
    }
    impl<'a> Drop for StateFileGuard<'a> {
        fn drop(&mut self) {
            if self.active {
                let _ = fs::remove_file(self.path);
            }
        }
    }

    let mut guard = StateFileGuard {
        path: &tmp_path,
        active: true,
    };

    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(&tmp_path)
        .map_err(|e| {
            format!(
                "Failed to create temp state file with 0600/O_NOFOLLOW: {}",
                e
            )
        })?;

    let _ = tmp_file.set_permissions(fs::Permissions::from_mode(0o600));

    tmp_file
        .write_all(content)
        .map_err(|e| format!("Failed to write state file: {}", e))?;

    tmp_file
        .sync_all()
        .map_err(|e| format!("Failed to sync state file to disk: {}", e))?;

    let meta = tmp_file
        .metadata()
        .map_err(|e| format!("Failed to read temp metadata: {}", e))?;
    if meta.len() != content.len() as u64 {
        return Err("State file size verification mismatch".to_string());
    }

    drop(tmp_file);

    if path.exists() {
        let dest_meta = fs::symlink_metadata(path)
            .map_err(|e| format!("Cannot check existing target: {}", e))?;
        if dest_meta.file_type().is_symlink() {
            return Err("Refusing to overwrite symlinked state file".to_string());
        }
        if !dest_meta.is_file() {
            return Err("Target state path is not a regular file".to_string());
        }
    }

    fs::rename(&tmp_path, path).map_err(|e| format!("Atomic state rename failed: {}", e))?;
    guard.active = false;
    Ok(())
}

/// Reads sensitive state file with bounded buffer, O_NOFOLLOW, and UID verification
pub(crate) fn read_secure_state_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    if !path.exists() {
        return Err("File does not exist".to_string());
    }

    let sym_meta =
        fs::symlink_metadata(path).map_err(|e| format!("symlink_metadata failed: {}", e))?;
    if sym_meta.file_type().is_symlink() {
        return Err("Symlinks are strictly prohibited for state files".to_string());
    }
    if !sym_meta.is_file() {
        return Err("State file target is not a regular file".to_string());
    }
    if sym_meta.len() > max_bytes as u64 {
        return Err("State file exceeds maximum allowed size".to_string());
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("Failed to open state file with O_NOFOLLOW: {}", e))?;

    let fd_meta = file
        .metadata()
        .map_err(|e| format!("Descriptor metadata failed: {}", e))?;
    if !fd_meta.is_file() {
        return Err("Descriptor is not a regular file".to_string());
    }

    // SAFETY: getuid is a POSIX libc syscall returning the real UID of current process
    let current_uid = unsafe { getuid() };
    if fd_meta.uid() != current_uid {
        return Err("State file is not owned by current user".to_string());
    }

    let mut buf = Vec::with_capacity(fd_meta.len() as usize);
    let mut handle = (&mut file).take((max_bytes + 1) as u64);
    handle
        .read_to_end(&mut buf)
        .map_err(|e| format!("Read failed: {}", e))?;
    if buf.len() > max_bytes {
        return Err("Read exceeded max_bytes limit".to_string());
    }
    Ok(buf)
}

/// Reads a system/procfs file with bounded buffer and O_NOFOLLOW to prevent symlink traversal and DoS memory exhaustion
pub(crate) fn read_file_bounded(path: &Path, max_bytes: usize) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("Failed to open {} with O_NOFOLLOW: {}", path.display(), e))?;

    let meta = file
        .metadata()
        .map_err(|e| format!("Failed to read metadata: {}", e))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }

    let mut buf = Vec::new();
    let mut handle = (&mut file).take((max_bytes + 1) as u64);
    handle
        .read_to_end(&mut buf)
        .map_err(|e| format!("Read failed on {}: {}", path.display(), e))?;
    if buf.len() > max_bytes {
        return Err(format!(
            "File {} exceeded limit of {} bytes",
            path.display(),
            max_bytes
        ));
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Per-session runtime directory for the cached report and the daemon lock.
/// `$XDG_RUNTIME_DIR` is a per-user tmpfs (0700) that logind removes at logout.
pub(crate) fn get_runtime_dir() -> Option<PathBuf> {
    let base = env::var("XDG_RUNTIME_DIR").ok()?;
    if !base.starts_with('/') {
        return None;
    }
    let dir = Path::new(&base).join("omarchy-security-sentinel");
    let _ = fs::create_dir(&dir);
    // Refuse a symlink or a directory planted by another user
    let meta = fs::symlink_metadata(&dir).ok()?;
    // SAFETY: getuid has no preconditions
    if !meta.file_type().is_dir() || meta.uid() != unsafe { getuid() } {
        return None;
    }
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    Some(dir)
}

pub(crate) fn report_cache_path() -> Option<PathBuf> {
    get_runtime_dir().map(|d| d.join("report.json"))
}

/// Publishes the report for the panel and dashboard (atomic rename, 0600)
pub(crate) fn write_report_cache(report: &SentinelReport) {
    if let (Some(path), Ok(json)) = (report_cache_path(), serde_json::to_vec(report)) {
        let _ = write_secure_state_file(&path, &json);
    }
}
