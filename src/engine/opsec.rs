//! Module 8: OpSec Cleaner (EXIF/metadata scrubbing).

use super::*;

pub(crate) fn check_opsec_cleaner() -> ModuleStatus {
    let items = vec![
        "Supported Formats: JPEG (EXIF / APP1-15), PNG (tEXt, zTXt, iTXt, eXIf)".to_string(),
        "Engine: In-memory lossless binary metadata & EXIF stripper".to_string(),
        "Drag & Drop: Drag any image from file manager onto this panel".to_string(),
        "Batch Mode: Click 'Scrub Downloads' to sanitize recent downloads".to_string(),
    ];

    ModuleStatus {
        id: "opsec".to_string(),
        name: "OpSec Metadata Scrubber".to_string(),
        status: Status::Ready,
        summary: "Lossless EXIF/PNG Sanitizer".to_string(),
        detail: "Drag & drop images or click to sanitize metadata".to_string(),
        is_toggleable: false,
        toggle_state: false,
        items,
    }
}

pub(crate) const MAX_IMAGE_SIZE: usize = 25 * 1024 * 1024; // 25 MiB cap

// Lossless JPEG & PNG cleaner with strict bounded I/O, no-follow descriptor binding, and atomic replacement
pub(crate) fn clean_file(path: &Path) -> Result<(), String> {
    // 1. Initial symlink and regular file verification
    let sym_meta =
        fs::symlink_metadata(path).map_err(|e| format!("Cannot read metadata: {}", e))?;
    if sym_meta.file_type().is_symlink() {
        return Err("Symlinks are strictly prohibited".to_string());
    }
    if !sym_meta.is_file() {
        return Err("Target is not a regular file".to_string());
    }
    if sym_meta.len() > MAX_IMAGE_SIZE as u64 {
        return Err(format!(
            "File exceeds maximum allowed size of {} bytes",
            MAX_IMAGE_SIZE
        ));
    }

    // 2. Open through held descriptor with O_NOFOLLOW
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("Failed to open file safely with O_NOFOLLOW: {}", e))?;

    // 3. Re-verify attributes on the held descriptor
    let fd_meta = file
        .metadata()
        .map_err(|e| format!("Failed to read descriptor metadata: {}", e))?;
    if !fd_meta.is_file() {
        return Err("Descriptor is not a regular file".to_string());
    }
    if fd_meta.len() > MAX_IMAGE_SIZE as u64 {
        return Err(format!(
            "Descriptor file size exceeds {} bytes",
            MAX_IMAGE_SIZE
        ));
    }

    // SAFETY: getuid returns the real UID of the running process
    unsafe {
        extern "C" {
            fn getuid() -> u32;
        }
        if fd_meta.uid() != getuid() {
            return Err("File is not owned by current user".to_string());
        }
    }

    // 4. Bounded read
    let mut data = Vec::with_capacity(fd_meta.len() as usize);
    let mut handle = (&mut file).take((MAX_IMAGE_SIZE + 1) as u64);
    handle
        .read_to_end(&mut data)
        .map_err(|e| format!("Read failed: {}", e))?;
    if data.len() > MAX_IMAGE_SIZE {
        return Err("Read data exceeded maximum image buffer limit".to_string());
    }

    // 5. Lossless metadata stripping
    let png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    let out = if data.len() >= 4 && data[0] == 0xFF && data[1] == 0xD8 {
        strip_jpeg_metadata(&data)?
    } else if data.len() >= 8 && data[..8] == png_header {
        strip_png_metadata(&data)
    } else {
        return Err("Unsupported image format or invalid header".to_string());
    };

    // Close descriptor before replacing file
    drop(file);

    // 6. Same-directory atomic replacement: write to .tmp_clean_..., verify, sync_all, rename
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_path = parent.join(format!(".tmp_clean_{}_{}", std::process::id(), nanos));

    let orig_mode = fd_meta.mode() & 0o777;
    let target_mode = if orig_mode != 0 { orig_mode } else { 0o600 };

    struct TempFileGuard<'a> {
        path: &'a Path,
        active: bool,
    }
    impl<'a> Drop for TempFileGuard<'a> {
        fn drop(&mut self) {
            if self.active {
                let _ = fs::remove_file(self.path);
            }
        }
    }

    let mut guard = TempFileGuard {
        path: &tmp_path,
        active: true,
    };

    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(target_mode)
        .custom_flags(O_NOFOLLOW)
        .open(&tmp_path)
        .map_err(|e| format!("Failed to create temporary clean file: {}", e))?;

    let _ = tmp_file.set_permissions(fs::Permissions::from_mode(target_mode));

    tmp_file
        .write_all(&out)
        .map_err(|e| format!("Failed to write cleaned image bytes: {}", e))?;

    tmp_file
        .sync_all()
        .map_err(|e| format!("Failed to sync cleaned file to disk: {}", e))?;

    let tmp_meta = tmp_file
        .metadata()
        .map_err(|e| format!("Failed to read temp metadata: {}", e))?;
    if tmp_meta.len() != out.len() as u64 {
        return Err("Written bytes verification mismatch".to_string());
    }

    drop(tmp_file);

    // Re-verify target path is still regular file and not replaced with symlink prior to rename
    let pre_rename_meta = fs::symlink_metadata(path)
        .map_err(|e| format!("Cannot verify target prior to rename: {}", e))?;
    if pre_rename_meta.file_type().is_symlink() {
        return Err("Target path changed to symlink during cleaning".to_string());
    }

    fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to atomically replace image: {}", e))?;

    guard.active = false;

    Ok(())
}

/// Removes EXIF/XMP/comment segments from a JPEG without re-encoding, in every scan
/// of a progressive JPEG, and drops everything after the end-of-image marker.
///
/// Kept on purpose: APP0 (JFIF), APP2 ICC_PROFILE (colour management) and APP14
/// "Adobe" (colour transform; dropping it corrupts CMYK/YCCK images). Malformed or
/// truncated segment headers abort with an error instead of producing a truncated
/// file that would then atomically replace the original.
pub(crate) fn strip_jpeg_metadata(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&[0xFF, 0xD8]);
    let mut idx = 2;
    loop {
        if idx >= data.len() {
            return Err("Truncated JPEG: no start-of-scan marker found".to_string());
        }
        if data[idx] != 0xFF {
            return Err(format!("Malformed JPEG: expected marker at offset {}", idx));
        }
        while idx < data.len() && data[idx] == 0xFF {
            idx += 1;
        }
        if idx >= data.len() {
            return Err("Truncated JPEG marker".to_string());
        }
        let marker = data[idx];
        idx += 1;
        match marker {
            // End of image. Anything after it is dropped: phones append a second
            // image (MPF) with its own EXIF/GPS there, and vendors add trailers.
            0xD9 => {
                out.extend_from_slice(&[0xFF, 0xD9]);
                return Ok(out);
            }
            0xDA => {
                // Start of scan: copy the header, then the entropy-coded data up to the
                // next real marker. Progressive JPEGs have more segments (and possibly
                // APPn/COM) between scans, so parsing continues instead of copying the
                // rest verbatim.
                if idx + 2 > data.len() {
                    return Err("Truncated JPEG scan header".to_string());
                }
                let len = ((data[idx] as usize) << 8) | (data[idx + 1] as usize);
                if len < 2 || idx + len > data.len() {
                    return Err("Malformed JPEG scan header length".to_string());
                }
                out.extend_from_slice(&[0xFF, 0xDA]);
                out.extend_from_slice(&data[idx..idx + len]);
                idx += len;
                let start = idx;
                while idx + 1 < data.len() {
                    if data[idx] != 0xFF {
                        idx += 1;
                        continue;
                    }
                    match data[idx + 1] {
                        // Stuffed 0xFF byte or restart marker: still scan data
                        0x00 | 0xD0..=0xD7 => idx += 2,
                        // Fill byte before a marker
                        0xFF => idx += 1,
                        _ => break,
                    }
                }
                if idx + 1 >= data.len() {
                    // No EOI: keep the scan data as it was
                    out.extend_from_slice(&data[start..]);
                    return Ok(out);
                }
                out.extend_from_slice(&data[start..idx]);
                continue;
            }
            // Standalone markers carry no length field
            0x01 | 0xD0..=0xD7 => {
                out.extend_from_slice(&[0xFF, marker]);
                continue;
            }
            _ => {}
        }
        if idx + 2 > data.len() {
            return Err("Truncated JPEG segment length".to_string());
        }
        let len = ((data[idx] as usize) << 8) | (data[idx + 1] as usize);
        if len < 2 || idx + len > data.len() {
            return Err(format!("Malformed JPEG segment 0x{:02X} length", marker));
        }
        let payload = &data[idx + 2..idx + len];
        let keep_colour_info = (marker == 0xE2 && payload.starts_with(b"ICC_PROFILE\0"))
            || (marker == 0xEE && payload.starts_with(b"Adobe"));
        let is_meta = ((0xE1..=0xEF).contains(&marker) || marker == 0xFE) && !keep_colour_info;
        if !is_meta {
            out.extend_from_slice(&[0xFF, marker]);
            out.extend_from_slice(&data[idx..idx + len]);
        }
        idx += len;
    }
}

/// Removes textual and EXIF chunks (tEXt, zTXt, iTXt, eXIf) from a PNG.
pub(crate) fn strip_png_metadata(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&data[..8]);
    let mut idx = 8;
    while idx + 12 <= data.len() {
        let length =
            u32::from_be_bytes([data[idx], data[idx + 1], data[idx + 2], data[idx + 3]]) as usize;
        let chunk_type = &data[idx + 4..idx + 8];
        let total_chunk_len = 12usize.saturating_add(length);
        if idx.saturating_add(total_chunk_len) > data.len() {
            out.extend_from_slice(&data[idx..]);
            return out;
        }
        let is_meta = matches!(chunk_type, b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf");
        if !is_meta {
            out.extend_from_slice(&data[idx..idx + total_chunk_len]);
        }
        idx += total_chunk_len;
    }
    // Keep any trailing bytes that do not form a full chunk instead of dropping them
    out.extend_from_slice(&data[idx..]);
    out
}

pub(crate) fn scrub_downloads() -> usize {
    let ddir = dirs_downloads();
    let mut cleaned = 0;
    if let Ok(entries) = fs::read_dir(ddir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = fs::symlink_metadata(&p) {
                if !meta.file_type().is_symlink() && meta.is_file() {
                    if let Some(ext) = p.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if (ext_str == "jpg" || ext_str == "jpeg" || ext_str == "png")
                            && clean_file(&p).is_ok()
                        {
                            cleaned += 1;
                        }
                    }
                }
            }
        }
    }
    cleaned
}

pub(crate) fn dirs_downloads() -> PathBuf {
    let home = env::var("HOME").unwrap_or_default();
    Path::new(&home).join("Downloads")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let len = (payload.len() + 2) as u16;
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn test_jpeg_metadata_between_scans_and_after_eoi_is_removed() {
        let mut jpg = vec![0xFF, 0xD8];
        jpg.extend(seg(0xE0, b"JFIF\0\x01\x01"));
        jpg.extend(seg(0xE1, b"Exif\0\0GPS-PRIMARY"));
        jpg.extend(seg(0xC2, b"\x08\x00\x10\x00\x10\x01\x01\x11\x00"));
        jpg.extend(seg(0xDA, b"\x01\x01\x00\x00\x3f\x00"));
        jpg.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]);
        // Progressive: metadata between the scans
        jpg.extend(seg(0xE1, b"Exif\0\0GPS-BETWEEN"));
        jpg.extend(seg(0xFE, b"comment"));
        jpg.extend(seg(0xDA, b"\x01\x01\x00\x00\x3f\x00"));
        jpg.extend_from_slice(&[0x78, 0x9A]);
        jpg.extend_from_slice(&[0xFF, 0xD9]);
        // MPF secondary image with its own EXIF after EOI
        jpg.extend_from_slice(&[0xFF, 0xD8]);
        jpg.extend(seg(0xE1, b"Exif\0\0GPS-SECONDARY"));
        jpg.extend_from_slice(&[0xFF, 0xD9]);

        let out = strip_jpeg_metadata(&jpg).unwrap();
        let has = |needle: &[u8]| out.windows(needle.len()).any(|w| w == needle);
        assert!(!has(b"Exif"));
        assert!(!has(b"comment"));
        assert!(has(b"JFIF"));
        // Scan data (with its stuffed byte and restart marker) survives intact
        assert!(has(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]));
        assert!(has(&[0x78, 0x9A, 0xFF, 0xD9]));
        assert!(out.ends_with(&[0xFF, 0xD9]));
    }
}
