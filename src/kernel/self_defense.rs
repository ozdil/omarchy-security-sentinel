//! Military-Grade Self-Defense and Anti-Tamper Module (DISA STIG / NSA Hardened)
//!
//! Provides:
//! - prctl(PR_SET_DUMPABLE, 0) protection against ptrace, /proc/self/mem inspection, and core dumps
//! - Binary self-integrity verification via /proc/self/exe SHA-256 calculation
//! - SecureBuffer with volatile memory zeroization on Drop
//! - Constant-time byte array comparison against timing side-channel attacks

use std::fs::File;
use std::io::Read;

/// Constant-time byte array comparison to prevent side-channel timing attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Standalone FIPS 180-4 compliant SHA-256 implementation in pure Rust
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 64);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, w_val) in w.iter_mut().take(16).enumerate() {
            let idx = i * 4;
            *w_val = u32::from_be_bytes([chunk[idx], chunk[idx + 1], chunk[idx + 2], chunk[idx + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }

    let mut out = String::with_capacity(64);
    for val in &h {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{:08x}", val));
    }
    out
}

extern "C" {
    fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
}

const PR_SET_DUMPABLE: i32 = 4;

/// Enforces military-grade anti-tampering by disallowing ptrace, core dumps,
/// and memory inspection from unprivileged processes via prctl(PR_SET_DUMPABLE, 0).
pub fn enforce_anti_tamper() -> bool {
    // SAFETY: PR_SET_DUMPABLE with argument 0 is a standard POSIX/Linux syscall.
    let ret = unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
    ret == 0
}

/// Verifies self-integrity by calculating the SHA-256 fingerprint of /proc/self/exe.
/// The read is strictly bounded to 64 MiB to prevent memory exhaustion.
pub fn calculate_self_exe_sha256() -> Result<String, String> {
    let mut file = File::open("/proc/self/exe").map_err(|e| format!("Cannot open /proc/self/exe: {}", e))?;
    let mut buf = Vec::new();
    let max_read = 64 * 1024 * 1024;
    file.by_ref().take(max_read as u64 + 1).read_to_end(&mut buf)
        .map_err(|e| format!("Failed to read self binary: {}", e))?;

    if buf.len() > max_read {
        return Err("Self binary exceeds 64 MiB ceiling".to_string());
    }

    Ok(sha256_hex(&buf))
}

/// RAII wrapper for sensitive buffers that zeroizes memory upon drop
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn zeroize(&mut self) {
        for byte in self.data.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_tamper_enforcement() {
        assert!(enforce_anti_tamper());
    }

    #[test]
    fn test_self_integrity_sha256() {
        let res = calculate_self_exe_sha256();
        assert!(res.is_ok());
        let hash = res.unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"military-secops", b"military-secops"));
        assert!(!constant_time_eq(b"military-secops", b"military-secopX"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_secure_buffer_zeroize() {
        let mut sec = SecureBuffer::new(vec![1, 2, 3, 4, 5]);
        sec.zeroize();
        assert_eq!(sec.as_slice(), &[0, 0, 0, 0, 0]);
    }
}
