//! USB device fingerprinting for the BadUSB trust baseline (`trusted_usb.json`).
//!
//! A VID:PID pair alone is trivially cloned by keystroke injectors (Rubber Ducky,
//! O.MG cables, Digispark). A fingerprint additionally pins:
//! - the device serial number, when the device reports one, and
//! - the sorted set of interface class triplets (`class:subclass:protocol`).
//!
//! The interface set is what catches the classic attack: a device that clones a
//! trusted flash drive's VID:PID but also exposes a HID keyboard interface no longer
//! matches its baseline entry. Port paths are deliberately not pinned, so moving a
//! trusted device to another port does not raise an alert.
//!
//! File format v2: `{"version": 2, "devices": [UsbFingerprint, ...]}`.
//! The legacy v1 format (a JSON array of `"vid:pid"` strings) is still read: such
//! entries match on VID:PID only until the device is seen again, at which point
//! [`TrustStore::upgrade_legacy`] fills in its serial and interface set.

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

pub const TRUST_STORE_VERSION: u32 = 2;

/// USB interface class code for Human Interface Devices (keyboards, mice, ...)
const HID_CLASS: &str = "03";
/// USB interface class code for Mass Storage
const MASS_STORAGE_CLASS: &str = "08";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbFingerprint {
    pub vid: String,
    pub pid: String,
    /// `None` when the device reports no serial (or for legacy v1 entries)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// Sorted, de-duplicated `class:subclass:protocol` triplets. `None` only for
    /// legacy v1 entries that have not been upgraded yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interfaces: Option<Vec<String>>,
    /// Human-readable product name, informational only (never used for matching)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
}

/// How a connected device relates to the baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustVerdict {
    Trusted,
    /// No baseline entry with this VID:PID at all
    Unknown,
    /// Same VID:PID as a trusted device but a different serial or interface set
    FingerprintMismatch {
        /// The device exposes a HID interface its baseline entry did not have
        gained_hid: bool,
    },
}

impl UsbFingerprint {
    pub fn id(&self) -> String {
        format!("{}:{}", self.vid, self.pid)
    }

    pub fn is_legacy(&self) -> bool {
        self.interfaces.is_none()
    }

    pub fn has_class(&self, class: &str) -> bool {
        self.interfaces
            .as_ref()
            .is_some_and(|ifs| ifs.iter().any(|i| i.split(':').next() == Some(class)))
    }

    pub fn is_hid(&self) -> bool {
        self.has_class(HID_CLASS)
    }

    /// HID + mass storage on one device is the typical "USB stick that types" profile.
    pub fn is_hid_storage_composite(&self) -> bool {
        self.is_hid() && self.has_class(MASS_STORAGE_CLASS)
    }

    fn same_model(&self, other: &UsbFingerprint) -> bool {
        self.vid.eq_ignore_ascii_case(&other.vid) && self.pid.eq_ignore_ascii_case(&other.pid)
    }

    /// Does this baseline entry vouch for `device`? Fields the entry does not know
    /// (legacy entries, devices without serial) are not required to match.
    pub fn matches(&self, device: &UsbFingerprint) -> bool {
        if !self.same_model(device) {
            return false;
        }
        if let Some(serial) = &self.serial {
            if device.serial.as_ref() != Some(serial) {
                return false;
            }
        }
        if let Some(ifs) = &self.interfaces {
            if device.interfaces.as_ref() != Some(ifs) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustStore {
    pub version: u32,
    pub devices: Vec<UsbFingerprint>,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            version: TRUST_STORE_VERSION,
            devices: Vec::new(),
        }
    }
}

impl TrustStore {
    /// Parses v2 files and legacy v1 `["vid:pid", ...]` arrays. Returns `None` for
    /// anything else, which callers must treat as a corrupt baseline.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if let Ok(store) = serde_json::from_slice::<TrustStore>(bytes) {
            if store.version == TRUST_STORE_VERSION {
                return Some(store);
            }
            return None;
        }
        let legacy: Vec<String> = serde_json::from_slice(bytes).ok()?;
        let mut devices = Vec::new();
        for id in legacy {
            let (vid, pid) = id.split_once(':')?;
            devices.push(UsbFingerprint {
                vid: vid.trim().to_string(),
                pid: pid.trim().to_string(),
                serial: None,
                interfaces: None,
                product: None,
            });
        }
        Some(Self {
            version: TRUST_STORE_VERSION,
            devices,
        })
    }

    pub fn to_json(&self) -> Option<Vec<u8>> {
        serde_json::to_vec_pretty(self).ok()
    }

    pub fn verdict(&self, device: &UsbFingerprint) -> TrustVerdict {
        if self.devices.iter().any(|e| e.matches(device)) {
            return TrustVerdict::Trusted;
        }
        let same_model: Vec<&UsbFingerprint> = self
            .devices
            .iter()
            .filter(|e| e.same_model(device))
            .collect();
        if same_model.is_empty() {
            return TrustVerdict::Unknown;
        }
        let gained_hid = device.is_hid() && same_model.iter().all(|e| !e.is_hid());
        TrustVerdict::FingerprintMismatch { gained_hid }
    }

    /// Replaces a legacy (VID:PID-only) entry with the full fingerprint of a
    /// connected device it vouches for. Returns true when the store changed.
    ///
    /// Only the first connected device per legacy entry upgrades it, and only when
    /// no full entry already covers that device, so the migration never widens trust.
    pub fn upgrade_legacy(&mut self, device: &UsbFingerprint) -> bool {
        if device.is_legacy()
            || self
                .devices
                .iter()
                .any(|e| !e.is_legacy() && e.matches(device))
        {
            return false;
        }
        if let Some(entry) = self
            .devices
            .iter_mut()
            .find(|e| e.is_legacy() && e.matches(device))
        {
            *entry = device.clone();
            return true;
        }
        false
    }

    /// Adds `device` unless an entry already vouches for it. Returns true when added.
    pub fn trust(&mut self, device: &UsbFingerprint) -> bool {
        if self.upgrade_legacy(device) {
            return true;
        }
        if self.devices.iter().any(|e| e.matches(device)) {
            return false;
        }
        self.devices.push(device.clone());
        true
    }
}

fn read_attr(path: &Path, max: u64) -> Option<String> {
    let mut buf = String::new();
    File::open(path)
        .ok()?
        .take(max)
        .read_to_string(&mut buf)
        .ok()?;
    let value = buf.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Keeps identifiers to printable ASCII so a hostile descriptor cannot smuggle
/// control characters or markup into the JSON baseline or the UI.
fn clean_identifier(raw: &str, max_len: usize) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .filter(|c| !matches!(c, '<' | '>' | '&' | '"' | '\''))
        .take(max_len)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Reads a device fingerprint from its sysfs directory (`/sys/bus/usb/devices/<bus_id>`).
/// Returns `None` for interface directories and other non-device entries.
pub fn read_fingerprint(dev_dir: &Path) -> Option<UsbFingerprint> {
    let vid = clean_identifier(&read_attr(&dev_dir.join("idVendor"), 16)?, 8);
    let pid = clean_identifier(&read_attr(&dev_dir.join("idProduct"), 16)?, 8);
    let serial = read_attr(&dev_dir.join("serial"), 256)
        .map(|s| clean_identifier(&s, 128))
        .filter(|s| !s.is_empty());
    let product = read_attr(&dev_dir.join("product"), 512)
        .map(|s| clean_identifier(&s, 64))
        .filter(|s| !s.is_empty());

    // Interface directories are named "<bus_id>:<config>.<interface>"
    let bus_id = dev_dir.file_name()?.to_string_lossy().to_string();
    let prefix = format!("{}:", bus_id);
    let mut interfaces = Vec::new();
    if let Ok(entries) = fs::read_dir(dev_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with(&prefix) {
                continue;
            }
            let ip = entry.path();
            let class = read_attr(&ip.join("bInterfaceClass"), 8);
            let sub = read_attr(&ip.join("bInterfaceSubClass"), 8);
            let proto = read_attr(&ip.join("bInterfaceProtocol"), 8);
            if let (Some(c), Some(s), Some(p)) = (class, sub, proto) {
                interfaces.push(clean_identifier(&format!("{}:{}:{}", c, s, p), 16));
            }
        }
    }
    interfaces.sort();
    interfaces.dedup();

    Some(UsbFingerprint {
        vid,
        pid,
        serial,
        interfaces: Some(interfaces),
        product,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(vid: &str, pid: &str, serial: Option<&str>, ifs: &[&str]) -> UsbFingerprint {
        UsbFingerprint {
            vid: vid.to_string(),
            pid: pid.to_string(),
            serial: serial.map(String::from),
            interfaces: Some(ifs.iter().map(|s| s.to_string()).collect()),
            product: None,
        }
    }

    #[test]
    fn test_parse_legacy_and_v2() {
        let legacy = TrustStore::parse(br#"["046d:c52b","0781:5567"]"#).unwrap();
        assert_eq!(legacy.devices.len(), 2);
        assert!(legacy.devices.iter().all(|d| d.is_legacy()));

        let v2 = TrustStore {
            version: 2,
            devices: vec![fp("0781", "5567", Some("ABC"), &["08:06:50"])],
        };
        let round = TrustStore::parse(&v2.to_json().unwrap()).unwrap();
        assert_eq!(round, v2);

        assert!(TrustStore::parse(b"not json").is_none());
        assert!(TrustStore::parse(br#"["no-colon"]"#).is_none());
        assert!(TrustStore::parse(br#"{"version":99,"devices":[]}"#).is_none());
    }

    #[test]
    fn test_cloned_vid_pid_with_extra_hid_interface_is_flagged() {
        let store = TrustStore {
            version: 2,
            devices: vec![fp("0781", "5567", Some("ABC"), &["08:06:50"])],
        };
        // Genuine stick
        assert_eq!(
            store.verdict(&fp("0781", "5567", Some("ABC"), &["08:06:50"])),
            TrustVerdict::Trusted
        );
        // Same VID:PID and serial, but now also a keyboard
        let ducky = fp("0781", "5567", Some("ABC"), &["03:01:01", "08:06:50"]);
        assert!(ducky.is_hid_storage_composite());
        assert_eq!(
            store.verdict(&ducky),
            TrustVerdict::FingerprintMismatch { gained_hid: true }
        );
        // Same model, different serial
        assert_eq!(
            store.verdict(&fp("0781", "5567", Some("XYZ"), &["08:06:50"])),
            TrustVerdict::FingerprintMismatch { gained_hid: false }
        );
        assert_eq!(
            store.verdict(&fp("1234", "5678", None, &["03:01:01"])),
            TrustVerdict::Unknown
        );
    }

    #[test]
    fn test_legacy_entries_upgrade_without_widening_trust() {
        let mut store = TrustStore::parse(br#"["046d:c52b"]"#).unwrap();
        let receiver = fp("046d", "c52b", None, &["03:01:01", "03:01:02"]);
        assert_eq!(store.verdict(&receiver), TrustVerdict::Trusted);
        assert!(store.upgrade_legacy(&receiver));
        assert_eq!(store.devices, vec![receiver.clone()]);
        // A second unit with a different interface set is no longer covered
        let other = fp("046d", "c52b", None, &["03:01:01", "03:01:02", "08:06:50"]);
        assert!(!store.upgrade_legacy(&other));
        assert!(matches!(
            store.verdict(&other),
            TrustVerdict::FingerprintMismatch { .. }
        ));
    }

    #[test]
    fn test_trust_is_idempotent() {
        let mut store = TrustStore::default();
        let kb = fp("04d9", "0006", None, &["03:01:01"]);
        assert!(store.trust(&kb));
        assert!(!store.trust(&kb));
        assert_eq!(store.devices.len(), 1);
    }

    #[test]
    fn test_read_fingerprint_from_sysfs_layout() {
        let root = std::env::temp_dir().join(format!("sentinel_usb_fp_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let dev = root.join("1-2");
        fs::create_dir_all(dev.join("1-2:1.1")).unwrap();
        fs::create_dir_all(dev.join("1-2:1.0")).unwrap();
        fs::write(dev.join("idVendor"), "0781\n").unwrap();
        fs::write(dev.join("idProduct"), "5567\n").unwrap();
        fs::write(dev.join("serial"), "4C53\x1b[31m<x>\n").unwrap();
        fs::write(dev.join("product"), "Cruzer Blade\n").unwrap();
        for (i, (c, s, p)) in [("08", "06", "50"), ("03", "01", "01")].iter().enumerate() {
            let ifd = dev.join(format!("1-2:1.{}", i));
            fs::write(ifd.join("bInterfaceClass"), format!("{}\n", c)).unwrap();
            fs::write(ifd.join("bInterfaceSubClass"), format!("{}\n", s)).unwrap();
            fs::write(ifd.join("bInterfaceProtocol"), format!("{}\n", p)).unwrap();
        }

        let got = read_fingerprint(&dev).unwrap();
        assert_eq!(got.id(), "0781:5567");
        assert_eq!(got.serial.as_deref(), Some("4C53[31mx"));
        assert_eq!(got.product.as_deref(), Some("Cruzer Blade"));
        assert_eq!(
            got.interfaces,
            Some(vec!["03:01:01".to_string(), "08:06:50".to_string()])
        );
        assert!(got.is_hid_storage_composite());

        // Interface directories are not devices
        assert!(read_fingerprint(&dev.join("1-2:1.0")).is_none());
        let _ = fs::remove_dir_all(&root);
    }
}
