//! Engine internals of the `sentinel-engine` binary, one file per concern.
//! Items are re-exported flat so modules can use each other as they did when this
//! all lived in main.rs.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sentinel_engine::cve::{self, Advisory, Severity};
use sentinel_engine::subproc::{run_cmd_bounded, run_cmd_bounded_status};
use sentinel_engine::usb::{self, TrustStore, TrustVerdict, UsbFingerprint};
use sentinel_engine::{ai, kernel, net, sha256_hex};

mod ai_behavior;
mod auth;
mod badusb;
mod cve_radar;
mod daemon;
mod dns;
mod ghost_mac;
mod network;
mod notify;
mod opsec;
mod report;
mod state;
mod tripwire;
mod types;

pub(crate) use self::ai_behavior::*;
pub(crate) use self::auth::*;
pub(crate) use self::badusb::*;
pub(crate) use self::cve_radar::*;
pub(crate) use self::daemon::*;
pub(crate) use self::dns::*;
pub(crate) use self::ghost_mac::*;
pub(crate) use self::network::*;
pub(crate) use self::notify::*;
pub(crate) use self::opsec::*;
pub(crate) use self::report::*;
pub(crate) use self::state::*;
pub(crate) use self::tripwire::*;
pub(crate) use self::types::*;
