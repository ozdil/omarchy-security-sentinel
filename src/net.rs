//! `/proc/net/{tcp,udp}[6]` parsing and socket → process attribution.
//!
//! The kernel tables only carry a socket inode; the owning process is found by
//! resolving `/proc/<pid>/fd/*` links of the form `socket:[<inode>]`. Without root
//! only the user's own processes are readable, so sockets owned by other users
//! (system daemons) stay unattributed rather than guessed.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Descriptor ceiling per process; keeps one fd-heavy process from stalling a scan
const MAX_FDS_PER_PROCESS: usize = 16384;

pub const TCP_ESTABLISHED: u8 = 0x01;
pub const TCP_LISTEN: u8 = 0x0A;
/// UDP has no LISTEN state: a bound, unconnected socket reports TCP_CLOSE (07)
pub const UDP_UNCONNECTED: u8 = 0x07;

pub fn is_suspicious_port(port: u16) -> bool {
    matches!(port, 1337 | 4444 | 5555 | 6666 | 6667 | 9001 | 31337)
}

pub fn port_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS Resolver",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        631 => "CUPS Print",
        853 => "DoT Encrypted",
        993 => "IMAPS",
        995 => "POP3S",
        1337 => "Backdoor/C2",
        1883 => "MQTT",
        3000 => "Node/Web",
        3306 => "MySQL/MariaDB",
        4444 => "Metasploit C2",
        5173 => "Vite Dev",
        5432 => "PostgreSQL",
        5555 => "ADB/Trojan",
        6379 => "Redis Cache",
        6666 | 6667 => "IRC Botnet",
        8000 => "Dev Server",
        8080 => "HTTP Proxy",
        8443 => "HTTPS Alt",
        8844 => "Local Service",
        9001 => "Tor/Malware C2",
        27017 => "MongoDB",
        31337 => "Back Orifice",
        _ => "System Port",
    }
}

/// Decodes a `/proc/net` address field (`0100007F:115C`, or 32 hex digits for IPv6).
/// The kernel prints each 32-bit word of the address as a native-endian integer,
/// so `to_ne_bytes` recovers the network-order bytes on any host.
pub fn parse_ip_port(s: &str) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let word = |chunk: &str| u32::from_str_radix(chunk, 16).ok().map(u32::to_ne_bytes);
    match ip_hex.len() {
        8 => Some((Ipv4Addr::from(word(ip_hex)?).to_string(), port)),
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let w = word(ip_hex.get(i * 8..i * 8 + 8)?)?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&w);
            }
            let v6 = Ipv6Addr::from(bytes);
            // Dual-stack sockets show IPv4 peers as ::ffff:a.b.c.d; print them as IPv4
            let ip = match v6.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => v6.to_string(),
            };
            Some((ip, port))
        }
        _ => None,
    }
}

/// True for 0.0.0.0 / :: (reachable from every interface)
pub fn is_wildcard_address(ip: &str) -> bool {
    ip == "0.0.0.0" || ip == "::"
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub proto: &'static str,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

impl SocketEntry {
    /// Accepting connections (TCP LISTEN) or bound and waiting for datagrams (UDP)
    pub fn is_listener(&self) -> bool {
        match self.proto {
            "tcp" | "tcp6" => self.state == TCP_LISTEN,
            _ => self.state == UDP_UNCONNECTED && self.local_port != 0,
        }
    }

    pub fn is_established(&self) -> bool {
        self.state == TCP_ESTABLISHED
    }
}

/// Parses one data line of `/proc/net/{tcp,udp}[6]`:
/// `sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ...`
pub fn parse_proc_net_line(line: &str, proto: &'static str) -> Option<SocketEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }
    let (local_ip, local_port) = parse_ip_port(parts[1])?;
    let (remote_ip, remote_port) = parse_ip_port(parts[2])?;
    Some(SocketEntry {
        proto,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        state: u8::from_str_radix(parts[3], 16).ok()?,
        uid: parts[7].parse().ok()?,
        inode: parts[9].parse().ok()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketOwner {
    pub pid: i32,
    pub name: String,
}

/// Extracts the inode from an fd link target `socket:[12345]`
pub fn socket_inode_from_link(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Maps socket inode → owning process for every process whose fds are readable.
/// When a socket is shared (fork, SCM_RIGHTS) the lowest pid, usually the parent, wins.
pub fn socket_owners() -> HashMap<u64, SocketOwner> {
    socket_owners_in(Path::new("/proc"))
}

pub fn socket_owners_in(proc_root: &Path) -> HashMap<u64, SocketOwner> {
    let mut owners: HashMap<u64, SocketOwner> = HashMap::new();
    let Ok(entries) = fs::read_dir(proc_root) else {
        return owners;
    };
    let mut pids: Vec<i32> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();

    for pid in pids {
        let pid_dir = proc_root.join(pid.to_string());
        let Ok(fds) = fs::read_dir(pid_dir.join("fd")) else {
            continue; // other user's process, or it already exited
        };
        let mut name: Option<String> = None;
        for fd in fds.flatten().take(MAX_FDS_PER_PROCESS) {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(inode) = target.to_str().and_then(socket_inode_from_link) else {
                continue;
            };
            if owners.contains_key(&inode) {
                continue;
            }
            let name = name.get_or_insert_with(|| read_comm(&pid_dir)).clone();
            owners.insert(inode, SocketOwner { pid, name });
        }
    }
    owners
}

fn read_comm(pid_dir: &Path) -> String {
    let mut buf = String::new();
    if let Ok(f) = fs::File::open(pid_dir.join("comm")) {
        let _ = f.take(64).read_to_string(&mut buf);
    }
    // comm is attacker-controlled (prctl PR_SET_NAME); keep it printable and short
    buf.trim()
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | '&' | '"' | '\''))
        .take(32)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_port_v4_and_v6() {
        assert_eq!(
            parse_ip_port("0100007F:115C"),
            Some(("127.0.0.1".to_string(), 4444))
        );
        assert_eq!(
            parse_ip_port("00000000000000000000000000000000:0016"),
            Some(("::".to_string(), 22))
        );
        assert_eq!(
            parse_ip_port("00000000000000000000000001000000:0035"),
            Some(("::1".to_string(), 53))
        );
        // ::ffff:192.168.1.10 as printed by the kernel on x86_64
        assert_eq!(
            parse_ip_port("0000000000000000FFFF00000A01A8C0:01BB"),
            Some(("192.168.1.10".to_string(), 443))
        );
        // 2001:db8::1
        assert_eq!(
            parse_ip_port("B80D0120000000000000000001000000:0050"),
            Some(("2001:db8::1".to_string(), 80))
        );
        assert!(parse_ip_port("invalid").is_none());
        assert!(parse_ip_port("0100007F:GGGG").is_none());
        assert!(parse_ip_port("0100:0050").is_none());
    }

    #[test]
    fn test_parse_proc_net_line() {
        let line = "   0: 00000000:115C 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 54321 1 0000000000000000 100 0 0 10 0";
        let e = parse_proc_net_line(line, "tcp").unwrap();
        assert_eq!(e.local_ip, "0.0.0.0");
        assert_eq!(e.local_port, 4444);
        assert_eq!(e.uid, 1000);
        assert_eq!(e.inode, 54321);
        assert!(e.is_listener());
        assert!(!e.is_established());

        let udp = "  12: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   977        0 999 2 0000000000000000 0";
        assert!(parse_proc_net_line(udp, "udp").unwrap().is_listener());
        assert!(parse_proc_net_line("  sl  local_address", "tcp").is_none());
    }

    #[test]
    fn test_socket_inode_from_link() {
        assert_eq!(socket_inode_from_link("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode_from_link("pipe:[12345]"), None);
        assert_eq!(socket_inode_from_link("/dev/null"), None);
    }

    #[test]
    fn test_socket_owners_finds_own_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let content = fs::read_to_string("/proc/net/tcp").unwrap();
        let entry = content
            .lines()
            .skip(1)
            .filter_map(|l| parse_proc_net_line(l, "tcp"))
            .find(|e| e.local_port == port && e.is_listener())
            .expect("listener visible in /proc/net/tcp");
        let owners = socket_owners();
        let owner = owners.get(&entry.inode).expect("own socket attributed");
        assert_eq!(owner.pid, std::process::id() as i32);
    }

    #[test]
    fn test_suspicious_ports() {
        for p in [1337, 4444, 5555, 6666, 6667, 9001, 31337] {
            assert!(is_suspicious_port(p));
        }
        for p in [22, 53, 80, 443, 853, 8888] {
            assert!(!is_suspicious_port(p));
        }
        assert_eq!(port_service_name(4444), "Metasploit C2");
        assert!(is_wildcard_address("::"));
        assert!(!is_wildcard_address("::1"));
    }
}
