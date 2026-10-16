//! Kernel uevent listener (NETLINK_KOBJECT_UEVENT) for instant USB hot-plug detection.
//!
//! Polling every 20 s leaves a keystroke injector plenty of time to type its payload;
//! a uevent arrives within milliseconds of the device enumerating. Unprivileged
//! processes may join the kernel uevent multicast group, so no extra rights are needed.

use std::time::Duration;

const AF_NETLINK: i32 = 16;
const SOCK_DGRAM: i32 = 2;
const SOCK_CLOEXEC: i32 = 0o2000000;
const NETLINK_KOBJECT_UEVENT: i32 = 15;
/// Multicast group 1 carries raw kernel uevents (group 2 is udevd's re-broadcast)
const KERNEL_UEVENT_GROUP: u32 = 1;
const POLLIN: i16 = 0x0001;
const MSG_DONTWAIT: i32 = 0x40;

#[repr(C)]
struct SockaddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn bind(fd: i32, addr: *const SockaddrNl, len: u32) -> i32;
    fn recv(fd: i32, buf: *mut u8, len: usize, flags: i32) -> isize;
    fn poll(fds: *mut PollFd, nfds: usize, timeout: i32) -> i32;
    fn close(fd: i32) -> i32;
}

/// A parsed kernel uevent (only the fields the engine cares about).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UEvent {
    pub action: String,
    pub devpath: String,
    pub subsystem: String,
    pub devtype: String,
}

impl UEvent {
    /// USB device or interface being added/bound: the fingerprint may have changed.
    pub fn is_usb_arrival(&self) -> bool {
        self.subsystem == "usb"
            && matches!(self.action.as_str(), "add" | "bind" | "change")
            && matches!(self.devtype.as_str(), "usb_device" | "usb_interface")
    }

    pub fn is_usb_removal(&self) -> bool {
        self.subsystem == "usb" && self.action == "remove" && self.devtype == "usb_device"
    }
}

/// Parses one kernel uevent datagram: `"action@devpath\0KEY=VALUE\0..."`.
/// Returns `None` for udevd-formatted ("libudev" header) or malformed messages.
pub fn parse_uevent(buf: &[u8]) -> Option<UEvent> {
    let mut parts = buf.split(|&b| b == 0).filter(|p| !p.is_empty());
    let header = std::str::from_utf8(parts.next()?).ok()?;
    if !header.contains('@') {
        return None;
    }
    let mut ev = UEvent::default();
    for part in parts {
        let Ok(kv) = std::str::from_utf8(part) else {
            continue;
        };
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        match k {
            "ACTION" => ev.action = v.to_string(),
            "DEVPATH" => ev.devpath = v.to_string(),
            "SUBSYSTEM" => ev.subsystem = v.to_string(),
            "DEVTYPE" => ev.devtype = v.to_string(),
            _ => {}
        }
    }
    if ev.action.is_empty() {
        return None;
    }
    Some(ev)
}

pub struct UEventSocket {
    fd: i32,
}

impl UEventSocket {
    pub fn open() -> std::io::Result<Self> {
        // SAFETY: plain socket(2) call with constant arguments
        let fd = unsafe {
            socket(
                AF_NETLINK,
                SOCK_DGRAM | SOCK_CLOEXEC,
                NETLINK_KOBJECT_UEVENT,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let addr = SockaddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0, // let the kernel assign a unique port id
            nl_groups: KERNEL_UEVENT_GROUP,
        };
        // SAFETY: addr is a valid sockaddr_nl for the lifetime of the call
        let ret = unsafe { bind(fd, &addr, std::mem::size_of::<SockaddrNl>() as u32) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // SAFETY: fd was just created and is not used afterwards
            unsafe { close(fd) };
            return Err(err);
        }
        Ok(Self { fd })
    }

    /// Waits up to `timeout` for events and returns everything currently queued.
    pub fn wait(&self, timeout: Duration) -> Vec<UEvent> {
        let mut events = Vec::new();
        let mut pfd = PollFd {
            fd: self.fd,
            events: POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: one valid pollfd
        if unsafe { poll(&mut pfd, 1, ms) } <= 0 {
            return events;
        }
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            // SAFETY: buf is valid for buf.len() bytes
            let n = unsafe { recv(self.fd, buf.as_mut_ptr(), buf.len(), MSG_DONTWAIT) };
            if n <= 0 {
                break;
            }
            if let Some(ev) = parse_uevent(&buf[..n as usize]) {
                events.push(ev);
            }
        }
        events
    }
}

impl Drop for UEventSocket {
    fn drop(&mut self) {
        // SAFETY: fd is owned by self and closed exactly once
        unsafe { close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kernel_uevent() {
        let msg = b"add@/devices/pci0000:00/0000:00:14.0/usb1/1-2\0ACTION=add\0DEVPATH=/devices/pci0000:00/0000:00:14.0/usb1/1-2\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0PRODUCT=781/5567/100\0SEQNUM=4242\0";
        let ev = parse_uevent(msg).unwrap();
        assert_eq!(ev.action, "add");
        assert_eq!(ev.subsystem, "usb");
        assert_eq!(ev.devtype, "usb_device");
        assert!(ev.is_usb_arrival());
        assert!(!ev.is_usb_removal());

        let iface =
            b"bind@/devices/x/1-2/1-2:1.0\0ACTION=bind\0SUBSYSTEM=usb\0DEVTYPE=usb_interface\0";
        assert!(parse_uevent(iface).unwrap().is_usb_arrival());

        let net = b"add@/devices/virtual/net/veth0\0ACTION=add\0SUBSYSTEM=net\0";
        assert!(!parse_uevent(net).unwrap().is_usb_arrival());

        // udevd re-broadcasts start with a "libudev" magic header, not action@devpath
        assert!(parse_uevent(b"libudev\0\xfe\xed\xca\xfe").is_none());
        assert!(parse_uevent(b"").is_none());
    }

    #[test]
    fn test_socket_opens_and_times_out() {
        // Some sandboxes forbid netlink sockets; only assert when it can be opened
        if let Ok(sock) = UEventSocket::open() {
            let _ = sock.wait(Duration::from_millis(10));
        }
    }
}
