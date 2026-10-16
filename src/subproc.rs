use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

const POLLIN: i16 = 0x0001;
const POLLHUP: i16 = 0x0010;
const POLLERR: i16 = 0x0008;

const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const O_NONBLOCK: i32 = 2048; // 0o4000 on Linux

extern "C" {
    fn poll(fds: *mut PollFd, nfds: usize, timeout: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
}

/// Strictly reaps a process group:
/// 1. Sends SIGTERM (15) to -pid
/// 2. Waits 5-10ms
/// 3. Sends SIGKILL (9) to -pid to eliminate any surviving processes
/// 4. Waits on direct child to prevent zombies
pub fn reap_process_group(child: &mut std::process::Child, pid: i32) {
    if pid > 1 {
        // SAFETY: kill(-pid, 15) sends SIGTERM to the process group with valid PID.
        unsafe {
            kill(-pid, 15);
        }
        std::thread::sleep(Duration::from_millis(5));
        // SAFETY: kill(-pid, 9) sends SIGKILL to the process group with valid PID.
        unsafe {
            kill(-pid, 9);
        }
    }
    let _ = child.wait();
}

/// Kills a process group unconditionally without needing the Child struct
#[allow(dead_code)]
pub fn kill_process_group(pid: i32) {
    if pid > 1 {
        // SAFETY: kill(-pid, 15) sends SIGTERM to the process group.
        unsafe {
            kill(-pid, 15);
        }
        std::thread::sleep(Duration::from_millis(8));
        // SAFETY: kill(-pid, 9) sends SIGKILL to the process group.
        unsafe {
            kill(-pid, 9);
        }
    }
}

pub struct ProcessGroupGuard<'a> {
    pub child: &'a mut std::process::Child,
    pub pid: i32,
    pub active: bool,
}

impl<'a> Drop for ProcessGroupGuard<'a> {
    fn drop(&mut self) {
        if self.active {
            reap_process_group(self.child, self.pid);
        }
    }
}

/// Executes an isolated subprocess with:
/// - cmd.process_group(0)
/// - Non-blocking I/O via fcntl O_NONBLOCK
/// - Bounded polling loop via POSIX poll()
/// - Monotonic deadline enforcement
/// - Maximum output buffer caps
/// - Clean environment with whitelisted variables
///
/// Returns stdout only when the command exits successfully (status 0).
pub fn run_cmd_bounded(
    cmd_path: &str,
    args: &[&str],
    extra_envs: &[(&str, &str)],
    deadline: Instant,
    max_output_bytes: usize,
) -> Option<Vec<u8>> {
    match run_cmd_bounded_status(cmd_path, args, extra_envs, deadline, max_output_bytes) {
        Some((0, out)) => Some(out),
        _ => None,
    }
}

/// Same isolation guarantees as [`run_cmd_bounded`], but also returns the exit code
/// so callers can distinguish "ran and reported a condition" (e.g. `checkupdates`
/// exiting 2 for "no updates") from spawn failures, timeouts, or output overruns,
/// which all yield `None`. A process killed by a signal reports exit code -1.
pub fn run_cmd_bounded_status(
    cmd_path: &str,
    args: &[&str],
    extra_envs: &[(&str, &str)],
    deadline: Instant,
    max_output_bytes: usize,
) -> Option<(i32, Vec<u8>)> {
    if Instant::now() >= deadline {
        return None;
    }

    let mut cmd = Command::new(cmd_path);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    for (k, v) in extra_envs {
        cmd.env(k, v);
    }

    cmd.process_group(0);

    let mut child = cmd.spawn().ok()?;
    let pid = child.id() as i32;
    let mut stdout = child.stdout.take()?;
    let raw_fd = stdout.as_raw_fd();

    // SAFETY: F_GETFL and F_SETFL are standard POSIX fcntl operations on a valid pipe file descriptor.
    unsafe {
        let flags = fcntl(raw_fd, F_GETFL, 0);
        if flags >= 0 {
            let _ = fcntl(raw_fd, F_SETFL, flags | O_NONBLOCK);
        }
    }

    let mut guard = ProcessGroupGuard {
        child: &mut child,
        pid,
        active: true,
    };

    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut stdout_closed = false;
    let mut direct_child_exited = false;
    let mut exit_code = -1;
    let mut overrun = false;
    let mut failed = false;

    loop {
        if Instant::now() >= deadline {
            break;
        }

        if !direct_child_exited {
            match guard.child.try_wait() {
                Ok(Some(status)) => {
                    direct_child_exited = true;
                    exit_code = status.code().unwrap_or(-1);
                }
                Ok(None) => {}
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }

        if direct_child_exited && stdout_closed {
            break;
        }

        if stdout_closed {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5).min(remaining));
            continue;
        }

        let now = Instant::now();
        let remaining_ms =
            (deadline.saturating_duration_since(now).as_millis().min(50) as i32).max(1);
        let mut pfd = PollFd {
            fd: raw_fd,
            events: POLLIN | POLLHUP | POLLERR,
            revents: 0,
        };

        // SAFETY: poll() is called with a valid pointer to PollFd and 1 descriptor.
        let ret = unsafe { poll(&mut pfd, 1, remaining_ms) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            failed = true;
            break;
        } else if ret == 0 {
            continue;
        }

        if pfd.revents & POLLIN != 0 {
            loop {
                match stdout.read(&mut chunk) {
                    Ok(0) => {
                        stdout_closed = true;
                        break;
                    }
                    Ok(n) => {
                        if buffer.len() + n > max_output_bytes {
                            let take = max_output_bytes.saturating_sub(buffer.len());
                            buffer.extend_from_slice(&chunk[..take]);
                            overrun = true;
                            break;
                        }
                        buffer.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        continue;
                    }
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            if overrun || failed {
                break;
            }
        }

        if pfd.revents & (POLLHUP | POLLERR) != 0 {
            loop {
                match stdout.read(&mut chunk) {
                    Ok(0) => {
                        break;
                    }
                    Ok(n) => {
                        if buffer.len() + n > max_output_bytes {
                            let take = max_output_bytes.saturating_sub(buffer.len());
                            buffer.extend_from_slice(&chunk[..take]);
                            overrun = true;
                            break;
                        }
                        buffer.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        continue;
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
            stdout_closed = true;
            if overrun {
                break;
            }
        }
    }

    if overrun || failed || !direct_child_exited || Instant::now() >= deadline {
        return None;
    }

    guard.active = false;
    reap_process_group(guard.child, guard.pid);

    Some((exit_code, buffer))
}

/// Safely pipes data to stdin of a process (e.g. `nft -f -`) with deadline and process group isolation
pub fn run_cmd_write_stdin_bounded(
    cmd_path: &str,
    args: &[&str],
    extra_envs: &[(&str, &str)],
    stdin_data: &[u8],
    deadline: Instant,
) -> bool {
    if Instant::now() >= deadline {
        return false;
    }

    let mut cmd = Command::new(cmd_path);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);

    for (k, v) in extra_envs {
        cmd.env(k, v);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let pid = child.id() as i32;

    let mut guard = ProcessGroupGuard {
        child: &mut child,
        pid,
        active: true,
    };

    if let Some(mut stdin) = guard.child.stdin.take() {
        let _ = stdin.write_all(stdin_data);
    }

    loop {
        if Instant::now() >= deadline {
            return false;
        }
        match guard.child.try_wait() {
            Ok(Some(status)) => {
                guard.active = false;
                reap_process_group(guard.child, guard.pid);
                return status.success();
            }
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_group_deadline_enforcement() {
        let deadline = Instant::now() + Duration::from_millis(100);
        let out = run_cmd_bounded("/bin/sleep", &["5"], &[], deadline, 1024);
        assert!(out.is_none());
    }

    #[test]
    fn test_process_group_buffer_cap_overrun() {
        let deadline = Instant::now() + Duration::from_millis(1000);
        let out = run_cmd_bounded("/bin/sh", &["-c", "yes | head -n 10000"], &[], deadline, 64);
        assert!(out.is_none());
    }

    #[test]
    fn test_status_variant_reports_nonzero_exit_code() {
        let deadline = Instant::now() + Duration::from_millis(2000);
        let out =
            run_cmd_bounded_status("/bin/sh", &["-c", "echo hi; exit 2"], &[], deadline, 1024);
        assert_eq!(out, Some((2, b"hi\n".to_vec())));
        // The success-only wrapper still rejects non-zero exits
        let deadline = Instant::now() + Duration::from_millis(2000);
        assert!(run_cmd_bounded("/bin/sh", &["-c", "exit 2"], &[], deadline, 1024).is_none());
    }
}
