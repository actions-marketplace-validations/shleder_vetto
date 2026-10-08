//! Non-blocking streaming I/O pump and secret redaction (INV-25).
//!
//! Handles concurrent draining of stdout, stderr, and PTY without deadlocks.

#![cfg_attr(windows, allow(unused_imports))]

#[allow(unused_imports)]
use std::io::Write;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};

use super::error::SuperviseError;

/// Bounded capture buffer limit per stream per INV-25 (1 MB).
pub const DEFAULT_MAX_PUMP_BYTES: usize = crate::sandbox::production::PROD_MAX_STDIO;

/// Drain budget after child process exits (200 ms).
pub const DEFAULT_DRAIN_BUDGET: Duration = crate::sandbox::production::PROD_DRAIN_BUDGET;

/// Collected and redacted stdio data.
#[derive(Debug, Clone, Default)]
pub struct PumpData {
    /// Masked or raw stdout bytes.
    pub stdout: Vec<u8>,
    /// Masked or raw stderr bytes.
    pub stderr: Vec<u8>,
    /// True if stdout stream was truncated beyond 1 MB buffer.
    pub stdout_truncated: bool,
    /// True if stderr stream was truncated beyond 1 MB buffer.
    pub stderr_truncated: bool,
}

/// Cross-platform stub for non-Unix environments.
#[cfg(not(unix))]
#[derive(Debug)]
pub struct OwnedFd;

/// Asynchronous non-blocking pump for child process I/O streams.
///
/// Invariant INV-25:
/// - Background `AsyncPipeReader` threads continuously drain child pipes.
/// - Upon reaching `DEFAULT_MAX_PUMP_BYTES` (1 MB), remaining data is read
///   and discarded into /dev/null, preventing child from blocking on write(2).
/// - On termination, `drain_and_redact()` applies `pty::AnsiRedactor` secret
///   masking and flushes to host terminal streams.
pub struct StdioPump {
    #[cfg(unix)]
    pty_master: Option<OwnedFd>,
    #[cfg(unix)]
    out_reader: Option<crate::sandbox::production::AsyncPipeReader>,
    #[cfg(unix)]
    err_reader: Option<crate::sandbox::production::AsyncPipeReader>,
    #[cfg_attr(not(unix), allow(dead_code))]
    mask_secrets: bool,
}

impl StdioPump {
    /// Starts asynchronous background readers for stdout and stderr pipes.
    #[cfg(unix)]
    pub fn start(
        pty_master: Option<OwnedFd>,
        stdout_r: Option<OwnedFd>,
        stderr_r: Option<OwnedFd>,
        mask_secrets: bool,
    ) -> Result<Self, SuperviseError> {
        if let Some(ref master) = pty_master {
            let _ = crate::pty::set_nonblocking(master.as_raw_fd(), true);
        }
        let out_reader = stdout_r.map(|fd| {
            crate::sandbox::production::AsyncPipeReader::spawn(
                fd,
                DEFAULT_MAX_PUMP_BYTES,
                DEFAULT_DRAIN_BUDGET,
            )
        });

        let err_reader = stderr_r.map(|fd| {
            crate::sandbox::production::AsyncPipeReader::spawn(
                fd,
                DEFAULT_MAX_PUMP_BYTES,
                DEFAULT_DRAIN_BUDGET,
            )
        });

        Ok(Self {
            pty_master,
            out_reader,
            err_reader,
            mask_secrets,
        })
    }

    /// Non-Unix stub constructor.
    #[cfg(not(unix))]
    pub fn start(
        _pty_master: Option<()>,
        _stdout_r: Option<()>,
        _stderr_r: Option<()>,
        mask_secrets: bool,
    ) -> Result<Self, SuperviseError> {
        Ok(Self { mask_secrets })
    }

    /// Access PTY master descriptor if allocated.
    #[cfg(unix)]
    pub fn pty_master(&self) -> Option<&OwnedFd> {
        self.pty_master.as_ref()
    }

    /// Non-Unix stub for PTY master access.
    #[cfg(not(unix))]
    pub fn pty_master(&self) -> Option<&OwnedFd> {
        None
    }

    /// Notify background readers that the child exited so drain budget timer starts.
    pub fn notify_child_exited(&self) {
        #[cfg(unix)]
        {
            if let Some(r) = &self.out_reader {
                r.notify_child_exited();
            }
            if let Some(r) = &self.err_reader {
                r.notify_child_exited();
            }
        }
    }

    /// Drain remaining stream bytes, apply ANSI/secret redactor, flush to terminal,
    /// and return captured `PumpData`.
    pub fn drain_and_redact(&mut self) -> Result<PumpData, SuperviseError> {
        #[cfg(unix)]
        {
            self.notify_child_exited();

            let (raw_out, out_trunc) = if let Some(r) = self.out_reader.take() {
                r.join_with_status()
            } else {
                (Vec::new(), false)
            };

            let (raw_err, err_trunc) = if let Some(r) = self.err_reader.take() {
                r.join_with_status()
            } else {
                (Vec::new(), false)
            };

            let mut final_out = Vec::new();
            let mut final_err = Vec::new();

            // Handle stdout
            if !raw_out.is_empty() {
                if self.mask_secrets {
                    let mut redactor = crate::pty::AnsiRedactor::new();
                    let redacted = redactor.redact_chunk(&raw_out);
                    let flushed = redactor.flush();
                    final_out.extend_from_slice(&redacted);
                    final_out.extend_from_slice(&flushed);
                } else {
                    final_out = raw_out;
                }

                #[cfg(unix)]
                safe_flush_output(libc::STDOUT_FILENO, &final_out);
                #[cfg(not(unix))]
                {
                    let mut dest = std::io::stdout();
                    let _ = dest.write_all(&final_out);
                    let _ = dest.flush();
                }
            }

            // Handle stderr
            if !raw_err.is_empty() {
                if self.mask_secrets {
                    let mut redactor = crate::pty::AnsiRedactor::new();
                    let redacted = redactor.redact_chunk(&raw_err);
                    let flushed = redactor.flush();
                    final_err.extend_from_slice(&redacted);
                    final_err.extend_from_slice(&flushed);
                } else {
                    final_err = raw_err;
                }

                #[cfg(unix)]
                safe_flush_output(libc::STDERR_FILENO, &final_err);
                #[cfg(not(unix))]
                {
                    let mut dest = std::io::stderr();
                    let _ = dest.write_all(&final_err);
                    let _ = dest.flush();
                }
            }

            // Drain residual bytes from PTY master if present
            if let Some(master) = &self.pty_master {
                let mut pty_buf = [0u8; 8192];
                let mut residual = Vec::new();
                let deadline = Instant::now() + DEFAULT_DRAIN_BUDGET;
                loop {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    let remaining_ms = (deadline - now).as_millis().min(50) as libc::c_int;
                    let mut pfd = libc::pollfd {
                        fd: master.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let pret = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
                    if pret <= 0 {
                        break;
                    }
                    if pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                        let n = crate::pty::read_ready(master.as_raw_fd(), &mut pty_buf);
                        if n == 0 {
                            break;
                        }
                        residual.extend_from_slice(&pty_buf[..n]);
                    } else {
                        break;
                    }
                }
                if !residual.is_empty() {
                    let to_write = if self.mask_secrets {
                        let mut redactor = crate::pty::AnsiRedactor::new();
                        let redacted = redactor.redact_chunk(&residual);
                        let flushed = redactor.flush();
                        [redacted, flushed].concat()
                    } else {
                        residual
                    };
                    #[cfg(unix)]
                    safe_flush_output(libc::STDOUT_FILENO, &to_write);
                    #[cfg(not(unix))]
                    {
                        let mut dest = std::io::stdout();
                        let _ = dest.write_all(&to_write);
                        let _ = dest.flush();
                    }
                    final_out.extend_from_slice(&to_write);
                }
            }

            Ok(PumpData {
                stdout: final_out,
                stderr: final_err,
                stdout_truncated: out_trunc,
                stderr_truncated: err_trunc,
            })
        }

        #[cfg(not(unix))]
        {
            Ok(PumpData::default())
        }
    }
}

/// Bounded non-blocking chunked output writer protecting against full pipes and EPIPE deadlocks (INV-25).
#[cfg(unix)]
fn safe_flush_output(fd: libc::c_int, data: &[u8]) {
    let mut offset = 0;
    let deadline = Instant::now() + Duration::from_millis(500);
    while offset < data.len() {
        if Instant::now() >= deadline {
            break;
        }
        let chunk_len = (data.len() - offset).min(8192);
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut pfd, 1, 50) };
        if r <= 0 {
            if r < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
            }
            break;
        }
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            break;
        }
        if pfd.revents & libc::POLLOUT != 0 {
            let written = unsafe {
                libc::write(
                    fd,
                    data[offset..offset + chunk_len].as_ptr().cast(),
                    chunk_len,
                )
            };
            if written > 0 {
                offset += written as usize;
            } else if written < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            } else {
                break;
            }
        }
    }
}

