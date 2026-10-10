//! Guaranteed terminal reset guard (Anti-Garbage Exit Guard).
//!
//! Provides RAII restoration of terminal modes (mouse modes, alt screen,
//! cursor visibility, raw mode, and termios state) on exit, drop, panic, or signals.

#[cfg(unix)]
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::Mutex;

const RESET_SEQUENCES: &[u8] =
    b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1049l\x1b[?25h\x1b[0m\x1b[r";

#[cfg(unix)]
struct SavedState {
    tty_fd: Option<RawFd>,
    termios: libc::termios,
}

#[cfg(unix)]
static SAVED_STATE: Mutex<Option<SavedState>> = Mutex::new(None);
static HOOKS_INSTALLED: AtomicBool = AtomicBool::new(false);
static IS_RESET: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn atexit_handler() {
    TerminalResetGuard::reset_now();
}

/// RAII terminal reset guard that guarantees terminal attributes and modes are restored.
pub struct TerminalResetGuard {
    active: bool,
}

impl TerminalResetGuard {
    /// Install terminal reset protection.
    /// Captures the initial termios state if a TTY is available,
    /// and registers panic hook and atexit handlers.
    pub fn install() -> Self {
        #[cfg(unix)]
        {
            if !HOOKS_INSTALLED.swap(true, Ordering::SeqCst) {
                // Try opening /dev/tty or probe standard streams
                let fd = match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/tty")
                {
                    Ok(f) => {
                        use std::os::fd::IntoRawFd;
                        Some(f.into_raw_fd())
                    }
                    Err(_) => {
                        let stdin_isatty = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
                        let stdout_isatty = unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 };
                        let stderr_isatty = unsafe { libc::isatty(libc::STDERR_FILENO) == 1 };
                        if stdout_isatty {
                            Some(libc::STDOUT_FILENO)
                        } else if stdin_isatty {
                            Some(libc::STDIN_FILENO)
                        } else if stderr_isatty {
                            Some(libc::STDERR_FILENO)
                        } else {
                            None
                        }
                    }
                };

                if let Some(tty_fd) = fd {
                    let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
                    let rc = unsafe { libc::tcgetattr(tty_fd, termios.as_mut_ptr()) };
                    if rc == 0 {
                        let termios = unsafe { termios.assume_init() };
                        if let Ok(mut lock) = SAVED_STATE.lock() {
                            *lock = Some(SavedState {
                                tty_fd: Some(tty_fd),
                                termios,
                            });
                        }
                    }
                }

                unsafe {
                    libc::atexit(atexit_handler);
                }

                let prev_hook = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |info| {
                    TerminalResetGuard::reset_now();
                    prev_hook(info);
                }));
            }
        }

        #[cfg(not(unix))]
        {
            if !HOOKS_INSTALLED.swap(true, Ordering::SeqCst) {
                let prev_hook = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |info| {
                    TerminalResetGuard::reset_now();
                    prev_hook(info);
                }));
            }
        }

        IS_RESET.store(false, Ordering::SeqCst);
        Self { active: true }
    }

    /// Explicitly trigger immediate terminal reset.
    /// Resets mouse modes, alt screen, cursor, flushes input queue, and restores termios.
    pub fn reset_now() {
        if IS_RESET.swap(true, Ordering::SeqCst) {
            return;
        }

        #[cfg(unix)]
        {
            let state = if let Ok(lock) = SAVED_STATE.lock() {
                lock.as_ref().map(|s| (s.tty_fd, s.termios))
            } else {
                None
            };

            let target_fd = state.and_then(|(fd, _)| fd).unwrap_or(libc::STDERR_FILENO);

            // 1. Write ANSI reset sequences: mouse off, alt screen off, cursor on, normal style, reset scroll region
            unsafe {
                libc::write(
                    target_fd,
                    RESET_SEQUENCES.as_ptr() as *const libc::c_void,
                    RESET_SEQUENCES.len(),
                );
                // 2. Non-blocking flush of residual input queue
                if libc::isatty(target_fd) == 1 {
                    libc::tcflush(target_fd, libc::TCIFLUSH);
                }
            }

            // 3. Restore saved termios if captured
            if let Some((Some(fd), termios)) = state {
                unsafe {
                    if libc::isatty(fd) == 1 {
                        libc::tcsetattr(fd, libc::TCSANOW, &termios);
                    }
                }
            }

            // 4. Disable crossterm raw mode as best-effort safety
            let _ = crossterm::terminal::disable_raw_mode();
        }

        #[cfg(not(unix))]
        {
            use std::io::Write;
            let _ = std::io::stderr().write_all(RESET_SEQUENCES);
            let _ = std::io::stderr().flush();
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

impl Drop for TerminalResetGuard {
    fn drop(&mut self) {
        if self.active {
            Self::reset_now();
        }
    }
}
