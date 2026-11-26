//! Offline pre-flight checks: what startup can fail on without touching the network.
//!
//! `validate` runs these (unless `--settings-only`), so `config OK` means the configuration
//! will not stop the proxy at startup. Nothing here binds a port, connects anywhere, or
//! creates a file.

use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;

use rusty_conduit_engine::mitm::{MitmOptions, MitmState};

use crate::fdlimit;

/// Load the MITM CA exactly as startup does: read the files, decrypt the key, and check the
/// certificate's validity and that the key matches it.
pub fn check_mitm(options: &MitmOptions) -> Result<(), String> {
    MitmState::from_options(options)
        .map(|_| ())
        .map_err(|e| format!("MITM setup failed: {e}"))
}

/// Check that the proxy could open `path` for appending, without creating or writing it.
///
/// An existing file must open for appending; a missing one needs an existing, writable
/// parent directory. `label` names the setting in the error, for example `--socks-log`.
pub fn check_log_path(label: &str, path: &Path) -> Result<(), String> {
    let show = path.display();
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Err(format!("{label} {show} is a directory")),
        Ok(_) => OpenOptions::new()
            .append(true)
            .open(path)
            .map(|_| ())
            .map_err(|e| format!("cannot open {label} {show}: {e}")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let dir = match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => Path::new("."),
            };
            match fs::metadata(dir) {
                Ok(meta) if meta.is_dir() => dir_writable(dir).map_err(|e| {
                    format!(
                        "cannot create {label} {show}: directory {}: {e}",
                        dir.display()
                    )
                }),
                Ok(_) => Err(format!(
                    "cannot create {label} {show}: {} is not a directory",
                    dir.display()
                )),
                Err(e) => Err(format!(
                    "cannot create {label} {show}: directory {}: {e}",
                    dir.display()
                )),
            }
        }
        Err(e) => Err(format!("cannot open {label} {show}: {e}")),
    }
}

#[cfg(unix)]
fn dir_writable(dir: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c = CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
    if unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn dir_writable(dir: &Path) -> io::Result<()> {
    if fs::metadata(dir)?.permissions().readonly() {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the directory is read-only",
        ))
    } else {
        Ok(())
    }
}

/// The open-file NOTICE startup would log for `connections` (`flag` names the setting).
///
/// Raises this process's soft limit the same way startup does, so the result matches what
/// the proxy would reach.
pub fn fd_limit_notice(connections: usize, flag: &str) -> Option<String> {
    if connections == 0 {
        return None;
    }
    let (_, after) = fdlimit::raise_nofile_limit(fdlimit::required_fds(connections)).ok()?;
    fdlimit::fd_limit_notice(after, connections, flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "preflight-test-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn log_path_in_a_writable_directory_passes_without_creating_it() {
        let dir = temp_dir("ok");
        let path = dir.join("access.log");
        assert_eq!(check_log_path("--http-access-log", &path), Ok(()));
        assert!(!path.exists(), "the check must not create the file");
        fs::write(&path, "existing\n").unwrap();
        assert_eq!(check_log_path("--http-access-log", &path), Ok(()));
        assert_eq!(fs::read_to_string(&path).unwrap(), "existing\n");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn log_path_problems_are_reported() {
        let dir = temp_dir("bad");
        let missing = dir.join("no-such-dir").join("access.log");
        let err = check_log_path("--socks-log", &missing).unwrap_err();
        assert!(err.starts_with("cannot create --socks-log"), "{err}");
        let err = check_log_path("--socks-log", &dir).unwrap_err();
        assert!(err.ends_with("is a directory"), "{err}");
        fs::remove_dir_all(dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn log_path_in_a_read_only_directory_fails() {
        use std::os::unix::fs::PermissionsExt;

        // Root ignores directory permissions, so the check would rightly pass.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = temp_dir("ro");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let err = check_log_path("--http-access-log", &dir.join("access.log")).unwrap_err();
        assert!(err.contains("Permission denied"), "{err}");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn no_fd_notice_for_unlimited_connections() {
        assert_eq!(fd_limit_notice(0, "--max-connections"), None);
    }
}
