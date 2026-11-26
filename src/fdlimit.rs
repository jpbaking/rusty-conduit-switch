//! Open-file limit: raise the soft `RLIMIT_NOFILE` at startup and warn when it still
//! cannot hold the configured connection cap.

use crate::logging::Logger;

/// Descriptors kept free for listeners, log files, and the runtime.
const HEADROOM: u64 = 64;

/// Descriptors needed for `connections` concurrent proxied connections (client + upstream each).
pub fn required_fds(connections: usize) -> u64 {
    2 * connections as u64 + HEADROOM
}

/// Concurrent proxied connections that fit in `limit` descriptors.
pub fn connections_for(limit: u64) -> u64 {
    limit.saturating_sub(HEADROOM) / 2
}

/// The NOTICE to log when `limit` cannot hold `connections` (`0` = unlimited, never warns).
pub fn fd_limit_notice(limit: u64, connections: usize, flag: &str) -> Option<String> {
    if connections == 0 {
        return None;
    }
    let needed = required_fds(connections);
    if limit >= needed {
        return None;
    }
    Some(format!(
        "NOTICE: open-file limit is {limit} but {flag} {connections} needs at least {needed}; \
         only about {} concurrent connections will fit. Raise `ulimit -n` (LimitNOFILE= under \
         systemd) or lower {flag}",
        connections_for(limit)
    ))
}

/// Raise the soft open-file limit toward the hard limit when it is below `needed`.
/// Returns the soft limit before and after. Never lowers the limit.
#[cfg(unix)]
pub fn raise_nofile_limit(needed: u64) -> std::io::Result<(u64, u64)> {
    let (soft, _hard) = rlimit::getrlimit(rlimit::Resource::NOFILE)?;
    if soft >= needed {
        return Ok((soft, soft));
    }
    let after = rlimit::increase_nofile_limit(u64::MAX)?;
    Ok((soft, after))
}

/// Windows has no per-process socket descriptor limit to raise.
#[cfg(not(unix))]
pub fn raise_nofile_limit(_needed: u64) -> std::io::Result<(u64, u64)> {
    Ok((u64::MAX, u64::MAX))
}

/// Raise the limit for `connections` and log the outcome (`flag` names the setting).
pub fn apply(logger: &Logger, connections: usize, flag: &str) {
    if connections == 0 {
        return;
    }
    match raise_nofile_limit(required_fds(connections)) {
        Ok((before, after)) => {
            if after > before {
                logger.debug(format!("raised open-file limit from {before} to {after}"));
            }
            if let Some(notice) = fd_limit_notice(after, connections, flag) {
                logger.info(notice);
            }
        }
        Err(e) => logger.debug(format!("could not read or raise the open-file limit: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_fds_matches_sizing_rule() {
        assert_eq!(required_fds(4096), 8256);
        assert_eq!(required_fds(480), 1024);
    }

    #[test]
    fn connections_for_inverts_required_fds() {
        assert_eq!(connections_for(1024), 480);
        assert_eq!(connections_for(10), 0);
    }

    #[test]
    fn notice_only_when_limit_is_too_low() {
        assert_eq!(fd_limit_notice(8256, 4096, "--max-connections"), None);
        assert_eq!(fd_limit_notice(1024, 0, "--max-connections"), None);
        let n = fd_limit_notice(1024, 4096, "--max-connections").unwrap();
        assert!(n.starts_with("NOTICE: open-file limit is 1024"), "{n}");
        assert!(
            n.contains("--max-connections 4096 needs at least 8256"),
            "{n}"
        );
        assert!(n.contains("about 480 concurrent connections"), "{n}");
    }

    #[cfg(unix)]
    #[test]
    fn raise_is_a_no_op_when_already_enough() {
        let (before, after) = raise_nofile_limit(0).unwrap();
        assert_eq!(before, after);
    }
}
