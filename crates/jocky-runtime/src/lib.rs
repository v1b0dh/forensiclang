//! JOCKY Forensic Runtime Library
//!
//! Provides cross-platform forensic data collection modules:
//! - Memory collection (VirtualQueryEx / procfs)
//! - Process enumeration (Toolhelp32 / procfs)
//! - Disk collection (VSS snapshots)
//! - Network capture (pcap)
//! - Artifact format (.jkya)
//! - Timeline builder

pub mod artifact;
pub mod memory;
pub mod processes;
pub mod timeline;

// Platform-specific modules
#[cfg(windows)]
pub mod disk;

#[cfg(windows)]
pub mod network;

#[cfg(windows)]
pub mod win32;

/// Runtime version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Helper to generate ISO 8601-compatible UTC timestamp using std::time
pub fn utc_timestamp_now() -> String {
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let total_secs = duration.as_secs();
    let days = total_secs / 86400;
    let rem_secs = total_secs % 86400;
    let hours = rem_secs / 3600;
    let mins = (rem_secs % 3600) / 60;
    let secs = rem_secs % 60;

    let mut y = 1970;
    let mut d = days;
    loop {
        let leap = if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) { 1 } else { 0 };
        let days_in_year = 365 + leap;
        if d < days_in_year {
            let days_in_months = [31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
            let mut m = 1;
            for dim in days_in_months {
                if d < dim {
                    return format!("{y:04}-{m:02}-{:02}T{hours:02}:{mins:02}:{secs:02}Z", d + 1);
                }
                d -= dim;
                m += 1;
            }
            break;
        }
        d -= days_in_year;
        y += 1;
    }
    format!("{y:04}-01-01T{hours:02}:{mins:02}:{secs:02}Z")
}

/// Helper to get current microseconds since UNIX epoch
pub fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}
