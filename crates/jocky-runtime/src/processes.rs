//! Process Enumeration Module
//!
//! Cross-platform process listing using read-only APIs:
//! - Windows: CreateToolhelp32Snapshot + Process32First/Next
//! - Linux: /proc/ directory enumeration

use log::info;
use serde::{Deserialize, Serialize};

/// A single process entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEntry {
    pub pid: u32,
    pub name: String,
    pub parent_pid: u32,
}

/// Enumerate all running processes (Windows implementation).
#[cfg(windows)]
pub fn scan_processes() -> Result<Vec<ProcessEntry>, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use crate::win32::*;

    info!("Scanning processes (Windows)");

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Err("CreateToolhelp32Snapshot failed".to_string());
    }

    let mut pe = PROCESSENTRY32W::default();
    let mut processes = Vec::new();

    unsafe {
        if Process32FirstW(snap, &mut pe) != 0 {
            loop {
                let name_len = pe
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(pe.szExeFile.len());
                let name = OsString::from_wide(&pe.szExeFile[..name_len])
                    .to_string_lossy()
                    .to_string();

                processes.push(ProcessEntry {
                    pid: pe.th32ProcessID,
                    name,
                    parent_pid: pe.th32ParentProcessID,
                });

                if Process32NextW(snap, &mut pe) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snap);
    }

    info!("Found {} processes", processes.len());
    Ok(processes)
}

/// Enumerate all running processes (Linux implementation).
#[cfg(unix)]
pub fn scan_processes() -> Result<Vec<ProcessEntry>, String> {
    use std::fs;

    info!("Scanning processes (Linux)");

    let mut processes = Vec::new();

    for entry in fs::read_dir("/proc").map_err(|e| format!("Cannot read /proc: {e}"))? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric directories are PIDs
        if let Ok(pid) = name_str.parse::<u32>() {
            let comm_path = format!("/proc/{}/comm", pid);
            let stat_path = format!("/proc/{}/stat", pid);

            let proc_name = fs::read_to_string(&comm_path)
                .unwrap_or_default()
                .trim()
                .to_string();

            let parent_pid = fs::read_to_string(&stat_path)
                .ok()
                .and_then(|s| {
                    // Field 4 in /proc/pid/stat is ppid
                    s.split_whitespace().nth(3)?.parse::<u32>().ok()
                })
                .unwrap_or(0);

            processes.push(ProcessEntry {
                pid,
                name: proc_name,
                parent_pid,
            });
        }
    }

    info!("Found {} processes", processes.len());
    Ok(processes)
}

/// Filter processes by a predicate.
pub fn filter_processes(
    processes: &[ProcessEntry],
    predicate: impl Fn(&ProcessEntry) -> bool,
) -> Vec<ProcessEntry> {
    processes.iter().filter(|p| predicate(p)).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_processes() {
        let procs = vec![
            ProcessEntry { pid: 1, name: "init".into(), parent_pid: 0 },
            ProcessEntry { pid: 100, name: "sshd".into(), parent_pid: 1 },
            ProcessEntry { pid: 200, name: "bash".into(), parent_pid: 100 },
        ];

        let children_of_1 = filter_processes(&procs, |p| p.parent_pid == 1);
        assert_eq!(children_of_1.len(), 1);
        assert_eq!(children_of_1[0].pid, 100);
    }
}
