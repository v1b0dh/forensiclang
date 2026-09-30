//! Memory Collection Module
//!
//! Cross-platform memory collection using read-only OS APIs:
//! - Windows: VirtualQueryEx + ReadProcessMemory
//! - Linux: /proc/{pid}/maps + /proc/{pid}/mem

use crate::artifact::Artifact;
use log::info;
#[cfg(unix)]
use log::warn;

#[cfg(windows)]
use crate::win32::*;

/// Collect memory regions from a process (Windows implementation).
///
/// Uses read-only APIs only — never writes to foreign process memory.
#[cfg(windows)]
pub fn collect_memory(pid: u32, export_name: &str) -> Result<Artifact, String> {
    use std::ffi::c_void;

    info!("Collecting memory from PID {} → artifact '{}'", pid, export_name);

    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if process.is_null() {
        return Err(format!("OpenProcess failed for PID {pid}"));
    }

    let mut artifact = Artifact::new(export_name);
    let mut address: usize = 0;
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    loop {
        let result = unsafe {
            VirtualQueryEx(
                process,
                address as *const c_void,
                &mut mbi,
                mbi_size,
            )
        };

        if result == 0 {
            break;
        }

        // Only read committed, private or mapped regions
        if mbi.State == MEM_COMMIT
            && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED)
        {
            let region_size = mbi.RegionSize;
            let mut buffer = vec![0u8; region_size];
            let mut bytes_read = 0usize;

            let read_ok = unsafe {
                ReadProcessMemory(
                    process,
                    mbi.BaseAddress,
                    buffer.as_mut_ptr() as *mut c_void,
                    region_size,
                    &mut bytes_read,
                )
            };

            if read_ok != 0 && bytes_read > 0 {
                buffer.truncate(bytes_read);
                artifact.append_region(
                    mbi.BaseAddress as u64,
                    buffer,
                    mbi.Protect,
                );
            }
        }

        address = mbi.BaseAddress as usize + mbi.RegionSize;
    }

    unsafe {
        CloseHandle(process);
    }

    info!(
        "Collected {} memory regions from PID {}",
        artifact.regions.len(),
        pid
    );
    Ok(artifact)
}

/// Collect memory regions from a process (Linux implementation).
///
/// Reads /proc/{pid}/maps for regions, /proc/{pid}/mem for data.
#[cfg(unix)]
pub fn collect_memory(pid: u32, export_name: &str) -> Result<Artifact, String> {
    use std::fs;
    use std::io::Read;

    info!("Collecting memory from PID {} → artifact '{}'", pid, export_name);

    let maps_path = format!("/proc/{}/maps", pid);
    let mem_path = format!("/proc/{}/mem", pid);

    let maps_content = fs::read_to_string(&maps_path)
        .map_err(|e| format!("Cannot read {maps_path}: {e}"))?;

    let mut mem_file = fs::File::open(&mem_path)
        .map_err(|e| format!("Cannot open {mem_path}: {e}"))?;

    let mut artifact = Artifact::new(export_name);

    for line in maps_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let range: Vec<&str> = parts[0].split('-').collect();
        if range.len() != 2 {
            continue;
        }

        let start = u64::from_str_radix(range[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(range[1], 16).unwrap_or(0);
        let perms = parts.get(1).unwrap_or(&"");

        // Only read regions with 'r' permission
        if perms.starts_with('r') {
            let size = (end - start) as usize;
            let mut buffer = vec![0u8; size];

            use std::os::unix::fs::FileExt;
            match mem_file.read_at(&mut buffer, start) {
                Ok(n) if n > 0 => {
                    buffer.truncate(n);
                    artifact.append_region(start, buffer, 0);
                }
                _ => {
                    warn!("Could not read region {:#x}-{:#x}", start, end);
                }
            }
        }
    }

    info!(
        "Collected {} memory regions from PID {}",
        artifact.regions.len(),
        pid
    );
    Ok(artifact)
}

/// Placeholder for unsupported platforms.
#[cfg(not(any(windows, unix)))]
pub fn collect_memory(_pid: u32, _export_name: &str) -> Result<Artifact, String> {
    Err("Memory collection not supported on this platform".to_string())
}
