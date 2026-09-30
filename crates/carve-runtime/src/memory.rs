//! Memory Collection Module
//!
//! Cross-platform memory collection using read-only OS APIs:
//! - Windows: VirtualQueryEx + ReadProcessMemory
//! - Linux: /proc/{pid}/maps + /proc/{pid}/mem

use crate::artifact::Artifact;
use log::info;
#[cfg(unix)]
use log::warn;
use serde::{Deserialize, Serialize};

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

/// Compute Shannon entropy over a buffer (0.0 to 8.0 bits per byte).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len_f = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Severity classification for detected memory injection anomalies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectionSeverity {
    Clean,
    Suspicious,
    Critical,
}

/// An identified unbacked or suspicious executable memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectedRegion {
    pub pid: u32,
    pub process_name: String,
    pub base_address: String,
    pub region_size: usize,
    pub protection: String,
    pub memory_type: String,
    pub entropy: f64,
    pub severity: InjectionSeverity,
    pub indicators: Vec<String>,
    pub mitre_attack: String,
    pub hex_preview: String,
    pub description: String,
}

/// Scan report aggregating reflective memory injection findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInjectionScanReport {
    pub scanned_at: String,
    pub total_processes_scanned: usize,
    pub suspicious_regions_found: usize,
    pub regions: Vec<InjectedRegion>,
}

/// Convert page protection flags to human-readable string.
#[cfg(windows)]
pub fn format_protection(protect: u32) -> &'static str {
    match protect & 0xFF {
        PAGE_EXECUTE_READWRITE => "PAGE_EXECUTE_READWRITE (RWX)",
        PAGE_EXECUTE_READ => "PAGE_EXECUTE_READ (RX)",
        PAGE_EXECUTE => "PAGE_EXECUTE (X)",
        PAGE_EXECUTE_WRITECOPY => "PAGE_EXECUTE_WRITECOPY (WCX)",
        PAGE_READWRITE => "PAGE_READWRITE (RW)",
        PAGE_READONLY => "PAGE_READONLY (R)",
        PAGE_NOACCESS => "PAGE_NOACCESS",
        _ => "OTHER",
    }
}

/// Inspect a process's Virtual Address Descriptors (VAD) for unbacked executable memory (Windows).
///
/// Uses strictly read-only VirtualQueryEx and ReadProcessMemory.
#[cfg(windows)]
pub fn scan_process_injections(pid: u32, process_name: &str) -> Result<Vec<InjectedRegion>, String> {
    use std::ffi::c_void;

    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if process.is_null() {
        return Err(format!("OpenProcess failed for PID {pid} (access denied or terminated)"));
    }

    let mut detected = Vec::new();
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

        // Detect unbacked executable memory:
        // 1. Memory is committed
        // 2. Memory is MEM_PRIVATE (allocated directly, NOT backed by disk image MEM_IMAGE)
        // 3. Memory has executable rights (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)
        let is_exec = (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE | PAGE_EXECUTE_WRITECOPY)) != 0;
        let is_unbacked = mbi.Type == MEM_PRIVATE;

        if mbi.State == MEM_COMMIT && is_exec && is_unbacked {
            // Read sample bytes from the candidate injected region
            let sample_size = mbi.RegionSize.min(4096);
            let mut buffer = vec![0u8; sample_size];
            let mut bytes_read = 0usize;

            let read_ok = unsafe {
                ReadProcessMemory(
                    process,
                    mbi.BaseAddress,
                    buffer.as_mut_ptr() as *mut c_void,
                    sample_size,
                    &mut bytes_read,
                )
            };

            let read_bytes = if read_ok != 0 && bytes_read > 0 {
                &buffer[..bytes_read]
            } else {
                &[][..]
            };

            let entropy = calculate_entropy(read_bytes);
            let mut indicators = Vec::new();
            let mut severity = InjectionSeverity::Suspicious;

            // Indicator 1: Reflective PE / DLL injection (MZ header)
            if read_bytes.len() >= 2 && read_bytes[0] == 0x4D && read_bytes[1] == 0x5A {
                indicators.push("Reflective PE/DLL loaded in private memory (MZ header)".to_string());
                severity = InjectionSeverity::Critical;
            }

            // Indicator 2: W^X violation (PAGE_EXECUTE_READWRITE)
            if (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 {
                indicators.push("RWX memory permissions without backing file (W^X violation)".to_string());
            }

            // Indicator 3: High entropy (> 6.8 bits/byte)
            if entropy > 6.8 && read_bytes.len() >= 256 {
                indicators.push(format!("High Shannon entropy ({:.2} bits/byte): packed or encrypted shellcode stager", entropy));
                severity = InjectionSeverity::Critical;
            }

            // Indicator 4: Shellcode preamble detection (e.g. NOP sled or common stager prelude)
            if read_bytes.windows(4).any(|w| w == [0x90, 0x90, 0x90, 0x90]) {
                indicators.push("NOP sled detected in executable payload".to_string());
                severity = InjectionSeverity::Critical;
            }

            // First 32 bytes formatted as hex preview
            let preview_len = read_bytes.len().min(32);
            let hex_preview = read_bytes[..preview_len]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");

            let desc = if indicators.is_empty() {
                "Unbacked executable private memory region detected.".to_string()
            } else {
                indicators.join("; ")
            };

            detected.push(InjectedRegion {
                pid,
                process_name: process_name.to_string(),
                base_address: format!("0x{:X}", mbi.BaseAddress as usize),
                region_size: mbi.RegionSize,
                protection: format_protection(mbi.Protect).to_string(),
                memory_type: "MEM_PRIVATE (Unbacked)".to_string(),
                entropy,
                severity,
                indicators,
                mitre_attack: "T1055".to_string(),
                hex_preview,
                description: desc,
            });
        }

        address = mbi.BaseAddress as usize + mbi.RegionSize;
    }

    unsafe {
        CloseHandle(process);
    }

    Ok(detected)
}

/// Fallback for non-Windows platforms.
#[cfg(not(windows))]
pub fn scan_process_injections(_pid: u32, _process_name: &str) -> Result<Vec<InjectedRegion>, String> {
    Ok(Vec::new())
}

/// Scan all running accessible processes for reflective memory injections.
pub fn scan_all_processes_injections() -> Result<MemoryInjectionScanReport, String> {
    let procs = crate::processes::scan_processes().unwrap_or_default();
    let mut total_scanned = 0;
    let mut all_regions = Vec::new();

    for p in &procs {
        if let Ok(regions) = scan_process_injections(p.pid, &p.name) {
            total_scanned += 1;
            all_regions.extend(regions);
        }
    }

    let suspicious_count = all_regions.len();

    Ok(MemoryInjectionScanReport {
        scanned_at: crate::utc_timestamp_now(),
        total_processes_scanned: total_scanned,
        suspicious_regions_found: suspicious_count,
        regions: all_regions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy_zero_and_uniform() {
        // All zeros -> entropy 0.0
        let zeros = vec![0u8; 1000];
        assert_eq!(calculate_entropy(&zeros), 0.0);

        // Completely uniform 256 bytes (one of each byte) -> entropy ~ 8.0
        let uniform: Vec<u8> = (0..=255).collect();
        let ent = calculate_entropy(&uniform);
        assert!((ent - 8.0).abs() < 0.001);
    }

    #[test]
    fn test_calculate_entropy_text_and_random() {
        // Typical ASCII text entropy is ~4.0 - 5.0
        let text = b"The quick brown fox jumps over the lazy dog repeatedly and consistently";
        let ent = calculate_entropy(text);
        assert!(ent > 3.0 && ent < 5.5);
    }

    #[cfg(windows)]
    #[test]
    fn test_scan_current_process_injections() {
        // Scan current process PID - should succeed without error
        let current_pid = std::process::id();
        let res = scan_process_injections(current_pid, "cargo_test.exe");
        assert!(res.is_ok());
    }
}

