//! Internal Win32 API Bindings for Forensic Collection
//!
//! Direct C ABI bindings to kernel32.dll without external bloat.
//! All calls use read-only operations suitable for digital forensics.

use std::ffi::c_void;

pub type HANDLE = *mut c_void;
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

pub const TH32CS_SNAPPROCESS: u32 = 0x00000002;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_VM_READ: u32 = 0x0010;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_PRIVATE: u32 = 0x20000;
pub const MEM_MAPPED: u32 = 0x40000;
pub const MEM_IMAGE: u32 = 0x1000000;

pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;

pub const MAX_PATH: usize = 260;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct PROCESSENTRY32W {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ProcessID: u32,
    pub th32DefaultHeapID: usize,
    pub th32ModuleID: u32,
    pub cntThreads: u32,
    pub th32ParentProcessID: u32,
    pub pcPriClassBase: i32,
    pub dwFlags: u32,
    pub szExeFile: [u16; MAX_PATH],
}

impl Default for PROCESSENTRY32W {
    fn default() -> Self {
        Self {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0; MAX_PATH],
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: *mut c_void,
    pub AllocationBase: *mut c_void,
    pub AllocationProtect: u32,
    pub PartitionId: u16,
    pub RegionSize: usize,
    pub State: u32,
    pub Protect: u32,
    pub Type: u32,
}

impl Default for MEMORY_BASIC_INFORMATION {
    fn default() -> Self {
        Self {
            BaseAddress: std::ptr::null_mut(),
            AllocationBase: std::ptr::null_mut(),
            AllocationProtect: 0,
            PartitionId: 0,
            RegionSize: 0,
            State: 0,
            Protect: 0,
            Type: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct WIN32_FIND_STREAM_DATA {
    pub StreamSize: i64,
    pub cStreamName: [u16; MAX_PATH + 36],
}

impl Default for WIN32_FIND_STREAM_DATA {
    fn default() -> Self {
        Self {
            StreamSize: 0,
            cStreamName: [0; MAX_PATH + 36],
        }
    }
}

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn CloseHandle(hObject: HANDLE) -> i32;

    pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> HANDLE;

    pub fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> i32;

    pub fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> i32;

    pub fn OpenProcess(
        dwDesiredAccess: u32,
        bInheritHandle: i32,
        dwProcessId: u32,
    ) -> HANDLE;

    pub fn VirtualQueryEx(
        hProcess: HANDLE,
        lpAddress: *const c_void,
        lpBuffer: *mut MEMORY_BASIC_INFORMATION,
        dwLength: usize,
    ) -> usize;

    pub fn ReadProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: *const c_void,
        lpBuffer: *mut c_void,
        nSize: usize,
        lpNumberOfBytesRead: *mut usize,
    ) -> i32;

    pub fn FindFirstStreamW(
        lpFileName: *const u16,
        InfoLevel: u32,
        lpFindStreamData: *mut c_void,
        dwFlags: u32,
    ) -> HANDLE;

    pub fn FindNextStreamW(
        hFindStream: HANDLE,
        lpFindStreamData: *mut c_void,
    ) -> i32;

    pub fn FindClose(hFindFile: HANDLE) -> i32;
}
