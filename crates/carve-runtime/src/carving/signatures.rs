//! File Signature Definitions for Forensic Carving
//!
//! Provides magic byte headers, footers, MIME types, and default max sizes
//! for key forensic file categories.

use serde::{Deserialize, Serialize};

/// Supported file types for signature-based and structure-based carving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    Pdf,
    Png,
    Jpeg,
    Gif,
    ZipOffice, // ZIP, DOCX, XLSX, PPTX, JAR, APK
    Sqlite,
    Pcap,
    Pe,        // Windows EXE/DLL
    Elf,       // Linux Executable
    Unknown,
}

impl FileType {
    pub fn extension(&self) -> &'static str {
        match self {
            FileType::Pdf => "pdf",
            FileType::Png => "png",
            FileType::Jpeg => "jpg",
            FileType::Gif => "gif",
            FileType::ZipOffice => "zip",
            FileType::Sqlite => "sqlite",
            FileType::Pcap => "pcap",
            FileType::Pe => "exe",
            FileType::Elf => "elf",
            FileType::Unknown => "bin",
        }
    }

    pub fn mime_type(&self) -> &'static str {
        match self {
            FileType::Pdf => "application/pdf",
            FileType::Png => "image/png",
            FileType::Jpeg => "image/jpeg",
            FileType::Gif => "image/gif",
            FileType::ZipOffice => "application/zip",
            FileType::Sqlite => "application/vnd.sqlite3",
            FileType::Pcap => "application/vnd.tcpdump.pcap",
            FileType::Pe => "application/vnd.microsoft.portable-executable",
            FileType::Elf => "application/x-elf",
            FileType::Unknown => "application/octet-stream",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pdf" => Some(FileType::Pdf),
            "png" => Some(FileType::Png),
            "jpg" | "jpeg" => Some(FileType::Jpeg),
            "gif" => Some(FileType::Gif),
            "zip" | "docx" | "xlsx" | "pptx" | "office" => Some(FileType::ZipOffice),
            "sqlite" | "db" | "sqlite3" => Some(FileType::Sqlite),
            "pcap" | "pcapng" => Some(FileType::Pcap),
            "pe" | "exe" | "dll" => Some(FileType::Pe),
            "elf" => Some(FileType::Elf),
            "all" => None, // Handled as wildcard by caller
            _ => None,
        }
    }
}

/// A signature rule used to detect file boundaries.
#[derive(Debug, Clone)]
pub struct FileSignature {
    pub file_type: FileType,
    pub header: &'static [u8],
    pub footer: Option<&'static [u8]>,
    pub max_size: usize,
}

/// The built-in signature registry.
pub static SIGNATURES: &[FileSignature] = &[
    // PDF: %PDF-
    FileSignature {
        file_type: FileType::Pdf,
        header: b"%PDF-",
        footer: Some(b"%%EOF"),
        max_size: 50 * 1024 * 1024, // 50MB
    },
    // PNG: \x89PNG\r\n\x1a\n ... IEND\xaeB`\x82
    FileSignature {
        file_type: FileType::Png,
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
        max_size: 20 * 1024 * 1024, // 20MB
    },
    // JPEG: \xFF\xD8\xFF ... \xFF\xD9
    FileSignature {
        file_type: FileType::Jpeg,
        header: &[0xFF, 0xD8, 0xFF],
        footer: Some(&[0xFF, 0xD9]),
        max_size: 25 * 1024 * 1024, // 25MB
    },
    // GIF: GIF87a or GIF89a ... \x00\x3B
    FileSignature {
        file_type: FileType::Gif,
        header: b"GIF89a",
        footer: Some(&[0x00, 0x3B]),
        max_size: 20 * 1024 * 1024,
    },
    FileSignature {
        file_type: FileType::Gif,
        header: b"GIF87a",
        footer: Some(&[0x00, 0x3B]),
        max_size: 20 * 1024 * 1024,
    },
    // ZIP / Office: PK\x03\x04 ... PK\x05\x06 (EOCD record start)
    FileSignature {
        file_type: FileType::ZipOffice,
        header: &[0x50, 0x4B, 0x03, 0x04],
        footer: Some(&[0x50, 0x4B, 0x05, 0x06]),
        max_size: 100 * 1024 * 1024, // 100MB
    },
    // SQLite 3: "SQLite format 3\0"
    FileSignature {
        file_type: FileType::Sqlite,
        header: b"SQLite format 3\0",
        footer: None, // SQLite has internal page-based sizing
        max_size: 200 * 1024 * 1024, // 200MB
    },
    // PCAP: \xd4\xc3\xb2\xa1 (microsecond) or \xa1\xb2\xc3\xd4 (swapped)
    FileSignature {
        file_type: FileType::Pcap,
        header: &[0xD4, 0xC3, 0xB2, 0xA1],
        footer: None,
        max_size: 100 * 1024 * 1024,
    },
    FileSignature {
        file_type: FileType::Pcap,
        header: &[0xA1, 0xB2, 0xC3, 0xD4],
        footer: None,
        max_size: 100 * 1024 * 1024,
    },
    // Windows Portable Executable (MZ)
    FileSignature {
        file_type: FileType::Pe,
        header: &[0x4D, 0x5A], // "MZ"
        footer: None,
        max_size: 50 * 1024 * 1024,
    },
    // Linux ELF: \x7fELF
    FileSignature {
        file_type: FileType::Elf,
        header: &[0x7F, 0x45, 0x4C, 0x46],
        footer: None,
        max_size: 50 * 1024 * 1024,
    },
];
