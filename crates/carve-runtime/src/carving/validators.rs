//! Structural Format Validators for Forensic Carving
//!
//! Validates internal file layout to filter out false positives and calculate
//! a calibrated Confidence Score (0.0 to 1.0) for each carved artifact.

use super::signatures::FileType;
use std::collections::HashMap;

/// Result of structural validation on a candidate file stream.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the candidate appears to be a valid file.
    pub is_valid: bool,
    /// Calibrated confidence score (0.00 to 1.00).
    pub confidence: f32,
    /// Detected actual length of the file in bytes (if determinable).
    pub estimated_length: usize,
    /// Extracted file metadata (e.g., dimensions, page count, table count).
    pub metadata: HashMap<String, String>,
}

impl ValidationResult {
    pub fn invalid() -> Self {
        Self {
            is_valid: false,
            confidence: 0.0,
            estimated_length: 0,
            metadata: HashMap::new(),
        }
    }
}

/// Validate a candidate file based on its detected FileType.
pub fn validate(file_type: FileType, data: &[u8]) -> ValidationResult {
    match file_type {
        FileType::Pdf => validate_pdf(data),
        FileType::Png => validate_png(data),
        FileType::Jpeg => validate_jpeg(data),
        FileType::Gif => validate_gif(data),
        FileType::ZipOffice => validate_zip(data),
        FileType::Sqlite => validate_sqlite(data),
        FileType::Pcap => validate_pcap(data),
        FileType::Pe => validate_pe(data),
        FileType::Elf => validate_elf(data),
        FileType::Unknown => ValidationResult {
            is_valid: true,
            confidence: 0.25,
            estimated_length: data.len(),
            metadata: HashMap::new(),
        },
    }
}

// ─────────────────────────────────────────────────────────────────
// PDF Validator
// ─────────────────────────────────────────────────────────────────
fn validate_pdf(data: &[u8]) -> ValidationResult {
    if data.len() < 32 || !data.starts_with(b"%PDF-") {
        return ValidationResult::invalid();
    }

    let mut metadata = HashMap::new();
    let version = String::from_utf8_lossy(&data[5..8]).to_string();
    metadata.insert("version".into(), format!("PDF-{}", version));

    // Look for %%EOF from the end or within the buffer
    let mut last_eof = None;
    for i in (0..data.len().saturating_sub(5)).rev() {
        if &data[i..i + 5] == b"%%EOF" {
            // Find end of line after %%EOF
            let mut end = i + 5;
            while end < data.len() && (data[end] == b'\r' || data[end] == b'\n' || data[end] == b' ') {
                end += 1;
            }
            last_eof = Some(end);
            break;
        }
    }

    let Some(end_pos) = last_eof else {
        // Truncated PDF with valid header
        return ValidationResult {
            is_valid: true,
            confidence: 0.45,
            estimated_length: data.len(),
            metadata,
        };
    };

    let slice = &data[..end_pos];
    let has_xref = slice.windows(4).any(|w| w == b"xref");
    let has_trailer = slice.windows(7).any(|w| w == b"trailer");

    let confidence = if has_xref && has_trailer {
        0.95
    } else if has_xref || has_trailer {
        0.80
    } else {
        0.65
    };

    ValidationResult {
        is_valid: true,
        confidence,
        estimated_length: end_pos,
        metadata,
    }
}

// ─────────────────────────────────────────────────────────────────
// PNG Validator
// ─────────────────────────────────────────────────────────────────
fn validate_png(data: &[u8]) -> ValidationResult {
    const PNG_HEADER: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 33 || !data.starts_with(PNG_HEADER) {
        return ValidationResult::invalid();
    }

    let mut metadata = HashMap::new();
    let mut offset = 8;
    let mut found_iend = false;
    let mut chunk_count = 0;

    while offset + 8 <= data.len() {
        let chunk_len = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;

        let chunk_type = &data[offset + 4..offset + 8];
        chunk_count += 1;

        if chunk_type == b"IHDR" && offset + 8 + 8 <= data.len() {
            let width = u32::from_be_bytes([data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11]]);
            let height = u32::from_be_bytes([data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15]]);
            metadata.insert("dimensions".into(), format!("{}x{}", width, height));
        }

        // chunk header (8) + chunk data (len) + CRC (4)
        offset += 8 + chunk_len + 4;

        if chunk_type == b"IEND" {
            found_iend = true;
            break;
        }

        if offset > data.len() {
            break;
        }
    }

    metadata.insert("chunks".into(), chunk_count.to_string());

    if found_iend && offset <= data.len() {
        ValidationResult {
            is_valid: true,
            confidence: 0.98,
            estimated_length: offset,
            metadata,
        }
    } else {
        ValidationResult {
            is_valid: chunk_count > 1,
            confidence: 0.50,
            estimated_length: data.len(),
            metadata,
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// JPEG Validator
// ─────────────────────────────────────────────────────────────────
fn validate_jpeg(data: &[u8]) -> ValidationResult {
    if data.len() < 16 || data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
        return ValidationResult::invalid();
    }

    let mut metadata = HashMap::new();
    let mut offset = 2;
    let mut found_eoi = false;
    let mut has_sof = false;

    while offset + 1 < data.len() {
        if data[offset] != 0xFF {
            offset += 1;
            continue;
        }

        let marker = data[offset + 1];
        if marker == 0xD9 {
            // EOI (End of Image)
            found_eoi = true;
            offset += 2;
            break;
        }

        if marker == 0x00 || marker == 0xFF {
            offset += 1;
            continue;
        }

        // Markers with variable payload lengths
        if offset + 4 <= data.len() {
            let len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            // Baseline or progressive SOF markers
            if marker == 0xC0 || marker == 0xC2 {
                has_sof = true;
                if offset + 9 <= data.len() {
                    let height = u16::from_be_bytes([data[offset + 5], data[offset + 6]]);
                    let width = u16::from_be_bytes([data[offset + 7], data[offset + 8]]);
                    metadata.insert("dimensions".into(), format!("{}x{}", width, height));
                }
            }
            if len >= 2 {
                offset += 2 + len;
            } else {
                offset += 2;
            }
        } else {
            offset += 2;
        }
    }

    let confidence = if found_eoi && has_sof {
        0.96
    } else if found_eoi || has_sof {
        0.75
    } else {
        0.40
    };

    ValidationResult {
        is_valid: true,
        confidence,
        estimated_length: if found_eoi { offset } else { data.len() },
        metadata,
    }
}

// ─────────────────────────────────────────────────────────────────
// GIF Validator
// ─────────────────────────────────────────────────────────────────
fn validate_gif(data: &[u8]) -> ValidationResult {
    if data.len() < 13 || (!data.starts_with(b"GIF89a") && !data.starts_with(b"GIF87a")) {
        return ValidationResult::invalid();
    }

    let mut metadata = HashMap::new();
    let width = u16::from_le_bytes([data[6], data[7]]);
    let height = u16::from_le_bytes([data[8], data[9]]);
    metadata.insert("dimensions".into(), format!("{}x{}", width, height));

    // Locate GIF trailer 0x3B
    let mut end_pos = data.len();
    for i in (10..data.len()).rev() {
        if data[i] == 0x3B {
            end_pos = i + 1;
            break;
        }
    }

    ValidationResult {
        is_valid: true,
        confidence: 0.90,
        estimated_length: end_pos,
        metadata,
    }
}

// ─────────────────────────────────────────────────────────────────
// ZIP / Office Validator
// ─────────────────────────────────────────────────────────────────
fn validate_zip(data: &[u8]) -> ValidationResult {
    if data.len() < 22 || !data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return ValidationResult::invalid();
    }

    let mut metadata = HashMap::new();

    // Look for End of Central Directory (EOCD) signature PK\x05\x06
    let mut eocd_pos = None;
    for i in (0..data.len().saturating_sub(22)).rev() {
        if &data[i..i + 4] == &[0x50, 0x4B, 0x05, 0x06] {
            eocd_pos = Some(i);
            break;
        }
    }

    if let Some(pos) = eocd_pos {
        let comment_len = if pos + 22 <= data.len() {
            u16::from_le_bytes([data[pos + 20], data[pos + 21]]) as usize
        } else {
            0
        };
        let total_len = pos + 22 + comment_len;

        // Check if it's an Office document (DOCX/XLSX/PPTX) by scanning for "[Content_Types].xml"
        let is_office = data.windows(19).any(|w| w == b"[Content_Types].xml");
        if is_office {
            metadata.insert("subtype".into(), "Microsoft Office Document (OpenXML)".into());
        } else {
            metadata.insert("subtype".into(), "Standard ZIP Archive".into());
        }

        ValidationResult {
            is_valid: true,
            confidence: 0.95,
            estimated_length: total_len.min(data.len()),
            metadata,
        }
    } else {
        ValidationResult {
            is_valid: true,
            confidence: 0.50,
            estimated_length: data.len(),
            metadata,
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// SQLite 3 Validator
// ─────────────────────────────────────────────────────────────────
fn validate_sqlite(data: &[u8]) -> ValidationResult {
    const SQLITE_HEADER: &[u8] = b"SQLite format 3\0";
    if data.len() < 100 || !data.starts_with(SQLITE_HEADER) {
        return ValidationResult::invalid();
    }

    let mut metadata = HashMap::new();
    let mut page_size = u16::from_be_bytes([data[16], data[17]]) as usize;
    if page_size == 1 {
        page_size = 65536;
    }

    let is_valid_page_size = page_size >= 512 && page_size <= 65536 && (page_size & (page_size - 1)) == 0;
    let page_count = u32::from_be_bytes([data[28], data[29], data[30], data[31]]) as usize;

    metadata.insert("page_size".into(), page_size.to_string());
    metadata.insert("page_count".into(), page_count.to_string());

    let estimated_length = if page_count > 0 && is_valid_page_size {
        (page_count * page_size).min(data.len())
    } else {
        data.len()
    };

    let confidence = if is_valid_page_size && page_count > 0 {
        0.98
    } else if is_valid_page_size {
        0.80
    } else {
        0.50
    };

    ValidationResult {
        is_valid: is_valid_page_size,
        confidence,
        estimated_length,
        metadata,
    }
}

// ─────────────────────────────────────────────────────────────────
// PCAP Validator
// ─────────────────────────────────────────────────────────────────
fn validate_pcap(data: &[u8]) -> ValidationResult {
    if data.len() < 24 {
        return ValidationResult::invalid();
    }

    let is_pcap = data.starts_with(&[0xD4, 0xC3, 0xB2, 0xA1]) || data.starts_with(&[0xA1, 0xB2, 0xC3, 0xD4]);
    if !is_pcap {
        return ValidationResult::invalid();
    }

    let mut metadata = HashMap::new();
    let snaplen = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let linktype = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

    metadata.insert("snaplen".into(), snaplen.to_string());
    metadata.insert("linktype".into(), linktype.to_string());

    ValidationResult {
        is_valid: true,
        confidence: 0.92,
        estimated_length: data.len(),
        metadata,
    }
}

// ─────────────────────────────────────────────────────────────────
// Windows PE Validator
// ─────────────────────────────────────────────────────────────────
fn validate_pe(data: &[u8]) -> ValidationResult {
    if data.len() < 64 || !data.starts_with(b"MZ") {
        return ValidationResult::invalid();
    }

    // Offset 0x3C points to the PE header
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset + 4] == b"PE\0\0" {
        let mut metadata = HashMap::new();
        metadata.insert("format".into(), "Windows Portable Executable (PE)".into());
        ValidationResult {
            is_valid: true,
            confidence: 0.96,
            estimated_length: data.len(),
            metadata,
        }
    } else {
        ValidationResult {
            is_valid: false,
            confidence: 0.20,
            estimated_length: 0,
            metadata: HashMap::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// Linux ELF Validator
// ─────────────────────────────────────────────────────────────────
fn validate_elf(data: &[u8]) -> ValidationResult {
    if data.len() < 52 || !data.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
        return ValidationResult::invalid();
    }

    let mut metadata = HashMap::new();
    let class_bit = if data[4] == 2 { "64-bit" } else { "32-bit" };
    metadata.insert("class".into(), class_bit.into());

    ValidationResult {
        is_valid: true,
        confidence: 0.95,
        estimated_length: data.len(),
        metadata,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_sqlite_valid() {
        let mut db = vec![0u8; 4096];
        db[..16].copy_from_slice(b"SQLite format 3\0");
        // Page size = 4096 (0x1000)
        db[16] = 0x10;
        db[17] = 0x00;
        // Page count = 1
        db[31] = 1;

        let res = validate(FileType::Sqlite, &db);
        assert!(res.is_valid);
        assert!(res.confidence >= 0.95);
        assert_eq!(res.estimated_length, 4096);
        assert_eq!(res.metadata.get("page_size").unwrap(), "4096");
    }

    #[test]
    fn test_validate_png() {
        let png = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // header
            0x00, 0x00, 0x00, 0x0D, // IHDR len 13
            0x49, 0x48, 0x44, 0x52, // "IHDR"
            0x00, 0x00, 0x00, 0x64, // w = 100
            0x00, 0x00, 0x00, 0x64, // h = 100
            0x08, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // CRC
            0x00, 0x00, 0x00, 0x00, // IEND len 0
            0x49, 0x45, 0x4E, 0x44, // "IEND"
            0xAE, 0x42, 0x60, 0x82, // CRC
        ];

        let res = validate(FileType::Png, &png);
        assert!(res.is_valid);
        assert_eq!(res.confidence, 0.98);
        assert_eq!(res.metadata.get("dimensions").unwrap(), "100x100");
    }
}
