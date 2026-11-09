//! The `regf` base block: the first 4096 bytes of a primary hive (512 of a log).
//!
//! Everything recovery decides on is here: the two sequence numbers (equal in a clean
//! hive, primary one ahead in a dirty one), the file type (primary, old-format log, new
//! HvLE log), the version, the root cell, the size of the hive bins, the tail of the
//! original path (which tells `NTUSER.DAT` of two users apart) and the XOR-32 checksum.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::diag::Result;
use crate::hive::code;
use crate::kind::HiveKind;

/// Bytes of a primary hive's base block.
pub const BASE_BLOCK_SIZE: usize = 4096;
/// Bytes of a transaction log's base block (the first sector).
pub const LOG_BASE_BLOCK_SIZE: usize = 512;
/// The signature every hive and log starts with.
pub const REGF_MAGIC: &[u8; 4] = b"regf";
const EMBEDDED_NAME_OFFSET: usize = 0x30;
const EMBEDDED_NAME_BYTES: usize = 64;
const CHECKSUM_OFFSET: usize = 0x1fc;

/// A decoded base block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiveHeader {
    /// Incremented before a write to the hive begins.
    pub primary_sequence: u32,
    /// Incremented when the write completes; behind the primary one in a dirty hive.
    pub secondary_sequence: u32,
    /// Last write, as a Windows FILETIME.
    pub timestamp_filetime: u64,
    /// Format version, major part (always 1).
    pub major_version: u32,
    /// Format version, minor part (3 to 6).
    pub minor_version: u32,
    /// 0 primary, 1 or 2 old-format log, 6 new-format (HvLE) log.
    pub file_type: u32,
    /// Format of the file (1: direct memory load).
    pub file_format: u32,
    /// Offset of the root key cell, relative to the hive bins.
    pub root_cell_offset: u32,
    /// Size of the hive bins in bytes.
    pub data_size: u32,
    /// Last 32 UTF-16 characters of the hive's original path.
    pub embedded_name: String,
    /// The checksum stored at 0x1fc.
    pub checksum_stored: u32,
    /// The checksum computed over the first 508 bytes.
    pub checksum_calculated: u32,
}

/// XOR-32 over the first 508 bytes, with the two Windows corner cases.
pub fn compute_checksum(bytes: &[u8]) -> u32 {
    let mut acc: u32 = 0;
    for i in 0..127 {
        let off = i * 4;
        if off + 4 > bytes.len() {
            break;
        }
        acc ^= u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    }
    match acc {
        0xffff_ffff => 0xffff_fffe,
        0 => 1,
        v => v,
    }
}

fn u32_at(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn u64_at(bytes: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[off..off + 8]);
    u64::from_le_bytes(b)
}

/// The UTF-16LE name stored at offset 0x30, up to the first NUL.
pub fn decode_embedded_name(bytes: &[u8]) -> String {
    if bytes.len() < EMBEDDED_NAME_OFFSET + EMBEDDED_NAME_BYTES {
        return String::new();
    }
    let raw = &bytes[EMBEDDED_NAME_OFFSET..EMBEDDED_NAME_OFFSET + EMBEDDED_NAME_BYTES];
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

impl HiveHeader {
    /// Decodes a base block. `label` names the file in errors.
    pub fn parse(bytes: &[u8], label: &str) -> Result<HiveHeader> {
        if bytes.len() < 4 {
            return Err(crate::err!(code::HEADER_TRUNCATED, "{label} ({} bytes)", bytes.len()));
        }
        if &bytes[..4] != REGF_MAGIC {
            return Err(crate::err!(code::SIGNATURE_INVALID, "{label} (found {:02x?})", &bytes[..4]));
        }
        if bytes.len() < LOG_BASE_BLOCK_SIZE {
            return Err(crate::err!(code::HEADER_TRUNCATED, "{label} ({} bytes, need at least {LOG_BASE_BLOCK_SIZE})", bytes.len()));
        }
        Ok(HiveHeader {
            primary_sequence: u32_at(bytes, 0x04),
            secondary_sequence: u32_at(bytes, 0x08),
            timestamp_filetime: u64_at(bytes, 0x0c),
            major_version: u32_at(bytes, 0x14),
            minor_version: u32_at(bytes, 0x18),
            file_type: u32_at(bytes, 0x1c),
            file_format: u32_at(bytes, 0x20),
            root_cell_offset: u32_at(bytes, 0x24),
            data_size: u32_at(bytes, 0x28),
            embedded_name: decode_embedded_name(bytes),
            checksum_stored: u32_at(bytes, CHECKSUM_OFFSET),
            checksum_calculated: compute_checksum(bytes),
        })
    }

    /// The sequence numbers differ: the last write did not complete on disk.
    pub fn is_dirty(&self) -> bool {
        self.primary_sequence != self.secondary_sequence
    }

    /// The stored checksum matches the bytes.
    pub fn checksum_valid(&self) -> bool {
        self.checksum_stored == self.checksum_calculated
    }

    /// File type 0: a primary hive.
    pub fn is_primary(&self) -> bool {
        self.file_type == 0
    }

    /// File type 1 or 2: an old-format (Windows XP to 8.0, `DIRT`) log.
    pub fn is_legacy_log(&self) -> bool {
        matches!(self.file_type, 1 | 2)
    }

    /// File type 6: a new-format (Windows 8.1+, `HvLE`) log.
    pub fn is_new_log(&self) -> bool {
        self.file_type == 6
    }

    /// Either log format.
    pub fn is_transaction_log(&self) -> bool {
        self.is_legacy_log() || self.is_new_log()
    }

    /// The kind the embedded name says.
    pub fn kind(&self) -> HiveKind {
        HiveKind::from_embedded_name(&self.embedded_name)
    }

    /// `1.5`.
    pub fn version(&self) -> String {
        format!("{}.{}", self.major_version, self.minor_version)
    }

    /// The parser accepts major 1 and minor 3 to 6.
    pub fn is_supported_version(&self) -> bool {
        self.major_version == 1 && (3..=6).contains(&self.minor_version)
    }

    /// The last write as UTC, when the FILETIME is in range.
    pub fn timestamp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        crate::value::filetime_to_utc(self.timestamp_filetime)
    }
}

/// Reads and decodes the base block of a file on disk.
pub fn read_header(path: &Path) -> Result<HiveHeader> {
    let label = path.display().to_string();
    let meta = std::fs::metadata(path).map_err(|e| crate::err!(code::OPEN_FAILED, "{label}: {e}"))?;
    if meta.len() == 0 {
        return Err(crate::err!(code::EMPTY_FILE, "{label}"));
    }
    let mut file = File::open(path).map_err(|e| crate::err!(code::OPEN_FAILED, "{label}: {e}"))?;
    let mut buf = vec![0u8; BASE_BLOCK_SIZE];
    let mut read = 0usize;
    while read < buf.len() {
        match file.read(&mut buf[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) => return Err(crate::err!(code::IO_ERROR, "{label}: {e}")),
        }
    }
    buf.truncate(read);
    let header = HiveHeader::parse(&buf, &label)?;
    if header.is_primary() && read < BASE_BLOCK_SIZE {
        return Err(crate::err!(code::HEADER_TRUNCATED, "{label} ({read} bytes, a primary hive needs {BASE_BLOCK_SIZE})"));
    }
    Ok(header)
}

/// Whether the file starts with `regf`.
pub fn starts_with_regf(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else { return false };
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic).is_ok() && &magic == REGF_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{base_block, HiveBuilder};

    #[test]
    fn parses_a_built_block() {
        let b = base_block(7, 6, 0x20, 8192, r"emRoot\System32\Config\SOFTWARE", 0, 5);
        let h = HiveHeader::parse(&b, "t").unwrap();
        assert_eq!(h.primary_sequence, 7);
        assert_eq!(h.secondary_sequence, 6);
        assert!(h.is_dirty());
        assert!(h.checksum_valid());
        assert!(h.is_primary());
        assert!(!h.is_transaction_log());
        assert_eq!(h.root_cell_offset, 0x20);
        assert_eq!(h.data_size, 8192);
        assert_eq!(h.embedded_name, r"emRoot\System32\Config\SOFTWARE");
        assert_eq!(h.kind(), HiveKind::Software);
        assert_eq!(h.version(), "1.5");
        assert!(h.is_supported_version());
        assert!(h.timestamp().is_some());
    }

    #[test]
    fn rejects_short_and_foreign_bytes() {
        assert_eq!(HiveHeader::parse(&[], "t").unwrap_err().code, code::HEADER_TRUNCATED);
        assert_eq!(HiveHeader::parse(b"reg", "t").unwrap_err().code, code::HEADER_TRUNCATED);
        assert_eq!(HiveHeader::parse(&[0u8; 600], "t").unwrap_err().code, code::SIGNATURE_INVALID);
        let mut b = vec![0u8; 100];
        b[..4].copy_from_slice(b"regf");
        assert_eq!(HiveHeader::parse(&b, "t").unwrap_err().code, code::HEADER_TRUNCATED);
    }

    #[test]
    fn log_types_and_versions() {
        for (ft, legacy, new) in [(1u32, true, false), (2, true, false), (6, false, true), (0, false, false), (9, false, false)] {
            let b = base_block(1, 1, 0x20, 4096, "x", ft, 5);
            let h = HiveHeader::parse(&b, "t").unwrap();
            assert_eq!(h.is_legacy_log(), legacy, "type {ft}");
            assert_eq!(h.is_new_log(), new, "type {ft}");
            assert_eq!(h.is_transaction_log(), legacy || new);
        }
        for (minor, ok) in [(2u32, false), (3, true), (5, true), (6, true), (7, false)] {
            let b = base_block(1, 1, 0x20, 4096, "x", 0, minor);
            assert_eq!(HiveHeader::parse(&b, "t").unwrap().is_supported_version(), ok, "minor {minor}");
        }
    }

    #[test]
    fn checksum_corner_cases() {
        // All zero words XOR to 0, which Windows stores as 1.
        assert_eq!(compute_checksum(&[0u8; 512]), 1);
        let mut b = vec![0u8; 512];
        b[0..4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert_eq!(compute_checksum(&b), 0xffff_fffe);
        b[0..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        assert_eq!(compute_checksum(&b), 0x1234_5678);
        assert_eq!(compute_checksum(&b[..6]), 0x1234_5678, "a short slice counts what it has");
    }

    #[test]
    fn embedded_name_stops_at_nul_and_tolerates_short_input() {
        assert_eq!(decode_embedded_name(&[0u8; 10]), "");
        let b = base_block(1, 1, 0x20, 4096, "abc", 0, 5);
        assert_eq!(decode_embedded_name(&b), "abc");
        let long = "x".repeat(40);
        let b = base_block(1, 1, 0x20, 4096, &long, 0, 5);
        assert_eq!(decode_embedded_name(&b).len(), 32, "only the last 32 characters fit");
    }

    #[test]
    fn read_header_from_disk() {
        let d = crate::testing::TempDir::new("hdr");
        let p = HiveBuilder::system().write(&d.join("SYSTEM"));
        let h = read_header(&p).unwrap();
        assert_eq!(h.kind(), HiveKind::System);
        assert!(starts_with_regf(&p));

        assert_eq!(read_header(&d.join("missing")).unwrap_err().code, code::OPEN_FAILED);
        let empty = d.write("empty", b"");
        assert_eq!(read_header(&empty).unwrap_err().code, code::EMPTY_FILE);
        let short = d.write("short", &HiveBuilder::system().build()[..1024]);
        assert_eq!(read_header(&short).unwrap_err().code, code::HEADER_TRUNCATED, "a primary needs the whole block");
        let text = d.write("text", b"hello world, this is not a hive at all, just text");
        assert_eq!(read_header(&text).unwrap_err().code, code::SIGNATURE_INVALID);
        assert!(!starts_with_regf(&text));
        assert!(!starts_with_regf(&d.join("missing")));
    }
}
