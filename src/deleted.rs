//! Deleted keys and values recovered from the free cells of a hive.
//!
//! When a key or value is deleted, Windows only flips the sign of its cell size: the bytes
//! stay until the space is reused. The walk over every hive bin is `blockcarve::hive_cells`
//! (shared with caarea, faramir and masstin), which trusts no count or offset without
//! checking it, because free cells may hold garbage. This module gives the result the
//! crate's shape: typed data, timestamps, the path rebuilt through the parent chain, and
//! the codes.

use std::panic::{catch_unwind, AssertUnwindSafe};

use chrono::{DateTime, Utc};

use crate::diag;
use crate::header::BASE_BLOCK_SIZE;
use crate::value::{Data, ValueType};

/// Codes of this module (200-299: hive bins and cells).
pub mod code {
    crate::codes! {
        CELLS_NOT_A_HIVE = 200, "the bytes handed to the deleted-cell scan do not start with a base block and a hive bin; the scan was skipped";
        CELLS_SCAN_PANIC = 201, "the cell walker panicked on this hive (a shape it has never seen); the deleted entries of this hive are not reported, the live ones are";
        CELLS_SCANNED = 202, "the deleted-cell scan ran: bins, cells, live keys, deleted keys and orphan values counted";
        CELLS_CHAIN_BROKEN = 203, "a deleted key's parent chain could not be followed to the root (a parent cell was reused); its path starts with '?\\' and the reachable tail";
        CELLS_VALUE_NO_DATA = 204, "a deleted value's data cell was reused or is out of bounds; the value is reported by name and type without data";
        CELLS_DELETED_KEY = 205, "a deleted key was recovered";
        CELLS_ORPHAN_VALUE = 206, "a deleted value whose key is gone was recovered";
        CELLS_SKIPPED = 207, "the deleted-cell scan was not asked for (OpenOptions::recover_deleted = false)";
    }
}

/// Prefix of a path whose parent chain is broken.
pub const BROKEN_CHAIN_PREFIX: &str = blockcarve::hive_cells::BROKEN_CHAIN_PREFIX;

/// A deleted value, with or without its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedValue {
    /// Path of the key it belonged to, when known (`None` for an orphan).
    pub key_path: Option<String>,
    /// The value name; `(Default)` for the unnamed value.
    pub name: String,
    /// The declared type.
    pub kind: ValueType,
    /// The data, when its cell was still there.
    pub data: Data,
    /// The data cell was gone or out of bounds.
    pub data_lost: bool,
    /// Offset of the value cell, relative to the hive bins.
    pub offset: u32,
}

/// A deleted key with its values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedKey {
    /// Root-relative path, or `?\<tail>` when the parent chain is broken.
    pub path: String,
    /// The key name.
    pub name: String,
    /// Last write, as a FILETIME.
    pub last_written_filetime: u64,
    /// Last write as UTC, when in range.
    pub last_written: Option<DateTime<Utc>>,
    /// Offset of the key cell, relative to the hive bins.
    pub offset: u32,
    /// Offset of the parent key cell.
    pub parent_offset: u32,
    /// The values still attached to it.
    pub values: Vec<DeletedValue>,
}

impl DeletedKey {
    /// The parent chain could not be followed to the root.
    pub fn chain_broken(&self) -> bool {
        self.path.starts_with(BROKEN_CHAIN_PREFIX)
    }
}

/// One recovered entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deleted {
    /// A key (its values inside).
    Key(DeletedKey),
    /// A value whose key is gone.
    Value(DeletedValue),
}

/// Counts of a scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeletedStats {
    /// Hive bins walked.
    pub bins: usize,
    /// Cells seen.
    pub cells: usize,
    /// Allocated key cells.
    pub live_keys: usize,
    /// Deleted keys recovered.
    pub deleted_keys: usize,
    /// Deleted values recovered inside those keys.
    pub deleted_values: usize,
    /// Deleted values without a key.
    pub orphan_values: usize,
    /// The scan did not run.
    pub skipped: bool,
}

/// What the scan found.
#[derive(Debug, Clone, Default)]
pub struct DeletedScan {
    /// Counts.
    pub stats: DeletedStats,
    /// Keys first (sorted by path, then offset), then orphan values (by offset).
    pub entries: Vec<Deleted>,
}

fn value_from(v: blockcarve::hive_cells::RawValue, key_path: Option<&str>) -> DeletedValue {
    let kind = ValueType(v.data_type);
    let (data, data_lost) = match &v.data {
        Some(raw) => (Data::from_raw(kind, raw), false),
        None => {
            diag::info(code::CELLS_VALUE_NO_DATA, format!("{} ({kind}) at {:#x}", v.name, v.offset));
            (Data::None, true)
        }
    };
    let name = if v.name.is_empty() { crate::value::DEFAULT_VALUE_NAME.to_string() } else { v.name };
    DeletedValue { key_path: key_path.map(|s| s.to_string()), name, kind, data, data_lost, offset: v.offset }
}

/// Walks every hive bin of `bytes` (a whole hive, logs applied) and classifies its cells.
pub fn scan(bytes: &[u8]) -> Result<DeletedScan, crate::diag::Error> {
    if bytes.len() < BASE_BLOCK_SIZE + 32 || &bytes[..4] != crate::header::REGF_MAGIC {
        return Err(crate::err!(code::CELLS_NOT_A_HIVE, "{} bytes", bytes.len()));
    }
    let raw = match catch_unwind(AssertUnwindSafe(|| blockcarve::hive_cells::scan(bytes))) {
        Ok(Some(s)) => s,
        Ok(None) => return Err(crate::err!(code::CELLS_NOT_A_HIVE, "{} bytes, no hive bin", bytes.len())),
        Err(p) => return Err(crate::err!(code::CELLS_SCAN_PANIC, "{}", diag::panic_message(&*p))),
    };
    let mut out = DeletedScan::default();
    out.stats.bins = raw.bins;
    out.stats.cells = raw.cells;
    out.stats.live_keys = raw.live_keys;
    let mut keys: Vec<DeletedKey> = raw
        .deleted_keys
        .into_iter()
        .map(|dk| {
            let values: Vec<DeletedValue> = dk.values.into_iter().map(|v| value_from(v, Some(&dk.path))).collect();
            if dk.path.starts_with(BROKEN_CHAIN_PREFIX) {
                diag::info(code::CELLS_CHAIN_BROKEN, format!("{} at {:#x}", dk.path, dk.key.offset));
            }
            DeletedKey {
                path: dk.path,
                name: dk.key.name,
                last_written_filetime: dk.key.timestamp_filetime,
                last_written: crate::value::filetime_to_utc(dk.key.timestamp_filetime),
                offset: dk.key.offset,
                parent_offset: dk.key.parent,
                values,
            }
        })
        .collect();
    keys.sort_by(|a, b| a.path.to_lowercase().cmp(&b.path.to_lowercase()).then(a.offset.cmp(&b.offset)));
    let mut orphans: Vec<DeletedValue> = raw.orphan_values.into_iter().map(|v| value_from(v, None)).collect();
    orphans.sort_by_key(|v| v.offset);
    out.stats.deleted_keys = keys.len();
    out.stats.deleted_values = keys.iter().map(|k| k.values.len()).sum();
    out.stats.orphan_values = orphans.len();
    for k in &keys {
        diag::info(code::CELLS_DELETED_KEY, format!("{} ({} value(s)) at {:#x}", k.path, k.values.len(), k.offset));
    }
    for v in &orphans {
        diag::info(code::CELLS_ORPHAN_VALUE, format!("{} ({}) at {:#x}", v.name, v.kind, v.offset));
    }
    diag::info(code::CELLS_SCANNED, format!("{} bin(s), {} cell(s), {} live key(s), {} deleted key(s), {} orphan value(s)", out.stats.bins, out.stats.cells, out.stats.live_keys, out.stats.deleted_keys, out.stats.orphan_values));
    out.entries.extend(keys.into_iter().map(Deleted::Key));
    out.entries.extend(orphans.into_iter().map(Deleted::Value));
    Ok(out)
}

impl DeletedScan {
    /// The deleted keys.
    pub fn keys(&self) -> impl Iterator<Item = &DeletedKey> {
        self.entries.iter().filter_map(|e| match e {
            Deleted::Key(k) => Some(k),
            _ => None,
        })
    }

    /// The orphan values.
    pub fn orphans(&self) -> impl Iterator<Item = &DeletedValue> {
        self.entries.iter().filter_map(|e| match e {
            Deleted::Value(v) => Some(v),
            _ => None,
        })
    }

    /// Every deleted value, inside a key or orphan.
    pub fn values(&self) -> impl Iterator<Item = &DeletedValue> {
        self.entries.iter().flat_map(|e| match e {
            Deleted::Key(k) => k.values.iter().collect::<Vec<_>>(),
            Deleted::Value(v) => vec![v],
        })
    }

    /// Nothing recovered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    const RUN: &str = r"Microsoft\Windows\CurrentVersion\Run";

    #[test]
    fn clean_hive_has_no_deleted_cells() {
        let mut b = HiveBuilder::software();
        b.sz(RUN, "Live", r"C:\live.exe");
        let s = scan(&b.build()).unwrap();
        assert!(s.is_empty());
        assert!(s.stats.bins >= 1);
        assert!(s.stats.live_keys >= 5, "root + 4 path components, got {}", s.stats.live_keys);
        assert!(s.stats.cells > s.stats.live_keys);
        assert_eq!(s.stats.deleted_keys, 0);
    }

    #[test]
    fn deleted_value_becomes_orphan_with_its_data() {
        diag::clear();
        let mut b = HiveBuilder::software();
        b.sz(RUN, "Keep", r"C:\keep.exe").sz(RUN, "Gone", r"C:\gone.exe").delete_value(RUN, "Gone");
        let s = scan(&b.build()).unwrap();
        assert_eq!(s.keys().count(), 0);
        let orphans: Vec<&DeletedValue> = s.orphans().collect();
        assert_eq!(orphans.len(), 1);
        let v = orphans[0];
        assert_eq!(v.name, "Gone");
        assert_eq!(v.key_path, None);
        assert_eq!(v.kind, ValueType::SZ);
        assert_eq!(v.data, Data::Sz(r"C:\gone.exe".into()));
        assert!(!v.data_lost);
        assert_eq!(s.values().count(), 1);
        assert!(diag::has(code::CELLS_ORPHAN_VALUE));
        assert!(diag::has(code::CELLS_SCANNED));
        diag::clear();
    }

    #[test]
    fn deleted_key_is_recovered_with_path_and_values() {
        let mut b = HiveBuilder::system();
        b.dword("Select", "Current", 1)
            .sz(r"ControlSet001\Services\EvilSvc", "ImagePath", r"C:\Windows\Temp\evil.exe")
            .sz(r"ControlSet001\Services\EvilSvc", "DisplayName", "Evil")
            .dword(r"ControlSet001\Services\EvilSvc", "Start", 2)
            .sz(r"ControlSet001\Services\GoodSvc", "ImagePath", r"C:\good.exe")
            .delete_key(r"ControlSet001\Services\EvilSvc");
        let s = scan(&b.build()).unwrap();
        let keys: Vec<&DeletedKey> = s.keys().collect();
        assert_eq!(keys.len(), 1);
        let dk = keys[0];
        assert_eq!(dk.path, r"ControlSet001\Services\EvilSvc");
        assert_eq!(dk.name, "EvilSvc");
        assert!(!dk.chain_broken());
        assert_eq!(dk.last_written_filetime, FILETIME_2024);
        assert_eq!(crate::value::format_utc(&dk.last_written.unwrap()), "2024-01-17T21:20:00.000000Z");
        let names: Vec<&str> = dk.values.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, vec!["ImagePath", "DisplayName", "Start"]);
        assert_eq!(dk.values[0].data, Data::Sz(r"C:\Windows\Temp\evil.exe".into()));
        assert_eq!(dk.values[0].key_path.as_deref(), Some(r"ControlSet001\Services\EvilSvc"));
        assert_eq!(dk.values[2].data, Data::Dword(2));
        assert_eq!(dk.values[2].kind, ValueType::DWORD);
        assert_eq!(s.orphans().count(), 0, "values of a deleted key are not orphans");
        assert_eq!(s.stats.deleted_values, 3);
        assert_eq!(s.values().count(), 3);
    }

    #[test]
    fn deleted_subtree_resolves_every_level_in_order() {
        let mut b = HiveBuilder::software();
        b.sz(r"Microsoft\Active Setup\Installed Components\{EVIL}", "StubPath", r"C:\stub.exe").delete_key(r"Microsoft\Active Setup");
        let s = scan(&b.build()).unwrap();
        let paths: Vec<&str> = s.keys().map(|k| k.path.as_str()).collect();
        assert_eq!(paths, vec![r"Microsoft\Active Setup", r"Microsoft\Active Setup\Installed Components", r"Microsoft\Active Setup\Installed Components\{EVIL}"]);
    }

    #[test]
    fn garbage_free_cells_do_not_break_the_scan() {
        let mut b = HiveBuilder::software();
        b.sz(RUN, "Live", r"C:\live.exe").deleted_sz(RUN, "Gone", r"C:\gone.exe");
        let mut bytes = b.build();
        let len = bytes.len();
        let tail = &mut bytes[len - 512..];
        for i in (0..tail.len()).step_by(16) {
            tail[i..i + 4].copy_from_slice(&0x7FFF_FFF8u32.to_le_bytes());
            tail[i + 4..i + 6].copy_from_slice(if i % 32 == 0 { b"nk" } else { b"vk" });
            tail[i + 6..i + 16].copy_from_slice(&[0xEE; 10]);
        }
        let s = scan(&bytes).unwrap();
        let orphans: Vec<&DeletedValue> = s.orphans().collect();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].data, Data::Sz(r"C:\gone.exe".into()));
    }

    #[test]
    fn rejects_non_hive_bytes() {
        assert_eq!(scan(&[0u8; 100]).unwrap_err().code, code::CELLS_NOT_A_HIVE);
        assert_eq!(scan(&[0u8; 8192]).unwrap_err().code, code::CELLS_NOT_A_HIVE);
        // A base block followed by zeros is a hive with no bins: nothing to walk, nothing found.
        let mut b = vec![0u8; 4096 + 32];
        b[..4].copy_from_slice(b"regf");
        let s = scan(&b).unwrap();
        assert_eq!(s.stats.bins, 0);
        assert!(s.is_empty());
    }

    #[test]
    fn real_windows_hive_scans() {
        diag::clear();
        let bytes = std::fs::read(fixture("dirty_hive/NewDirtyHive")).unwrap();
        let s = scan(&bytes).unwrap();
        assert!(s.stats.bins >= 1);
        assert!(s.stats.live_keys >= 1);
        assert!(!diag::has(code::CELLS_SCAN_PANIC));
        let bytes = std::fs::read(fixture("clean_hive/testhive")).unwrap();
        let s = scan(&bytes).unwrap();
        assert!(s.stats.live_keys >= 1);
        diag::clear();
    }

    #[test]
    fn deleted_default_value_gets_its_name() {
        let mut b = HiveBuilder::software();
        b.sz(r"Classes\x\shell\open\command", "", r"C:\x.exe").delete_value(r"Classes\x\shell\open\command", "");
        let s = scan(&b.build()).unwrap();
        let o: Vec<&DeletedValue> = s.orphans().collect();
        assert_eq!(o.len(), 1);
        assert_eq!(o[0].name, crate::value::DEFAULT_VALUE_NAME);
    }
}
