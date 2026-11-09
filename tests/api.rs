//! The public surface as a tool uses it: re-exports, builder options, listings.

use dirtyhive::testing::*;
use dirtyhive::{diag, Data, Deleted, Hive, HiveKind, LogPolicy, OpenOptions, ValueType, Walk, WalkLimits};

#[test]
fn a_tool_lists_a_hive_one_row_per_value() {
    let d = TempDir::new("api_rows");
    let mut b = HiveBuilder::ntuser("bob");
    b.sz(r"Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive", r"C:\Users\bob\OneDrive.exe /background")
        .dword(r"Software\Microsoft\Windows\CurrentVersion\Explorer", "ShellState", 0x24)
        .binary(r"Software\Microsoft\Windows\Shell\BagMRU", "0", &[0x14, 0x00, 0x1f])
        .sz(r"Software\Gone", "Old", "x")
        .delete_key(r"Software\Gone");
    let p = b.write(&d.join("NTUSER.DAT"));
    let mut h = Hive::open(&p, &OpenOptions::new().logs(LogPolicy::Auto).recover_deleted(true)).unwrap();
    assert_eq!(h.info().kind, HiveKind::NtUser);

    let mut rows: Vec<String> = Vec::new();
    let hive_name = h.info().name.clone();
    h.walk(&WalkLimits::default(), |key| {
        for v in &key.values {
            rows.push(format!("{}\t{}\t{}\t{}\t{}\t{}", key.last_written_text(), hive_name, key.path, v.name, v.kind, v.data.display()));
        }
        Walk::Continue
    })
    .unwrap();
    assert_eq!(rows.len(), 3);
    assert!(rows[0].starts_with("2024-01-17T21:20:00.000000Z\tNTUSER.DAT\t"));
    assert!(rows.iter().any(|r| r.contains("\tOneDrive\tREG_SZ\tC:\\Users\\bob\\OneDrive.exe /background")));
    assert!(rows.iter().any(|r| r.contains("\tShellState\tREG_DWORD\t36 (0x00000024)")));
    assert!(rows.iter().any(|r| r.contains("\t0\tREG_BINARY\t14 00 1f")));

    let deleted: Vec<String> = h
        .deleted()
        .iter()
        .map(|e| match e {
            Deleted::Key(k) => format!("key {} ({} values)", k.path, k.values.len()),
            Deleted::Value(v) => format!("value {} = {}", v.name, v.data.display()),
        })
        .collect();
    assert_eq!(deleted, vec![r"key Software\Gone (1 values)"]);
    if let Deleted::Key(k) = &h.deleted()[0] {
        assert_eq!(k.values[0].data, Data::Sz("x".into()));
        assert_eq!(k.values[0].kind, ValueType::SZ);
        assert_eq!(k.values[0].key_path.as_deref(), Some(r"Software\Gone"));
    }
    assert_eq!(diag::summary().errors, 0);
    diag::clear();
}

#[test]
fn codes_are_documented_and_findable() {
    let all = diag::catalog();
    assert!(all.len() >= 80, "{}", all.len());
    for c in &all {
        assert_eq!(diag::lookup(&c.to_string()), Some(*c));
    }
    let md = diag::catalog_markdown();
    assert!(md.starts_with("# Diagnostic codes"));
    assert_eq!(md.matches("\n| `DH").count(), all.len());
}

#[test]
fn version_and_header_exports() {
    assert!(!dirtyhive::VERSION.is_empty());
    let d = TempDir::new("api_hdr");
    let p = HiveBuilder::system().write(&d.join("SYSTEM"));
    let h = dirtyhive::read_header(&p).unwrap();
    assert_eq!(h.kind(), HiveKind::System);
    assert_eq!(dirtyhive::BASE_BLOCK_SIZE, 4096);
    assert_eq!(dirtyhive::filetime_text(FILETIME_2024), "2024-01-17T21:20:00.000000Z");
    assert!(dirtyhive::filetime_to_utc(0).is_none());
}
