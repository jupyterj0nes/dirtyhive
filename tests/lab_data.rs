//! Real hives from the lab triage packages. Every test skips silently when the data is not
//! on this machine, so the suite is green anywhere and complete where the evidence is.

use std::path::{Path, PathBuf};

use dirtyhive::diag;
use dirtyhive::hive::code as hive_code;
use dirtyhive::txlog;
use dirtyhive::{Hive, HiveKind, OpenOptions, Walk, WalkLimits};

fn lab(rel: &str) -> Option<PathBuf> {
    let p = PathBuf::from(r"D:\evidence").join(rel);
    p.exists().then_some(p)
}

fn open(path: &Path, root: Option<&Path>) -> Hive {
    diag::clear();
    txlog::clear_log_index();
    let mut opts = OpenOptions::default();
    if let Some(r) = root {
        opts = opts.search_root(r);
    }
    Hive::open(path, &opts).unwrap_or_else(|e| panic!("{}: {e}\n{:?}", path.display(), diag::snapshot()))
}

#[test]
fn dirty_ntuser_whose_logs_are_ahead_stays_dirty_with_the_gap_reported() {
    // The lab copy of administrator_NTUSER.DAT says 71/70 while its logs hold entries 95 to
    // 98: the primary is a stale copy and the writes between were overwritten in the logs.
    // Windows would refuse to apply them too; the hive is read as it is, and the analyst is
    // told exactly why.
    let Some(p) = lab(r"mixed-intake\dev-srv01-hives\administrator_NTUSER.DAT") else { return };
    let mut h = open(&p, None);
    let info = h.info();
    assert_eq!(info.kind, HiveKind::NtUser);
    assert!(info.was_dirty, "the lab hive is dirty (sequence 71/70)");
    let found = info.logs_found.as_ref().expect("the logs next to the hive are located");
    assert!(found.log1.is_some() && found.log2.is_some(), "{found:?}");
    assert!(!info.recovered(), "{:?}", diag::snapshot());
    assert!(info.is_dirty);
    assert!(diag::has(txlog::code::LOG_GAP), "{:?}", diag::snapshot());
    assert!(diag::has(hive_code::DIRTY_KEPT));
    assert!(!diag::has(txlog::code::LOG_STALE), "a gap is not staleness");
    assert_eq!(diag::summary().errors, 0);
    // The profile has the usual HKCU layout, and every key walks.
    assert!(h.key(r"Software\Microsoft\Windows\CurrentVersion").unwrap().is_some());
    let stats = h.walk(&WalkLimits::default(), |_| Walk::Continue).unwrap();
    assert!(stats.keys > 100, "{stats:?}");
    assert_eq!(stats.failed_subkey_lists, 0);
    assert!(!stats.stopped);
    // The lab planted a deleted value; the free-cell scan brings it back.
    assert!(h.deleted_stats().orphan_values >= 1, "{:?}", h.deleted_stats());
    assert!(h.deleted_scan().orphans().any(|v| v.name.contains("Canary")), "{:?}", h.deleted_scan().orphans().map(|v| v.name.clone()).collect::<Vec<_>>());
    // Twice gives the same answer.
    let again = open(&p, None);
    assert_eq!(again.bytes(), h.bytes());
    assert_eq!(again.deleted().len(), h.deleted().len());
}

#[test]
fn clean_system_and_software_walk_completely() {
    let Some(root) = lab(r"lab-case\dev-srv01-triage") else { return };
    for (name, kind, key) in [("SYSTEM", HiveKind::System, "Select"), ("SOFTWARE", HiveKind::Software, r"Microsoft\Windows NT\CurrentVersion")] {
        let p = root.join(r"Windows\System32\config").join(name);
        if !p.exists() {
            continue;
        }
        let mut h = open(&p, Some(&root));
        assert_eq!(h.info().kind, kind);
        assert!(!h.info().was_dirty, "{name} is clean in the lab");
        let k = h.key(key).unwrap().unwrap_or_else(|| panic!("{name}: {key} missing"));
        assert!(!k.values.is_empty());
        let stats = h.walk(&WalkLimits::default(), |_| Walk::Continue).unwrap();
        assert!(stats.keys > 1000, "{name}: {stats:?}");
        assert_eq!(stats.failed_subkey_lists, 0, "{name}");
        assert_eq!(diag::summary().errors, 0, "{name}: {:?}", diag::snapshot());
    }
}

#[test]
fn system_current_control_set_resolves() {
    let Some(p) = lab(r"lab-case\dev-srv01-triage\Windows\System32\config\SYSTEM") else { return };
    let mut h = open(&p, None);
    let select = h.key("Select").unwrap().unwrap();
    let current = select.value("Current").and_then(|v| v.data.as_u64()).unwrap();
    let cs = format!("ControlSet{current:03}");
    let services = h.key(&format!(r"{cs}\Services")).unwrap().unwrap();
    assert!(services.subkey_count > 50);
    let names: Vec<String> = h.subkeys(&services).unwrap().iter().map(|k| k.name.to_lowercase()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "children come out sorted");
    let computer = h.string_value(&format!(r"{cs}\Control\ComputerName\ComputerName"), "ComputerName").unwrap().unwrap();
    assert_eq!(computer.to_uppercase(), "DEV-SRV01");
}

#[test]
fn dirty_amcache_is_handled() {
    let Some(p) = lab(r"lab-case\dev-srv01-triage\Windows\AppCompat\Programs\Amcache.hve") else { return };
    let mut h = open(&p, None);
    assert_eq!(h.info().kind, HiveKind::Amcache);
    assert!(h.info().was_dirty);
    // No log was collected with it: the hive stays dirty and is still readable.
    if !h.info().recovered() {
        assert!(h.info().is_dirty);
        assert!(diag::has(txlog::code::LOG_NOT_FOUND) || diag::has(hive_code::DIRTY_KEPT), "{:?}", diag::snapshot());
    }
    let root = h.root().unwrap();
    assert!(root.subkey_count >= 1);
    let stats = h.walk(&WalkLimits::default(), |_| Walk::Continue).unwrap();
    assert!(stats.keys > 10, "{stats:?}");
    assert_eq!(diag::summary().errors, 0);
}

#[test]
fn every_user_hive_of_the_triage_opens() {
    let Some(root) = lab(r"lab-case\dev-srv01-triage\Users") else { return };
    let (found, stats) = dirtyhive::discover(&root);
    assert!(stats.hives >= 5, "{stats:?}");
    assert_eq!(found.len(), stats.hives);
    assert!(found.iter().any(|d| d.kind == HiveKind::NtUser));
    for d in &found {
        // systemprofile's NTUSER.DAT is the DEFAULT hive and says so in its header.
        assert!(matches!(d.kind, HiveKind::NtUser | HiveKind::UsrClass | HiveKind::Default), "{}: {}", d.path.display(), d.kind);
        let mut h = open(&d.path, Some(&root));
        let s = h.walk(&WalkLimits::default(), |_| Walk::Continue).unwrap();
        assert!(s.keys >= 1, "{}", d.path.display());
        assert_eq!(diag::summary().errors, 0, "{}: {:?}", d.path.display(), diag::snapshot());
    }
}

#[test]
fn deleted_scan_runs_on_real_hives_without_panics() {
    let Some(root) = lab(r"lab-case\dev-srv01-triage\Windows\System32\config") else { return };
    for name in ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"] {
        let p = root.join(name);
        if !p.exists() {
            continue;
        }
        let h = open(&p, None);
        let st = h.deleted_stats();
        assert!(st.bins >= 1, "{name}");
        assert!(st.live_keys >= 1, "{name}");
        assert!(!diag::has(dirtyhive::deleted::code::CELLS_SCAN_PANIC), "{name}");
        for d in h.deleted() {
            if let dirtyhive::Deleted::Key(k) = d {
                assert!(!k.name.is_empty(), "{name}: a deleted key without a name");
            }
        }
    }
}

#[test]
fn discovery_over_the_mixed_intake_finds_the_hives_and_skips_the_logs() {
    let Some(root) = lab(r"mixed-intake\dev-srv01-hives") else { return };
    diag::clear();
    let (found, stats) = dirtyhive::discover(&root);
    assert_eq!(stats.hives, 1, "{found:?}");
    assert_eq!(stats.companions, 2, "LOG1 and LOG2");
    assert_eq!(found[0].kind, HiveKind::NtUser);
    assert!(found[0].is_dirty());
}
