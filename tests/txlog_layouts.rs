//! Locating LOG1/LOG2 across collector layouts and surviving damaged logs, end to end
//! through `Hive::open`.

use std::path::{Path, PathBuf};

use dirtyhive::diag;
use dirtyhive::hive::code as hive_code;
use dirtyhive::testing::*;
use dirtyhive::txlog::{self, code as log_code, LogSlot, LogTarget};
use dirtyhive::{Hive, HiveKind, OpenOptions};

const RUN: &str = r"Microsoft\Windows\CurrentVersion\Run";

/// SOFTWARE hive whose log adds Run\Marker = C:\marker.exe
fn software_fixture(secondary: u32) -> DirtyFixture {
    let base = HiveBuilder::software();
    let mut step = HiveBuilder::software();
    step.sz(RUN, "Marker", r"C:\marker.exe");
    build_dirty(&base, &[&step], secondary, false)
}

fn ntuser_fixture(user: &str, marker: &str) -> DirtyFixture {
    let base = HiveBuilder::ntuser(user);
    let mut step = HiveBuilder::ntuser(user);
    step.sz(&format!(r"SOFTWARE\{RUN}"), "Marker", marker);
    build_dirty(&base, &[&step], 5, false)
}

/// Opens with the folder as search root: (logs applied, Marker, logs used).
fn open_and_marker(hive: &Path, root: &Path, path: &str) -> (bool, Option<String>, Vec<PathBuf>) {
    diag::clear();
    txlog::clear_log_index();
    let mut h = Hive::open(hive, &OpenOptions::new().search_root(root)).unwrap();
    let marker = h.string_value(path, "Marker").unwrap();
    let logs = h.info().logs_applied.iter().map(|l| l.path.clone()).collect();
    (h.info().recovered(), marker, logs)
}

#[test]
fn kape_layout_logs_next_to_hive() {
    let d = TempDir::new("loc_kape");
    let fx = software_fixture(5);
    let hive = write_dirty(&d, "C/Windows/System32/config/SOFTWARE", &fx);
    let (applied, marker, logs) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
    assert_eq!(logs, vec![d.join("C/Windows/System32/config/SOFTWARE.LOG1")]);
    assert!(!diag::has(log_code::LOG_REMOTE_MATCH));
}

#[test]
fn lowercase_log_extension_is_found() {
    let d = TempDir::new("loc_lower");
    let fx = software_fixture(5);
    let hive = d.write("config/software", &fx.primary);
    d.write("config/software.log1", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
}

#[test]
fn image_dump_layout_user_prefixed_names() {
    let d = TempDir::new("loc_image");
    let fx = ntuser_fixture("bob", r"C:\bob.exe");
    let hive = write_dirty(&d, "partition_0/Users/bob_NTUSER.DAT", &fx);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, &format!(r"SOFTWARE\{RUN}"));
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\bob.exe"));
}

#[test]
fn flattened_collector_names_in_same_folder() {
    let d = TempDir::new("loc_flat");
    let fx = software_fixture(5);
    let hive = write_dirty(&d, "output/C_Windows_System32_config_SOFTWARE", &fx);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
    let h = Hive::open(&hive, &OpenOptions::default()).unwrap();
    assert_eq!(h.info().kind, HiveKind::Software);
}

#[test]
fn flattened_collector_logs_in_separate_folder() {
    let d = TempDir::new("loc_flat_sep");
    let fx = software_fixture(5);
    let hive = d.write("output/registry/C_Windows_System32_config_SOFTWARE", &fx.primary);
    d.write("output/logs/C_Windows_System32_config_SOFTWARE.LOG1", &fx.log1);
    let (applied, marker, logs) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied, "{:?}", diag::snapshot());
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
    assert_eq!(logs, vec![d.join("output/logs/C_Windows_System32_config_SOFTWARE.LOG1")]);
    assert!(diag::has(log_code::LOG_REMOTE_MATCH));
}

#[test]
fn parallel_tree_canonical_names() {
    let d = TempDir::new("loc_parallel");
    let fx = software_fixture(5);
    let hive = d.write("files/C/Windows/System32/config/SOFTWARE", &fx.primary);
    d.write("logs/C/Windows/System32/config/SOFTWARE.LOG1", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
}

#[test]
fn prefixed_hive_with_canonical_log_elsewhere() {
    let d = TempDir::new("loc_prefix_canon");
    let fx = ntuser_fixture("bob", r"C:\bob.exe");
    let hive = d.write("hives/bob_NTUSER.DAT", &fx.primary);
    d.write("Users/bob/NTUSER.DAT.LOG1", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, &format!(r"SOFTWARE\{RUN}"));
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\bob.exe"));
}

#[test]
fn copy_suffix_hive_finds_plain_log() {
    let d = TempDir::new("loc_hve");
    let fx = software_fixture(5);
    let hive = d.write("SOFTWARE.hve", &fx.primary);
    d.write("SOFTWARE.LOG1", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
}

#[test]
fn two_users_are_disambiguated_by_embedded_name() {
    let d = TempDir::new("loc_users");
    let bob = ntuser_fixture("bob", r"C:\bob.exe");
    let alice = ntuser_fixture("alice", r"C:\alice.exe");
    let bob_hive = d.write("files/Users/bob/NTUSER.DAT", &bob.primary);
    d.write("files/Users/alice/NTUSER.DAT", &alice.primary);
    d.write("logs/1/NTUSER.DAT.LOG1", &alice.log1);
    d.write("logs/2/NTUSER.DAT.LOG1", &bob.log1);
    let (applied, marker, logs) = open_and_marker(&bob_hive, &d.path, &format!(r"SOFTWARE\{RUN}"));
    assert!(applied, "{:?}", diag::snapshot());
    assert_eq!(marker.as_deref(), Some(r"C:\bob.exe"));
    assert_eq!(logs, vec![d.join("logs/2/NTUSER.DAT.LOG1")]);
    assert!(diag::has(log_code::LOG_FOREIGN), "alice's log must be rejected");
}

#[test]
fn foreign_log_in_same_folder_is_rejected_and_remote_one_used() {
    let d = TempDir::new("loc_foreign");
    let sw = software_fixture(5);
    let sys = {
        let base = HiveBuilder::system();
        let step = HiveBuilder::system();
        build_dirty(&base, &[&step], 5, false)
    };
    let hive = d.write("a/SOFTWARE", &sw.primary);
    d.write("a/SOFTWARE.LOG1", &sys.log1);
    d.write("b/SOFTWARE.LOG1", &sw.log1);
    let (applied, marker, logs) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied, "{:?}", diag::snapshot());
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
    assert_eq!(logs, vec![d.join("b/SOFTWARE.LOG1")]);
    assert!(diag::has(log_code::LOG_FOREIGN));
}

#[test]
fn equally_good_candidates_raise_ambiguous_warning() {
    let d = TempDir::new("loc_ambig");
    let fx = software_fixture(5);
    let hive = d.write("hives/SOFTWARE", &fx.primary);
    d.write("x/SOFTWARE.LOG1", &fx.log1);
    d.write("y/SOFTWARE.LOG1", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
    assert!(diag::has(log_code::LOG_AMBIGUOUS));
}

#[test]
fn same_folder_beats_remote_even_with_better_name() {
    let d = TempDir::new("loc_samedir");
    let fx = software_fixture(5);
    let hive = d.write("cfg/SOFTWARE", &fx.primary);
    d.write("cfg/SOFTWARE.LOG1", &fx.log1);
    d.write("elsewhere/SOFTWARE.LOG1", &fx.log1);
    let (_, _, logs) = open_and_marker(&hive, &d.path, RUN);
    assert_eq!(logs, vec![d.join("cfg/SOFTWARE.LOG1")]);
    assert!(!diag::has(log_code::LOG_REMOTE_MATCH));
}

#[test]
fn log1_and_log2_alternate() {
    let d = TempDir::new("loc_pair");
    let base = HiveBuilder::software();
    let mut s1 = HiveBuilder::software();
    s1.sz(RUN, "First", "1");
    let mut s2 = HiveBuilder::software();
    s2.sz(RUN, "First", "1").sz(RUN, "Marker", r"C:\marker.exe");
    let fx = build_dirty(&base, &[&s1, &s2], 5, true);
    let hive = write_dirty(&d, "SOFTWARE", &fx);
    let (applied, marker, logs) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied, "{:?}", diag::snapshot());
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
    assert_eq!(logs.len(), 2);
    let mut h = Hive::open(&hive, &OpenOptions::default()).unwrap();
    assert_eq!(h.string_value(RUN, "First").unwrap().as_deref(), Some("1"));
    assert_eq!(h.info().header_after.primary_sequence, 7);
}

#[test]
fn no_logs_anywhere() {
    let d = TempDir::new("loc_none");
    let fx = software_fixture(5);
    let hive = d.write("SOFTWARE", &fx.primary);
    let (applied, marker, logs) = open_and_marker(&hive, &d.path, RUN);
    assert!(!applied);
    assert_eq!(marker, None);
    assert!(logs.is_empty());
    assert!(diag::has(log_code::LOG_NOT_FOUND));
    assert!(diag::has(hive_code::DIRTY_KEPT));
}

#[test]
fn only_legacy_named_log_present_but_new_format_inside() {
    // A `.LOG` with a new-format body: it is found through the legacy slot, inspected,
    // rejected as "legacy" by name only, and the replay engine then reads it by content.
    let d = TempDir::new("loc_legacy_name");
    let fx = software_fixture(5);
    let hive = d.write("SOFTWARE", &fx.primary);
    d.write("SOFTWARE.LOG", &fx.log1);
    let (applied, marker, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied, "{:?}", diag::snapshot());
    assert_eq!(marker.as_deref(), Some(r"C:\marker.exe"));
}

#[test]
fn legacy_type_log_that_does_not_match_leaves_hive_dirty() {
    let d = TempDir::new("loc_legacy");
    let fx = software_fixture(5);
    let hive = d.write("SOFTWARE", &fx.primary);
    let mut legacy = fx.log1.clone();
    patch_base_block(&mut legacy, 6, 6, 1);
    d.write("SOFTWARE.LOG", &legacy);
    let (applied, _, _) = open_and_marker(&hive, &d.path, RUN);
    assert!(!applied);
    assert!(diag::has(log_code::LOG_LEGACY_FORMAT));
    assert!(diag::has(hive_code::DIRTY_KEPT));
}

#[test]
fn garbage_log_is_rejected_hive_still_usable() {
    let d = TempDir::new("loc_garbage");
    let mut base = HiveBuilder::software();
    base.sz(RUN, "Existing", r"C:\e.exe");
    let mut step = HiveBuilder::software();
    step.sz(RUN, "Existing", r"C:\e.exe").sz(RUN, "Marker", r"C:\m.exe");
    let fx = build_dirty(&base, &[&step], 5, false);
    let hive = d.write("SOFTWARE", &fx.primary);
    d.write("SOFTWARE.LOG1", &vec![0x41u8; 4096]);
    diag::clear();
    txlog::clear_log_index();
    let mut h = Hive::open(&hive, &OpenOptions::default()).unwrap();
    assert!(!h.info().recovered());
    assert!(diag::has(log_code::LOG_SIGNATURE_INVALID));
    assert!(diag::has(hive_code::DIRTY_KEPT));
    assert_eq!(h.string_value(RUN, "Existing").unwrap().as_deref(), Some(r"C:\e.exe"));
    assert_eq!(h.string_value(RUN, "Marker").unwrap(), None);
}

#[test]
fn truncated_log_tail_is_cut_and_valid_prefix_applied() {
    let d = TempDir::new("loc_partial");
    let base = HiveBuilder::software();
    let mut s1 = HiveBuilder::software();
    s1.sz(RUN, "First", r"C:\1.exe");
    let mut s2 = HiveBuilder::software();
    s2.sz(RUN, "First", r"C:\1.exe").sz(RUN, "Second", r"C:\2.exe");
    let fx = build_dirty(&base, &[&s1, &s2], 5, false);
    let hive = d.write("SOFTWARE", &fx.primary);
    let cut = fx.log1.len() - 700;
    d.write("SOFTWARE.LOG1", &fx.log1[..cut]);
    diag::clear();
    txlog::clear_log_index();
    let mut h = Hive::open(&hive, &OpenOptions::default()).unwrap();
    assert!(h.info().recovered(), "{:?}", diag::snapshot());
    assert!(!h.info().logs_applied[0].complete);
    assert!(diag::has(log_code::LOG_TRUNCATED));
    assert!(diag::has(log_code::LOG_PARTIAL));
    assert_eq!(h.string_value(RUN, "First").unwrap().as_deref(), Some(r"C:\1.exe"));
    assert_eq!(h.string_value(RUN, "Second").unwrap(), None);
}

#[test]
fn corrupt_page_reference_never_reaches_the_replay() {
    let d = TempDir::new("loc_pageref");
    let base = HiveBuilder::software();
    let mut s1 = HiveBuilder::software();
    s1.sz(RUN, "First", r"C:\1.exe");
    let s2 = s1.clone();
    let fx = build_dirty(&base, &[&s1, &s2], 5, false);
    let hive = d.write("SOFTWARE", &fx.primary);
    let mut log = fx.log1.clone();
    let summary = txlog::inspect_log_bytes(Path::new("x"), &log).unwrap();
    let off2 = summary.entries[1].offset as usize;
    log[off2 + 44..off2 + 48].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    d.write("SOFTWARE.LOG1", &log);
    diag::clear();
    txlog::clear_log_index();
    let mut h = Hive::open(&hive, &OpenOptions::default()).unwrap();
    assert!(h.info().recovered(), "{:?}", diag::snapshot());
    assert!(diag::has(log_code::LOG_ENTRY_INVALID));
    assert_eq!(h.string_value(RUN, "First").unwrap().as_deref(), Some(r"C:\1.exe"));
}

#[test]
fn stale_logs_only_leave_hive_dirty_with_warning() {
    let d = TempDir::new("loc_stale");
    let fx = software_fixture(5);
    let hive = d.write("SOFTWARE", &HiveBuilder::software().build_with(10, 9));
    d.write("SOFTWARE.LOG1", &fx.log1);
    diag::clear();
    txlog::clear_log_index();
    let h = Hive::open(&hive, &OpenOptions::default()).unwrap();
    assert!(!h.info().recovered());
    assert!(h.info().logs_found.as_ref().unwrap().log1.is_some(), "the log is located and attributed");
    assert!(diag::has(log_code::LOG_STALE));
    assert!(!diag::has(hive_code::RECOVERED));
}

#[test]
fn log_starting_later_is_applied_by_the_format() {
    // The hive says 6/5, the log starts at 21 (its own base block) with entry 21: by the regf
    // specification (transaction logs, note 7) recovery starts at the log's base block
    // sequence when it is not less than the hive's secondary one. Applied, and the writes
    // 6 to 20 that no log holds any more are named.
    let d = TempDir::new("loc_ahead");
    let base = HiveBuilder::software();
    let mut step = HiveBuilder::software();
    step.sz(RUN, "Marker", r"C:\m.exe");
    let fx = build_dirty(&base, &[&step], 20, false);
    let hive = d.write("SOFTWARE", &HiveBuilder::software().build_with(6, 5));
    d.write("SOFTWARE.LOG1", &fx.log1);
    diag::clear();
    txlog::clear_log_index();
    let mut h = Hive::open(&hive, &OpenOptions::default()).unwrap();
    assert!(h.info().recovered(), "{:?}", diag::snapshot());
    assert!(diag::has(log_code::LOG_AHEAD));
    assert!(!diag::has(log_code::LOG_GAP));
    let k = h.key(RUN).unwrap().expect("Run key");
    assert!(k.values.iter().any(|v| v.name == "Marker"), "the write held only by the log is there");
}

#[test]
fn log_whose_entries_miss_its_own_start_is_not_applied() {
    // The same log with its base block saying 19: no entry carries 19, so it cannot start a
    // recovery (note 7); the hive is read as it is and the gap is reported.
    let d = TempDir::new("loc_gap");
    let base = HiveBuilder::software();
    let mut step = HiveBuilder::software();
    step.sz(RUN, "Marker", r"C:\m.exe");
    let fx = build_dirty(&base, &[&step], 20, false);
    let mut log = fx.log1.clone();
    patch_base_block(&mut log[..512], 19, 19, 6);
    let hive = d.write("SOFTWARE", &HiveBuilder::software().build_with(6, 5));
    d.write("SOFTWARE.LOG1", &log);
    diag::clear();
    txlog::clear_log_index();
    let h = Hive::open(&hive, &OpenOptions::default()).unwrap();
    assert!(!h.info().recovered(), "{:?}", diag::snapshot());
    assert!(diag::has(log_code::LOG_GAP));
}

#[test]
fn clean_hive_never_touches_logs() {
    let d = TempDir::new("loc_clean");
    let mut b = HiveBuilder::software();
    b.sz(RUN, "X", "y.exe");
    let hive = b.write(&d.join("SOFTWARE"));
    d.write("SOFTWARE.LOG1", &[0x41u8; 1024]);
    diag::clear();
    let h = Hive::open(&hive, &OpenOptions::default()).unwrap();
    assert!(!h.info().was_dirty);
    assert!(h.info().logs_found.is_none());
    assert!(!diag::has(log_code::LOG_SIGNATURE_INVALID));
}

#[test]
fn search_root_is_optional_and_file_roots_do_not_walk() {
    let d = TempDir::new("loc_root");
    let fx = software_fixture(5);
    let hive = d.write("hives/SOFTWARE", &fx.primary);
    d.write("logs/SOFTWARE.LOG1", &fx.log1);
    diag::clear();
    txlog::clear_log_index();
    // No search root: the log in another folder is never seen.
    let h = Hive::open(&hive, &OpenOptions::default()).unwrap();
    assert!(!h.info().recovered());
    assert!(diag::has(log_code::LOG_NOT_FOUND));
    // With the root it is.
    let (applied, _, logs) = open_and_marker(&hive, &d.path, RUN);
    assert!(applied);
    assert_eq!(logs, vec![d.join("logs/SOFTWARE.LOG1")]);
    // The locator's own API, with a file as root.
    let header = dirtyhive::read_header(&hive).unwrap();
    let target = LogTarget { path: &hive, header: &header, kind: HiveKind::Software, search_root: Some(&hive) };
    assert!(txlog::find_candidates(&target, LogSlot::Log1).is_empty());
    let sel = txlog::locate_logs(&target);
    assert!(sel.is_empty());
}

#[test]
fn diagnostics_summarise_a_recovery() {
    let d = TempDir::new("loc_diag");
    let fx = software_fixture(5);
    let hive = write_dirty(&d, "SOFTWARE", &fx);
    diag::clear();
    txlog::clear_log_index();
    let _ = Hive::open(&hive, &OpenOptions::default()).unwrap();
    let s = diag::summary();
    assert_eq!(s.errors, 0);
    assert_eq!(s.warnings, 0, "{:?}", diag::snapshot());
    assert!(s.infos >= 4, "candidate, applied, recovered, scanned, opened: {:?}", diag::snapshot());
    let texts: Vec<String> = diag::drain().into_iter().map(|d| d.to_string()).collect();
    assert!(texts.iter().any(|t| t.contains("DH017_RECOVERED")), "{texts:?}");
    assert!(diag::snapshot().is_empty());
}
