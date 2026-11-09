//! Finding the hives under a folder (a triage package, an extracted image, a case).
//!
//! Companion files (`.LOG1`, `.blf`, `.regtrans-ms`, …) are skipped, files are only
//! sniffed when their name or extension looks hive-like or their size is a multiple of
//! 4 KiB with no extension, and everything that is not `regf` is ignored.

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::diag;
use crate::header::{self, HiveHeader};
use crate::kind::{self, HiveKind};

/// Codes of this module (400-449: discovery).
pub mod code {
    crate::codes! {
        DISCOVERY_IO = 400, "a folder or file could not be listed or read while walking for hives; the rest of the tree was still walked";
        COMPANION_SKIPPED = 401, "a registry companion file (.LOG1/.LOG2/.blf/.regtrans-ms/.TMP/.SAV) was seen and left for the log locator; it is not a hive";
        DUPLICATE_SKIPPED = 402, "the same hive file was reached twice (a link or a double path); counted once";
        NOT_REGF_SKIPPED = 403, "a file named like a hive does not start with 'regf'; it is not a hive (empty, text, a stub) and was skipped";
        HIVE_FOUND = 404, "a primary hive was found and classified";
        UNREADABLE_HIVE = 405, "a file that starts with 'regf' could not be read as a primary hive (log, truncated, wrong version); skipped with the reason";
        DISCOVERY_DONE = 406, "the walk finished: files seen, hives found, dirty hives";
        ROOT_MISSING = 407, "the folder given to walk does not exist";
    }
}

/// A hive found under a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// The file.
    pub path: PathBuf,
    /// Header first, then name.
    pub kind: HiveKind,
    /// What the name said.
    pub name_kind: HiveKind,
    /// Its base block.
    pub header: HiveHeader,
    /// Size in bytes.
    pub size: u64,
}

impl Discovered {
    /// Dirty on disk.
    pub fn is_dirty(&self) -> bool {
        self.header.is_dirty()
    }

    /// `<path> [SOFTWARE]`.
    pub fn label(&self) -> String {
        format!("{} [{}]", self.path.display(), self.kind)
    }
}

/// Counts of a walk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiscoveryStats {
    /// Files looked at.
    pub files: usize,
    /// Hives found.
    pub hives: usize,
    /// Of which dirty.
    pub dirty: usize,
    /// Companion files seen.
    pub companions: usize,
}

/// Reads and checks one file as a primary hive.
pub fn classify_file(path: &Path) -> crate::diag::Result<Discovered> {
    let header = header::read_header(path)?;
    let label = path.display().to_string();
    if header.is_transaction_log() {
        return Err(crate::err!(crate::hive::code::NOT_PRIMARY, "{label} (file type {})", header.file_type));
    }
    if !header.is_primary() {
        return Err(crate::err!(crate::hive::code::UNEXPECTED_FILE_TYPE, "{label} (file type {})", header.file_type));
    }
    if !header.is_supported_version() {
        return Err(crate::err!(crate::hive::code::UNSUPPORTED_VERSION, "{label} (version {})", header.version()));
    }
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let name_kind = HiveKind::from_file_name(&name);
    let kind = HiveKind::resolve(header.kind(), name_kind);
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    Ok(Discovered { path: path.to_path_buf(), kind, name_kind, header, size })
}

/// Walks `root` (or takes it as the one file) and returns every primary hive, sorted by path.
pub fn discover(root: &Path) -> (Vec<Discovered>, DiscoveryStats) {
    let mut out: Vec<Discovered> = Vec::new();
    let mut stats = DiscoveryStats::default();
    if !root.exists() {
        diag::warn(code::ROOT_MISSING, root.display().to_string());
        return (out, stats);
    }
    if root.is_file() {
        stats.files = 1;
        match classify_file(root) {
            Ok(d) => {
                stats.hives = 1;
                stats.dirty = usize::from(d.is_dirty());
                diag::info(code::HIVE_FOUND, d.label());
                out.push(d);
            }
            Err(e) => {
                diag::warn(code::UNREADABLE_HIVE, e.to_string());
            }
        }
        return (out, stats);
    }

    let mut seen: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(root).into_iter() {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                diag::warn(code::DISCOVERY_IO, e.to_string());
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        stats.files += 1;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        if kind::is_companion_file(&name) {
            stats.companions += 1;
            if kind::companion_base_kind(&name) != HiveKind::Unknown {
                diag::info(code::COMPANION_SKIPPED, path.display().to_string());
            }
            continue;
        }

        let name_kind = HiveKind::from_file_name(&name);
        let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let looks_like_hive = name_kind != HiveKind::Unknown || kind::has_hive_like_extension(&name) || (!name.contains('.') && len >= 8192 && len % 4096 == 0);
        if !looks_like_hive {
            continue;
        }
        if !header::starts_with_regf(path) {
            if name_kind != HiveKind::Unknown && len > 0 {
                diag::info(code::NOT_REGF_SKIPPED, path.display().to_string());
            }
            continue;
        }
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if seen.contains(&canonical) {
            diag::info(code::DUPLICATE_SKIPPED, path.display().to_string());
            continue;
        }
        match classify_file(path) {
            Ok(d) => {
                seen.push(canonical);
                stats.hives += 1;
                stats.dirty += usize::from(d.is_dirty());
                diag::info(code::HIVE_FOUND, format!("{}{}", d.label(), if d.is_dirty() { " (dirty)" } else { "" }));
                out.push(d);
            }
            Err(e) => {
                diag::warn(code::UNREADABLE_HIVE, e.to_string());
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    diag::info(code::DISCOVERY_DONE, format!("{}: {} file(s), {} hive(s), {} dirty", root.display(), stats.files, stats.hives, stats.dirty));
    (out, stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    #[test]
    fn finds_hives_skips_companions_and_junk() {
        diag::clear();
        let d = TempDir::new("disc");
        HiveBuilder::software().write(&d.join("C/Windows/System32/config/SOFTWARE"));
        HiveBuilder::system().write_with(&d.join("C/Windows/System32/config/SYSTEM"), 7, 6);
        HiveBuilder::ntuser("bob").write(&d.join("C/Users/bob/NTUSER.DAT"));
        HiveBuilder::anonymous().write(&d.join("odd/blob.hve"));
        let mut tall = HiveBuilder::anonymous();
        tall.min_bin_size = 8192;
        tall.write(&d.join("odd/noext"));
        d.write("C/Windows/System32/config/SYSTEM.LOG1", b"regf log");
        d.write("C/Windows/System32/config/SOFTWARE", &HiveBuilder::software().build());
        d.write("C/Users/bob/NTUSER.DAT{guid}.TM.blf", b"blf");
        d.write("notes/SYSTEM", b"this is a text file named like a hive");
        d.write("notes/readme.txt", b"hello");
        d.write("C/Users/bob/UsrClass.dat", b"");
        let (found, stats) = discover(&d.path);
        let names: Vec<String> = found.iter().map(|f| f.path.strip_prefix(&d.path).unwrap().to_string_lossy().replace('\\', "/")).collect();
        assert_eq!(names, vec!["C/Users/bob/NTUSER.DAT", "C/Windows/System32/config/SOFTWARE", "C/Windows/System32/config/SYSTEM", "odd/blob.hve", "odd/noext"]);
        assert_eq!(stats.hives, 5);
        assert_eq!(stats.dirty, 1);
        assert_eq!(stats.companions, 2);
        assert!(stats.files >= 10);
        let sys = found.iter().find(|f| f.kind == HiveKind::System).unwrap();
        assert!(sys.is_dirty());
        assert!(sys.label().ends_with("[SYSTEM]"));
        assert_eq!(found.iter().filter(|f| f.kind == HiveKind::Unknown).count(), 2);
        assert!(diag::has(code::COMPANION_SKIPPED));
        assert!(diag::has(code::NOT_REGF_SKIPPED));
        assert!(diag::has(code::DISCOVERY_DONE));
        assert!(diag::has(code::HIVE_FOUND));
        diag::clear();
    }

    #[test]
    fn single_file_and_missing_root() {
        diag::clear();
        let d = TempDir::new("disc_one");
        let p = HiveBuilder::software().write(&d.join("SOFTWARE"));
        let (found, stats) = discover(&p);
        assert_eq!(found.len(), 1);
        assert_eq!(stats.files, 1);
        assert_eq!(found[0].size, std::fs::metadata(&p).unwrap().len());
        let (found, _) = discover(&d.join("nothing"));
        assert!(found.is_empty());
        assert!(diag::has(code::ROOT_MISSING));
        diag::clear();
        let log = d.write("SOFTWARE.LOG1", &build_log(&HiveBuilder::software().build_with(6, 5), &[]));
        let (found, _) = discover(&log);
        assert!(found.is_empty());
        assert!(diag::has(code::UNREADABLE_HIVE));
        assert_eq!(classify_file(&log).unwrap_err().code, crate::hive::code::NOT_PRIMARY);
        let mut old = HiveBuilder::software();
        old.minor_version = 9;
        let p = old.write(&d.join("old/SOFTWARE"));
        assert_eq!(classify_file(&p).unwrap_err().code, crate::hive::code::UNSUPPORTED_VERSION);
        diag::clear();
    }
}
