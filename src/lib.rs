//! Windows registry hives read the forensic way.
//!
//! A hive copied from a live machine or carved out of an image is usually *dirty*: its
//! last writes sit in the transaction logs (`.LOG1` / `.LOG2`) rather than in the file.
//! Keys and values deleted before the copy are still in its free cells. This crate opens a
//! hive the way an analyst needs it:
//!
//! 1. reads and checks the base block ([`header`]), classifies the hive ([`kind`]);
//! 2. finds its transaction logs even when the collector renamed or moved them, validates
//!    every entry, and replays the valid prefix ([`txlog`], the replay engine is
//!    `blockcarve::hive_logs`, shared with caarea, faramir and masstin);
//! 3. hands the clean bytes to [`nt_hive2`] for keys and values ([`hive`], [`value`]);
//! 4. walks the free cells for deleted keys and values ([`deleted`]).
//!
//! Every degraded path records a diagnostic with a stable code (`DH###_NAME`, see
//! [`diag`]) and the work goes on with what is there.
//!
//! ```no_run
//! use dirtyhive::{Hive, OpenOptions, Walk, WalkLimits};
//!
//! let mut hive = Hive::open(std::path::Path::new("SOFTWARE"), &OpenOptions::new().search_root("evidence")).unwrap();
//! println!("{}", hive.info().summary());
//! hive.walk(&WalkLimits::default(), |key| {
//!     for v in &key.values {
//!         println!("{}\\{} = {}", key.path, v.name, v.data.display());
//!     }
//!     Walk::Continue
//! }).unwrap();
//! for d in hive.deleted() {
//!     println!("{d:?}");
//! }
//! for d in dirtyhive::diag::drain() {
//!     eprintln!("{d}");
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod deleted;
pub mod diag;
pub mod discover;
pub mod header;
pub mod hive;
pub mod kind;
pub mod testing;
pub mod txlog;
pub mod value;

pub use deleted::{Deleted, DeletedKey, DeletedScan, DeletedStats, DeletedValue};
pub use diag::{Code, Diagnostic, Error, Severity};
pub use discover::{discover, Discovered, DiscoveryStats};
pub use header::{read_header, HiveHeader, BASE_BLOCK_SIZE};
pub use hive::{Hive, HiveInfo, Key, LogApplied, LogPolicy, OpenOptions, Walk, WalkLimits, WalkStats};
pub use kind::HiveKind;
pub use txlog::{inspect_log, inspect_log_bytes, locate_logs, Candidate, LogRelation, LogSearch, LogSlot, LogSummary, LogTarget};
pub use value::{filetime_text, filetime_to_utc, format_utc, Data, Value, ValueType};

/// The crate version, for the tools to print.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }

    /// `DIRTYHIVE_WRITE_DOCS=1 cargo test codes_doc` rewrites `docs/codes.md`; otherwise the
    /// test checks that the file matches the source.
    #[test]
    fn codes_doc_is_current() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs").join("codes.md");
        let want = crate::diag::catalog_markdown();
        if std::env::var_os("DIRTYHIVE_WRITE_DOCS").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &want).unwrap();
            return;
        }
        let have = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
        assert_eq!(have, want, "docs/codes.md is stale: run DIRTYHIVE_WRITE_DOCS=1 cargo test codes_doc");
    }
}
