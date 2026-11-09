//! Opening a hive: the base block, the logs, the replay, the parser, the deleted cells.
//!
//! [`Hive::open`] never drops a hive it can parse: every degraded path records a diagnostic
//! and the hive comes back in the best state available (logs applied, or the on-disk state
//! when they cannot be), so a caller always gets what is there.

use std::cell::RefCell;
use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use blockcarve::hive_logs::{self, LogFile, Outcome};
use chrono::{DateTime, Utc};
use nt_hive2::{CleanHive, DirtyHive, HiveParseMode, KeyNode, Offset};

use crate::deleted::{self, Deleted, DeletedScan, DeletedStats};
use crate::diag::{self, Result};
use crate::header::{self, HiveHeader, BASE_BLOCK_SIZE};
use crate::kind::HiveKind;
use crate::txlog::{self, LogSearch, LogTarget};
use crate::value::{self, Value};

/// Codes of this module (000-099: opening a hive).
pub mod code {
    crate::codes! {
        OPEN_FAILED = 1, "the hive file could not be opened or read (missing, locked, permissions); nothing of it is available";
        EMPTY_FILE = 2, "the hive file is zero bytes: the collector copied a locked file and got nothing; look for a copy in a shadow copy or in the logs";
        SIGNATURE_INVALID = 3, "the file does not start with 'regf': it is not a registry hive (or the first sector was overwritten)";
        HEADER_TRUNCATED = 4, "the file is shorter than a base block (4096 bytes for a primary, 512 for a log); it was cut while copied";
        CHECKSUM_INVALID = 5, "the base block checksum does not match its bytes: the first sector was damaged; the hive is opened by its root cell offset and the logs cannot be replayed";
        NOT_PRIMARY = 6, "the file is a transaction log (file type 1, 2 or 6), not a primary hive; give the primary and the logs are found from it";
        UNSUPPORTED_VERSION = 7, "the hive format version is not 1.3 to 1.6; the parser does not know it (Windows NT 3.x, or garbage in the header)";
        UNEXPECTED_FILE_TYPE = 8, "the base block carries a file type that is neither primary nor log; the file is damaged or not a hive";
        KIND_UNRESOLVED = 9, "neither the file name nor the embedded path says which hive this is; it is opened as Unknown and every path is tried against it";
        NAME_HEADER_MISMATCH = 10, "the file name says one hive and the embedded path another; the header wins (collectors rename, Windows does not)";
        PARSE_FAILED = 11, "nt_hive2 could not parse the hive (root cell or bin structure damaged); the deleted-cell scan may still read it";
        PARSE_PANIC = 12, "nt_hive2 panicked while parsing the hive; reported instead of crashing, the hive is skipped";
        OPENED_WITHOUT_BASE_BLOCK = 13, "the hive was opened by its root cell offset because its base block checksum is wrong; keys and values are read, sequence numbers are not trusted";
        IO_ERROR = 14, "an input/output error while reading the hive; the device or the file system failed mid-read";
        SEQUENCE_TOO_FAR = 15, "the primary sequence is more than one ahead of the secondary: several writes were lost; the logs cannot bring the hive to a consistent state and it is read as it is";
        DIRTY_KEPT = 16, "the hive is dirty and stays so: no usable log; its last writes may be missing";
        RECOVERED = 17, "the hive was dirty and its transaction logs were applied: it now holds the writes the file had not received";
        OPENED = 18, "the hive was opened: kind, version, sequence numbers, dirty or clean";
        ROOT_READ_FAILED = 19, "the root key could not be read after parsing; the hive is unusable through the parser";
        BYTES_WITHOUT_PATH = 20, "a hive given as bytes has no file, so logs can only be given explicitly (LogPolicy::Only); Auto found nothing";
        SAVE_FAILED = 21, "the rebuilt hive could not be written to the path asked for";
        SAVED = 22, "the rebuilt hive (logs applied) was written to disk";
        NOT_DIRTY_LOGS_IGNORED = 23, "the hive is clean, so the transaction logs given or found were not applied (Windows ignores them too)";
    }
}

/// Bytes shared between the parser's cursor and the caller, read-only.
#[derive(Clone, Debug)]
pub struct SharedBytes(Arc<Vec<u8>>);

impl AsRef<[u8]> for SharedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The parsed hive, as nt_hive2 sees it.
pub type Parsed = nt_hive2::Hive<Cursor<SharedBytes>, CleanHive>;

/// Which transaction logs to use.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LogPolicy {
    /// Find them: next to the hive, then under the search root.
    #[default]
    Auto,
    /// Only these files.
    Only(Vec<PathBuf>),
    /// None: read the hive as it is on disk.
    None,
}

/// How to open a hive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOptions {
    /// Which logs to use.
    pub logs: LogPolicy,
    /// Where to look for logs beyond the hive's folder (the evidence root).
    pub search_root: Option<PathBuf>,
    /// Scan the free cells for deleted keys and values.
    pub recover_deleted: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        OpenOptions { logs: LogPolicy::Auto, search_root: None, recover_deleted: true }
    }
}

impl OpenOptions {
    /// Logs found automatically, deleted cells recovered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Where to look for logs beyond the hive's folder.
    pub fn search_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.search_root = Some(root.into());
        self
    }

    /// Which logs to use.
    pub fn logs(mut self, policy: LogPolicy) -> Self {
        self.logs = policy;
        self
    }

    /// Whether to scan for deleted cells.
    pub fn recover_deleted(mut self, yes: bool) -> Self {
        self.recover_deleted = yes;
        self
    }
}

/// A transaction log that went into the hive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogApplied {
    /// The file.
    pub path: PathBuf,
    /// HvLE entries it held (0 for an old-format log).
    pub entries: usize,
    /// The whole file was valid; `false` when a damaged tail was cut.
    pub complete: bool,
    /// An old-format (`DIRT`) log.
    pub old_format: bool,
}

/// What is known about an opened hive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiveInfo {
    /// The file, when opened from one.
    pub path: Option<PathBuf>,
    /// The file name, or the name given with the bytes.
    pub name: String,
    /// The kind, header first, then the name.
    pub kind: HiveKind,
    /// What the file name alone said.
    pub name_kind: HiveKind,
    /// What the embedded path said.
    pub header_kind: HiveKind,
    /// The base block as it was on disk.
    pub header: HiveHeader,
    /// The base block after the logs (the same when none applied).
    pub header_after: HiveHeader,
    /// The file was dirty when opened.
    pub was_dirty: bool,
    /// Still dirty after the logs (none applied).
    pub is_dirty: bool,
    /// The base block checksum was right.
    pub checksum_valid: bool,
    /// Parsed by root offset because the checksum was wrong.
    pub opened_without_base_block: bool,
    /// The log search, when one ran.
    pub logs_found: Option<LogSearch>,
    /// The logs applied, in order.
    pub logs_applied: Vec<LogApplied>,
    /// Words on what the replay did.
    pub replay: Option<String>,
    /// Size of the hive bytes after the logs.
    pub size: usize,
}

impl HiveInfo {
    /// The logs went in.
    pub fn recovered(&self) -> bool {
        !self.logs_applied.is_empty()
    }

    /// Last write of the hive (after the logs) as UTC.
    pub fn last_written(&self) -> Option<DateTime<Utc>> {
        self.header_after.timestamp()
    }

    /// `SOFTWARE [dirty, 2 logs applied]`.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.was_dirty {
            parts.push("dirty".to_string());
        }
        if self.recovered() {
            parts.push(format!("{} log(s) applied", self.logs_applied.len()));
        } else if self.is_dirty {
            parts.push("kept dirty".to_string());
        }
        if self.opened_without_base_block {
            parts.push("bad checksum".to_string());
        }
        if parts.is_empty() {
            format!("{} [clean]", self.kind)
        } else {
            format!("{} [{}]", self.kind, parts.join(", "))
        }
    }
}

/// A key: its path, name, timestamp, values, and a handle to walk its children.
#[derive(Clone)]
pub struct Key {
    /// Root-relative path with backslashes; empty for the root.
    pub path: String,
    /// The key name (the root's is what the hive calls it).
    pub name: String,
    /// Last write.
    pub last_written: DateTime<Utc>,
    /// Number of subkeys.
    pub subkey_count: u32,
    /// The values.
    pub values: Vec<Value>,
    /// Depth under the root (0 for the root).
    pub depth: usize,
    node: Rc<RefCell<KeyNode>>,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key").field("path", &self.path).field("name", &self.name).field("last_written", &self.last_written).field("subkey_count", &self.subkey_count).field("values", &self.values.len()).field("depth", &self.depth).finish()
    }
}

impl Key {
    fn from_node(node: Rc<RefCell<KeyNode>>, path: String, depth: usize) -> Key {
        let (name, last_written, subkey_count, values) = {
            let n = node.borrow();
            (n.name().to_string(), *n.timestamp(), n.subkey_count(), n.values().iter().map(Value::from_nt).collect())
        };
        Key { path, name, last_written, subkey_count, values, depth, node }
    }

    /// The value named `name` (case-insensitive; `""` or `(Default)` for the unnamed one).
    pub fn value(&self, name: &str) -> Option<&Value> {
        let want_default = name.is_empty() || name.eq_ignore_ascii_case(value::DEFAULT_VALUE_NAME);
        self.values.iter().find(|v| if want_default { v.is_default() } else { v.name.eq_ignore_ascii_case(name) })
    }

    /// The last written time as the family's text.
    pub fn last_written_text(&self) -> String {
        value::format_utc(&self.last_written)
    }

    /// No subkeys.
    pub fn is_leaf(&self) -> bool {
        self.subkey_count == 0
    }
}

/// What a walk callback decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Walk {
    /// Go on, children included.
    Continue,
    /// Go on, skipping this key's children.
    SkipChildren,
    /// Stop the walk.
    Stop,
}

/// Bounds of a walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkLimits {
    /// Deepest level visited (the root is 0).
    pub max_depth: usize,
    /// Most keys visited.
    pub max_keys: usize,
}

impl Default for WalkLimits {
    fn default() -> Self {
        WalkLimits { max_depth: 512, max_keys: usize::MAX }
    }
}

/// What a walk did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalkStats {
    /// Keys visited.
    pub keys: usize,
    /// Values seen on them.
    pub values: usize,
    /// Deepest level reached.
    pub max_depth: usize,
    /// Keys whose children could not be read.
    pub failed_subkey_lists: usize,
    /// Stopped by the callback or a limit.
    pub stopped: bool,
}

/// A log chosen for the replay: path, the cut to apply (usable bytes, valid entries), entries.
type ChosenLog = (PathBuf, Option<(u64, usize)>, usize);

/// A hive opened the forensic way.
pub struct Hive {
    bytes: SharedBytes,
    parsed: Parsed,
    info: HiveInfo,
    deleted: DeletedScan,
}

fn file_name_of(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
}

/// Checks a base block as a primary hive's and resolves the kind.
fn classify(header: &HiveHeader, name: &str, label: &str) -> Result<(HiveKind, HiveKind, HiveKind)> {
    if header.is_transaction_log() {
        return Err(crate::err!(code::NOT_PRIMARY, "{label} (file type {})", header.file_type));
    }
    if !header.is_primary() {
        return Err(crate::err!(code::UNEXPECTED_FILE_TYPE, "{label} (file type {})", header.file_type));
    }
    if !header.is_supported_version() {
        return Err(crate::err!(code::UNSUPPORTED_VERSION, "{label} (version {})", header.version()));
    }
    let name_kind = HiveKind::from_file_name(name);
    let header_kind = header.kind();
    let kind = match (header_kind, name_kind) {
        (HiveKind::Unknown, HiveKind::Unknown) => {
            diag::info(code::KIND_UNRESOLVED, label.to_string());
            HiveKind::Unknown
        }
        (HiveKind::Unknown, n) => n,
        (h, HiveKind::Unknown) => h,
        (h, n) if h == n => h,
        (h, n) => {
            diag::warn(code::NAME_HEADER_MISMATCH, format!("{label} (name says {n}, header says {h} via '{}')", header.embedded_name));
            h
        }
    };
    Ok((kind, name_kind, header_kind))
}

fn parse(bytes: &SharedBytes, header: &HiveHeader, label: &str) -> Result<Parsed> {
    let mode = if header.checksum_valid() { HiveParseMode::NormalWithBaseBlock } else { HiveParseMode::Normal(Offset(header.root_cell_offset)) };
    let cursor = Cursor::new(bytes.clone());
    let parsed: std::result::Result<nt_hive2::Hive<Cursor<SharedBytes>, DirtyHive>, nt_hive2::Error> = match catch_unwind(AssertUnwindSafe(|| nt_hive2::Hive::new(cursor, mode))) {
        Ok(r) => r,
        Err(p) => return Err(crate::err!(code::PARSE_PANIC, "{label}: {}", diag::panic_message(&*p))),
    };
    let hive = parsed.map_err(|e| crate::err!(code::PARSE_FAILED, "{label}: {e}"))?;
    let mut clean = hive.treat_hive_as_clean();
    match catch_unwind(AssertUnwindSafe(|| clean.root_key_node())) {
        Ok(Ok(_)) => Ok(clean),
        Ok(Err(e)) => Err(crate::err!(code::ROOT_READ_FAILED, "{label}: {e}")),
        Err(p) => Err(crate::err!(code::PARSE_PANIC, "{label}: root key: {}", diag::panic_message(&*p))),
    }
}

/// Loads the chosen logs (cut to their valid prefix) and replays them into `raw`.
fn apply_logs(raw: Vec<u8>, label: &str, chosen: &[ChosenLog]) -> (Vec<u8>, Vec<LogApplied>, Option<String>) {
    let mut files = Vec::new();
    let mut meta: Vec<(PathBuf, usize, bool)> = Vec::new();
    for (path, cut, entries) in chosen {
        match std::fs::read(path) {
            Ok(mut data) => {
                let mut complete = true;
                if let Some((usable, valid_entries)) = cut {
                    let usable = (*usable as usize).min(data.len());
                    diag::warn(txlog::code::LOG_PARTIAL, format!("{}: using the first {usable} of {} bytes ({valid_entries} valid entries)", path.display(), data.len()));
                    data.truncate(usable);
                    complete = false;
                }
                files.push(LogFile { path: path.clone(), data });
                meta.push((path.clone(), *entries, complete));
            }
            Err(e) => {
                diag::warn(txlog::code::LOG_OPEN_FAILED, format!("{}: {e}", path.display()));
            }
        }
    }
    if files.is_empty() {
        diag::warn(txlog::code::LOG_APPLY_FAILED, format!("{label}: no transaction log could be loaded"));
        return (raw, Vec::new(), None);
    }
    let replay = hive_logs::replay(&raw, &files);
    for (path, why) in &replay.skipped_old {
        diag::warn(txlog::code::LOG_OLD_FORMAT_SKIPPED, format!("{}: {why}", path.display()));
    }
    let outcome_text = format!("{:?}", replay.outcome);
    let applied: Vec<LogApplied> = match &replay.outcome {
        Outcome::NewFormat { entries, pages, logs, from_seq, to_seq, gap, rejected } => {
            if *gap {
                diag::warn(txlog::code::LOG_REPLAY_GAP, format!("{label}: replay stopped at a missing sequence number after {entries} entries"));
            }
            if *rejected > 0 {
                diag::warn(txlog::code::LOG_ENTRIES_REJECTED, format!("{label}: {rejected} entries rejected by their hashes"));
            }
            diag::info(txlog::code::LOG_APPLIED, format!("{label}: {entries} entries, {pages} pages from {logs} log(s), sequence {from_seq} to {to_seq}"));
            meta.iter().map(|(p, e, c)| LogApplied { path: p.clone(), entries: *e, complete: *c, old_format: false }).collect()
        }
        Outcome::OldFormat { pages, log } => {
            diag::info(txlog::code::LOG_OLD_FORMAT_APPLIED, format!("{label}: {pages} pages from {}", log.display()));
            vec![LogApplied { path: log.clone(), entries: 0, complete: true, old_format: true }]
        }
        other => {
            diag::warn(txlog::code::LOG_APPLY_FAILED, format!("{label}: {other:?}"));
            return (raw, Vec::new(), Some(outcome_text));
        }
    };
    let data = match replay.data {
        std::borrow::Cow::Owned(v) => v,
        std::borrow::Cow::Borrowed(_) => raw,
    };
    (data, applied, Some(outcome_text))
}

impl std::fmt::Debug for Hive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hive").field("info", &self.info).field("bytes", &self.bytes.as_ref().len()).field("deleted", &self.deleted.stats).finish()
    }
}

impl Hive {
    /// Opens a hive file, finds and applies its logs, recovers its deleted cells.
    pub fn open(path: &Path, opts: &OpenOptions) -> Result<Hive> {
        let label = path.display().to_string();
        let header = header::read_header(path).map_err(diag::error)?;
        let name = file_name_of(path);
        let (kind, name_kind, header_kind) = classify(&header, &name, &label).map_err(diag::error)?;
        let bytes = std::fs::read(path).map_err(|e| diag::error(crate::err!(code::OPEN_FAILED, "{label}: {e}")))?;
        Self::assemble(bytes, Some(path), name, header, kind, name_kind, header_kind, opts)
    }

    /// Opens a hive held in memory. Logs are used only when given with [`LogPolicy::Only`]
    /// (there is no folder to search).
    pub fn from_bytes(bytes: Vec<u8>, name: &str, opts: &OpenOptions) -> Result<Hive> {
        let label = name.to_string();
        if bytes.is_empty() {
            return Err(diag::error(crate::err!(code::EMPTY_FILE, "{label}")));
        }
        let header = HiveHeader::parse(&bytes, &label).map_err(diag::error)?;
        if bytes.len() < BASE_BLOCK_SIZE {
            return Err(diag::error(crate::err!(code::HEADER_TRUNCATED, "{label} ({} bytes, a primary hive needs {BASE_BLOCK_SIZE})", bytes.len())));
        }
        let (kind, name_kind, header_kind) = classify(&header, name, &label).map_err(diag::error)?;
        Self::assemble(bytes, None, name.to_string(), header, kind, name_kind, header_kind, opts)
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(mut bytes: Vec<u8>, path: Option<&Path>, name: String, header: HiveHeader, kind: HiveKind, name_kind: HiveKind, header_kind: HiveKind, opts: &OpenOptions) -> Result<Hive> {
        let label = path.map(|p| p.display().to_string()).unwrap_or_else(|| name.clone());
        let mut info = HiveInfo {
            path: path.map(Path::to_path_buf),
            name,
            kind,
            name_kind,
            header_kind,
            header: header.clone(),
            header_after: header.clone(),
            was_dirty: header.is_dirty(),
            is_dirty: header.is_dirty(),
            checksum_valid: header.checksum_valid(),
            opened_without_base_block: false,
            logs_found: None,
            logs_applied: Vec::new(),
            replay: None,
            size: bytes.len(),
        };

        if !header.checksum_valid() {
            diag::warn(code::CHECKSUM_INVALID, format!("{label} (stored 0x{:08x}, calculated 0x{:08x}); opening by root offset, logs cannot be replayed", header.checksum_stored, header.checksum_calculated));
            info.opened_without_base_block = true;
            diag::info(code::OPENED_WITHOUT_BASE_BLOCK, label.clone());
        } else if header.is_dirty() {
            let (data, applied, outcome, search) = Self::recover(bytes, &label, path, &header, kind, opts);
            bytes = data;
            info.logs_found = search;
            info.replay = outcome;
            if !applied.is_empty() {
                info.logs_applied = applied;
                if let Ok(h) = HiveHeader::parse(&bytes, &label) {
                    info.header_after = h;
                }
                info.is_dirty = info.header_after.is_dirty();
                info.size = bytes.len();
                diag::info(code::RECOVERED, format!("{label} using {}", info.logs_applied.iter().map(|l| l.path.display().to_string()).collect::<Vec<_>>().join(", ")));
            } else {
                diag::warn(code::DIRTY_KEPT, format!("{label} (primary {}, secondary {})", header.primary_sequence, header.secondary_sequence));
            }
        } else if let LogPolicy::Only(paths) = &opts.logs {
            if !paths.is_empty() {
                diag::info(code::NOT_DIRTY_LOGS_IGNORED, format!("{label}: {} log(s) given", paths.len()));
            }
        }

        let shared = SharedBytes(Arc::new(bytes));
        let parsed = parse(&shared, &info.header_after, &label).map_err(diag::error)?;

        let deleted = if opts.recover_deleted {
            match deleted::scan(shared.as_ref()) {
                Ok(s) => s,
                Err(e) => {
                    diag::warned(e);
                    DeletedScan::default()
                }
            }
        } else {
            diag::info(deleted::code::CELLS_SKIPPED, label.clone());
            DeletedScan { stats: DeletedStats { skipped: true, ..Default::default() }, entries: Vec::new() }
        };

        diag::info(code::OPENED, format!("{label}: {} version {} primary {} secondary {} {}", info.kind, info.header.version(), info.header.primary_sequence, info.header.secondary_sequence, if info.was_dirty { "dirty" } else { "clean" }));
        Ok(Hive { bytes: shared, parsed, info, deleted })
    }

    /// The dirty path: find the logs by policy, apply what is usable.
    fn recover(raw: Vec<u8>, label: &str, path: Option<&Path>, header: &HiveHeader, kind: HiveKind, opts: &OpenOptions) -> (Vec<u8>, Vec<LogApplied>, Option<String>, Option<LogSearch>) {
        if opts.logs == LogPolicy::None {
            diag::info(txlog::code::LOG_POLICY_NONE, label.to_string());
            return (raw, Vec::new(), None, None);
        }
        if header.primary_sequence != header.secondary_sequence.wrapping_add(1) {
            diag::warn(code::SEQUENCE_TOO_FAR, format!("{label} (primary {} vs secondary {})", header.primary_sequence, header.secondary_sequence));
            return (raw, Vec::new(), None, None);
        }
        let fallback = PathBuf::from(&label);
        let hive_path: &Path = path.unwrap_or(&fallback);
        let target = LogTarget { path: hive_path, header, kind, search_root: opts.search_root.as_deref() };
        let search = match &opts.logs {
            LogPolicy::Only(paths) => txlog::given_logs(&target, paths),
            LogPolicy::Auto if path.is_none() => {
                diag::warn(code::BYTES_WITHOUT_PATH, label.to_string());
                LogSearch::default()
            }
            LogPolicy::Auto => txlog::locate_logs(&target),
            LogPolicy::None => unreachable!(),
        };

        if search.is_empty() {
            let legacy = search.legacy();
            if !legacy.is_empty() {
                let chosen: Vec<ChosenLog> = legacy.into_iter().map(|p| (p, None, 0)).collect();
                let (data, applied, outcome) = apply_logs(raw, label, &chosen);
                return (data, applied, outcome, Some(search));
            }
            if search.rejected.is_empty() && path.is_some() {
                diag::warn(txlog::code::LOG_NOT_FOUND, label.to_string());
            }
            return (raw, Vec::new(), None, Some(search));
        }
        if !search.has_matching() {
            let gap = [&search.log1, &search.log2].into_iter().flatten().any(|c| c.relation == Some(txlog::LogRelation::Gap));
            if gap {
                diag::warn(txlog::code::LOG_GAP, format!("{label}: the located logs start ahead of the hive's secondary sequence {}; the writes between were lost with an earlier log, nothing can be replayed consistently", header.secondary_sequence));
            } else {
                diag::warn(txlog::code::LOG_STALE, format!("{label}: every located log is behind the hive's secondary sequence {}; nothing to replay", header.secondary_sequence));
            }
            return (raw, Vec::new(), None, Some(search));
        }
        let chosen: Vec<ChosenLog> = search
            .usable()
            .into_iter()
            .map(|c| {
                let s = c.summary.as_ref();
                let cut = s.filter(|s| s.needs_sanitizing()).map(|s| (s.usable_len, s.entries.len()));
                (c.path.clone(), cut, s.map(|s| s.entries.len()).unwrap_or(0))
            })
            .collect();
        let (data, applied, outcome) = apply_logs(raw, label, &chosen);
        if applied.is_empty() {
            diag::warn(txlog::code::LOG_REPLAY_FAILED, format!("{label}: continuing with the on-disk state"));
        }
        (data, applied, outcome, Some(search))
    }

    /// What is known about the hive.
    pub fn info(&self) -> &HiveInfo {
        &self.info
    }

    /// The hive bytes, logs applied.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// The parser's view, for what this crate does not expose.
    pub fn parsed_mut(&mut self) -> &mut Parsed {
        &mut self.parsed
    }

    /// The deleted keys and values (empty when not asked for).
    pub fn deleted(&self) -> &[Deleted] {
        &self.deleted.entries
    }

    /// The full deleted scan.
    pub fn deleted_scan(&self) -> &DeletedScan {
        &self.deleted
    }

    /// Counts of the deleted-cell scan.
    pub fn deleted_stats(&self) -> &DeletedStats {
        &self.deleted.stats
    }

    /// Writes the hive bytes (logs applied) to `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| diag::error(crate::err!(code::SAVE_FAILED, "{}: {e}", path.display())))?;
            }
        }
        std::fs::write(path, self.bytes()).map_err(|e| diag::error(crate::err!(code::SAVE_FAILED, "{}: {e}", path.display())))?;
        diag::info(code::SAVED, format!("{} ({} bytes)", path.display(), self.bytes().len()));
        Ok(())
    }

    /// The root key.
    pub fn root(&mut self) -> Result<Key> {
        let node = match catch_unwind(AssertUnwindSafe(|| self.parsed.root_key_node())) {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(diag::error(crate::err!(value::code::ROOT_KEY_FAILED, "{}: {e}", self.info.name))),
            Err(p) => return Err(diag::error(crate::err!(code::PARSE_PANIC, "{}: root key: {}", self.info.name, diag::panic_message(&*p)))),
        };
        Ok(Key::from_node(Rc::new(RefCell::new(node)), String::new(), 0))
    }

    /// The children of a key, sorted by name without case (the order Windows keeps).
    pub fn subkeys(&mut self, key: &Key) -> Result<Vec<Key>> {
        if key.subkey_count == 0 {
            return Ok(Vec::new());
        }
        let node = key.node.clone();
        let children: Vec<Rc<RefCell<KeyNode>>> = {
            let n = node.borrow();
            match catch_unwind(AssertUnwindSafe(|| n.subkeys(&mut self.parsed).map(|r| r.iter().cloned().collect::<Vec<_>>()))) {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return Err(diag::warned(crate::err!(value::code::SUBKEYS_FAILED, "{}: {e}", key.path))),
                Err(p) => return Err(diag::warned(crate::err!(value::code::VALUE_PARSE_PANIC, "{}: {}", key.path, diag::panic_message(&*p)))),
            }
        };
        let mut out: Vec<Key> = children
            .into_iter()
            .map(|c| {
                let name = c.borrow().name().to_string();
                let path = if key.path.is_empty() { name } else { format!("{}\\{}", key.path, name) };
                Key::from_node(c, path, key.depth + 1)
            })
            .collect();
        // Windows keeps subkey lists sorted without case; sorting here makes every hive,
        // including a hand-built or damaged one, come out in one order.
        out.sort_by_key(|k| k.name.to_lowercase());
        Ok(out)
    }

    /// The key at `path` (backslashes or slashes, case-insensitive), or `None`.
    pub fn key(&mut self, path: &str) -> Result<Option<Key>> {
        let parts: Vec<&str> = path.split(['\\', '/']).filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Err(crate::err!(value::code::PATH_EMPTY, "use root() for the root key"));
        }
        let mut cur = self.root()?;
        for part in parts {
            let children = self.subkeys(&cur)?;
            match children.into_iter().find(|k| k.name.eq_ignore_ascii_case(part)) {
                Some(k) => cur = k,
                None => {
                    diag::info(value::code::KEY_NOT_FOUND, format!("{}: {path}", self.info.name));
                    return Ok(None);
                }
            }
        }
        Ok(Some(cur))
    }

    /// Visits every key depth-first, the root first, children sorted by name, within `limits`.
    pub fn walk<F>(&mut self, limits: &WalkLimits, mut f: F) -> Result<WalkStats>
    where
        F: FnMut(&Key) -> Walk,
    {
        let mut stats = WalkStats::default();
        let root = self.root()?;
        let mut stack: Vec<Key> = vec![root];
        while let Some(key) = stack.pop() {
            if stats.keys >= limits.max_keys {
                diag::warn(value::code::WALK_KEY_LIMIT, format!("{}: stopped at {} keys", self.info.name, stats.keys));
                stats.stopped = true;
                break;
            }
            stats.keys += 1;
            stats.values += key.values.len();
            stats.max_depth = stats.max_depth.max(key.depth);
            match f(&key) {
                Walk::Stop => {
                    stats.stopped = true;
                    break;
                }
                Walk::SkipChildren => continue,
                Walk::Continue => {}
            }
            if key.subkey_count == 0 {
                continue;
            }
            if key.depth >= limits.max_depth {
                diag::warn(value::code::WALK_DEPTH_LIMIT, format!("{}: {} at depth {}", self.info.name, key.path, key.depth));
                stats.stopped = true;
                continue;
            }
            match self.subkeys(&key) {
                Ok(mut children) => {
                    children.reverse();
                    stack.extend(children);
                }
                Err(_) => stats.failed_subkey_lists += 1,
            }
        }
        Ok(stats)
    }

    /// Every key, depth-first, children sorted by name.
    pub fn keys(&mut self) -> Result<Vec<Key>> {
        let mut out = Vec::new();
        self.walk(&WalkLimits::default(), |k| {
            out.push(k.clone());
            Walk::Continue
        })?;
        Ok(out)
    }

    /// The string of value `name` under `path`, if both exist.
    pub fn string_value(&mut self, path: &str, name: &str) -> Result<Option<String>> {
        Ok(self.key(path)?.and_then(|k| k.value(name).and_then(|v| v.data.as_str())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    const RUN: &str = r"Microsoft\Windows\CurrentVersion\Run";

    #[test]
    fn clean_hive_opens_and_reads() {
        diag::clear();
        let d = TempDir::new("open_clean");
        let mut b = HiveBuilder::software();
        b.sz(RUN, "Updater", r"C:\u.exe").dword("K", "n", 5).multi_sz("K", "m", &["a", "b"]).binary("K", "b", &[1, 2]).sz_resident("K", "r", "x").qword("K", "q", 77);
        let p = b.write(&d.join("SOFTWARE"));
        let mut h = Hive::open(&p, &OpenOptions::default()).unwrap();
        let info = h.info();
        assert_eq!(info.kind, HiveKind::Software);
        assert!(!info.was_dirty && !info.is_dirty);
        assert!(info.checksum_valid);
        assert!(!info.recovered());
        assert_eq!(info.summary(), "SOFTWARE [clean]");
        assert!(info.last_written().is_some());
        assert_eq!(h.bytes().len(), std::fs::metadata(&p).unwrap().len() as usize);
        assert_eq!(h.string_value(RUN, "Updater").unwrap().as_deref(), Some(r"C:\u.exe"));
        assert_eq!(h.string_value(RUN, "nope").unwrap(), None);
        assert_eq!(h.string_value("Nowhere", "x").unwrap(), None);
        assert!(diag::has(value::code::KEY_NOT_FOUND));
        let k = h.key("k").unwrap().unwrap();
        assert_eq!(k.path, "K");
        assert_eq!(k.depth, 1);
        assert!(k.is_leaf());
        assert_eq!(k.value("n").unwrap().data, value::Data::Dword(5));
        assert_eq!(k.value("N").unwrap().kind, value::ValueType::DWORD);
        assert!(k.value("n").unwrap().resident);
        assert_eq!(k.value("m").unwrap().data, value::Data::MultiSz(vec!["a".into(), "b".into()]));
        assert_eq!(k.value("b").unwrap().data, value::Data::Binary(vec![1, 2]));
        assert_eq!(k.value("r").unwrap().data, value::Data::Sz("x".into()));
        assert_eq!(k.value("q").unwrap().data, value::Data::Qword(77));
        assert_eq!(k.last_written_text(), "2024-01-17T21:20:00.000000Z");
        assert!(format!("{k:?}").contains("\"K\""));
        let root = h.root().unwrap();
        assert_eq!(root.path, "");
        assert_eq!(root.depth, 0);
        assert_eq!(root.subkey_count, 2);
        let children = h.subkeys(&root).unwrap();
        assert_eq!(children.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), vec!["K", "Microsoft"]);
        assert_eq!(h.key("microsoft/windows\\CurrentVersion").unwrap().unwrap().path, r"Microsoft\Windows\CurrentVersion");
        assert_eq!(h.key("").unwrap_err().code, value::code::PATH_EMPTY);
        assert!(h.deleted().is_empty());
        assert!(!h.deleted_stats().skipped);
        assert!(diag::has(code::OPENED));
        diag::clear();
    }

    #[test]
    fn walk_visits_everything_in_order_and_honours_limits() {
        let d = TempDir::new("walk");
        let mut b = HiveBuilder::system();
        b.dword("Select", "Current", 1).sz(r"ControlSet001\Services\A", "ImagePath", "a").sz(r"ControlSet001\Services\B", "ImagePath", "b").sz(r"ControlSet001\Control", "x", "y");
        let p = b.write(&d.join("SYSTEM"));
        let mut h = Hive::open(&p, &OpenOptions::default()).unwrap();
        let keys = h.keys().unwrap();
        let paths: Vec<&str> = keys.iter().map(|k| k.path.as_str()).collect();
        assert_eq!(paths, vec!["", "ControlSet001", r"ControlSet001\Control", r"ControlSet001\Services", r"ControlSet001\Services\A", r"ControlSet001\Services\B", "Select"]);
        let mut seen = 0;
        let stats = h
            .walk(&WalkLimits::default(), |k| {
                seen += 1;
                if k.path == "ControlSet001" {
                    Walk::SkipChildren
                } else {
                    Walk::Continue
                }
            })
            .unwrap();
        assert_eq!(seen, 3, "root, ControlSet001 (children skipped), Select");
        assert_eq!(stats.keys, 3);
        assert_eq!(stats.values, 1);
        assert!(!stats.stopped);
        let stats = h.walk(&WalkLimits::default(), |_| Walk::Stop).unwrap();
        assert_eq!(stats.keys, 1);
        assert!(stats.stopped);
        diag::clear();
        let stats = h.walk(&WalkLimits { max_depth: 1, max_keys: usize::MAX }, |_| Walk::Continue).unwrap();
        assert_eq!(stats.max_depth, 1);
        assert!(stats.stopped);
        assert!(diag::has(value::code::WALK_DEPTH_LIMIT));
        diag::clear();
        let stats = h.walk(&WalkLimits { max_depth: 512, max_keys: 2 }, |_| Walk::Continue).unwrap();
        assert_eq!(stats.keys, 2);
        assert!(stats.stopped);
        assert!(diag::has(value::code::WALK_KEY_LIMIT));
        diag::clear();
    }

    #[test]
    fn dirty_hive_is_recovered_from_its_log() {
        diag::clear();
        let d = TempDir::new("open_dirty");
        let base = HiveBuilder::software();
        let mut step = HiveBuilder::software();
        step.sz(RUN, "Dropper", r"C:\Temp\d.exe");
        let fx = build_dirty(&base, &[&step], 5, false);
        let p = write_dirty(&d, "SOFTWARE", &fx);
        let mut h = Hive::open(&p, &OpenOptions::default()).unwrap();
        assert!(h.info().was_dirty);
        assert!(!h.info().is_dirty);
        assert!(h.info().recovered());
        assert_eq!(h.info().logs_applied.len(), 1);
        assert_eq!(h.info().logs_applied[0].path, d.join("SOFTWARE.LOG1"));
        assert!(h.info().logs_applied[0].complete);
        assert!(!h.info().logs_applied[0].old_format);
        assert_eq!(h.info().logs_applied[0].entries, 1);
        assert_eq!(h.info().header_after.primary_sequence, 6);
        assert_eq!(h.info().header_after.secondary_sequence, 6);
        assert_eq!(h.info().summary(), "SOFTWARE [dirty, 1 log(s) applied]");
        assert!(h.info().replay.as_deref().unwrap().starts_with("NewFormat"));
        assert!(h.info().logs_found.as_ref().unwrap().log1.is_some());
        assert_eq!(h.string_value(RUN, "Dropper").unwrap().as_deref(), Some(r"C:\Temp\d.exe"));
        assert!(diag::has(code::RECOVERED));
        assert!(diag::has(txlog::code::LOG_APPLIED));
        let out = d.join("rebuilt/SOFTWARE");
        h.save(&out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), h.bytes());
        assert!(diag::has(code::SAVED));
        let again = Hive::open(&out, &OpenOptions::default()).unwrap();
        assert!(!again.info().was_dirty, "the saved hive is clean");
        diag::clear();
    }

    #[test]
    fn dirty_hive_without_logs_is_kept_dirty() {
        diag::clear();
        let d = TempDir::new("open_nolog");
        let mut base = HiveBuilder::software();
        base.sz(RUN, "Old", r"C:\old.exe");
        let step = base.clone();
        let fx = build_dirty(&base, &[&step], 5, false);
        let p = d.write("SOFTWARE", &fx.primary);
        let mut h = Hive::open(&p, &OpenOptions::default()).unwrap();
        assert!(h.info().was_dirty && h.info().is_dirty);
        assert!(!h.info().recovered());
        assert_eq!(h.info().summary(), "SOFTWARE [dirty, kept dirty]");
        assert_eq!(h.string_value(RUN, "Old").unwrap().as_deref(), Some(r"C:\old.exe"));
        assert!(diag::has(txlog::code::LOG_NOT_FOUND));
        assert!(diag::has(code::DIRTY_KEPT));
        diag::clear();
        let h = Hive::open(&p, &OpenOptions::default().logs(LogPolicy::None)).unwrap();
        assert!(h.info().is_dirty);
        assert!(diag::has(txlog::code::LOG_POLICY_NONE));
        assert!(!diag::has(txlog::code::LOG_NOT_FOUND));
        diag::clear();
    }

    #[test]
    fn given_logs_policy() {
        diag::clear();
        let d = TempDir::new("open_given");
        let base = HiveBuilder::software();
        let mut step = HiveBuilder::software();
        step.sz(RUN, "Marker", "m");
        let fx = build_dirty(&base, &[&step], 5, false);
        let p = d.write("hives/SOFTWARE", &fx.primary);
        let log = d.write("elsewhere/weird-name.bin", &fx.log1);
        let mut h = Hive::open(&p, &OpenOptions::default().logs(LogPolicy::Only(vec![log.clone(), d.join("missing.LOG2")]))).unwrap();
        assert!(h.info().recovered());
        assert_eq!(h.info().logs_applied[0].path, log);
        assert_eq!(h.string_value(RUN, "Marker").unwrap().as_deref(), Some("m"));
        assert!(diag::has(txlog::code::LOG_GIVEN_MISSING));
        diag::clear();
        // A clean hive ignores given logs.
        let clean = HiveBuilder::software().write(&d.join("clean/SOFTWARE"));
        let h = Hive::open(&clean, &OpenOptions::default().logs(LogPolicy::Only(vec![log]))).unwrap();
        assert!(!h.info().recovered());
        assert!(diag::has(code::NOT_DIRTY_LOGS_IGNORED));
        diag::clear();
    }

    #[test]
    fn from_bytes_paths() {
        diag::clear();
        let base = HiveBuilder::software();
        let mut step = HiveBuilder::software();
        step.sz(RUN, "Marker", "m");
        let fx = build_dirty(&base, &[&step], 5, false);
        let h = Hive::from_bytes(fx.primary.clone(), "SOFTWARE", &OpenOptions::default()).unwrap();
        assert!(h.info().is_dirty);
        assert_eq!(h.info().path, None);
        assert_eq!(h.info().name, "SOFTWARE");
        assert!(diag::has(code::BYTES_WITHOUT_PATH));
        diag::clear();
        let d = TempDir::new("bytes");
        let log = d.write("SOFTWARE.LOG1", &fx.log1);
        let mut h = Hive::from_bytes(fx.primary.clone(), "SOFTWARE", &OpenOptions::default().logs(LogPolicy::Only(vec![log]))).unwrap();
        assert!(h.info().recovered());
        assert_eq!(h.string_value(RUN, "Marker").unwrap().as_deref(), Some("m"));
        assert_eq!(Hive::from_bytes(Vec::new(), "x", &OpenOptions::default()).unwrap_err().code, code::EMPTY_FILE);
        assert_eq!(Hive::from_bytes(vec![0u8; 8192], "x", &OpenOptions::default()).unwrap_err().code, code::SIGNATURE_INVALID);
        assert_eq!(Hive::from_bytes(fx.primary[..2048].to_vec(), "x", &OpenOptions::default()).unwrap_err().code, code::HEADER_TRUNCATED);
        assert_eq!(Hive::from_bytes(fx.log1.clone(), "x", &OpenOptions::default()).unwrap_err().code, code::NOT_PRIMARY);
        let mut odd = fx.primary.clone();
        patch_base_block(&mut odd, 5, 5, 9);
        assert_eq!(Hive::from_bytes(odd, "x", &OpenOptions::default()).unwrap_err().code, code::UNEXPECTED_FILE_TYPE);
        let mut old = HiveBuilder::software();
        old.minor_version = 2;
        assert_eq!(Hive::from_bytes(old.build(), "x", &OpenOptions::default()).unwrap_err().code, code::UNSUPPORTED_VERSION);
        diag::clear();
    }

    #[test]
    fn checksum_invalid_opens_by_root_offset() {
        diag::clear();
        let d = TempDir::new("open_chk");
        let mut base = HiveBuilder::software();
        base.sz(RUN, "Existing", r"C:\e.exe");
        let mut bytes = base.build_with(6, 5);
        bytes[0x60] ^= 0x7f;
        let p = d.write("SOFTWARE", &bytes);
        let mut h = Hive::open(&p, &OpenOptions::default()).unwrap();
        assert!(h.info().opened_without_base_block);
        assert!(!h.info().checksum_valid);
        assert!(h.info().was_dirty && !h.info().recovered());
        assert!(h.info().summary().contains("bad checksum"));
        assert_eq!(h.string_value(RUN, "Existing").unwrap().as_deref(), Some(r"C:\e.exe"));
        assert!(diag::has(code::CHECKSUM_INVALID));
        assert!(diag::has(code::OPENED_WITHOUT_BASE_BLOCK));
        diag::clear();
    }

    #[test]
    fn sequence_too_far_and_stale_logs() {
        diag::clear();
        let d = TempDir::new("open_seq");
        let base = HiveBuilder::software();
        let mut step = HiveBuilder::software();
        step.sz(RUN, "Marker", "m");
        let fx = build_dirty(&base, &[&step], 5, false);
        let p = d.write("SOFTWARE", &HiveBuilder::software().build_with(9, 5));
        d.write("SOFTWARE.LOG1", &fx.log1);
        let h = Hive::open(&p, &OpenOptions::default()).unwrap();
        assert!(h.info().is_dirty);
        assert!(diag::has(code::SEQUENCE_TOO_FAR));
        diag::clear();
        txlog::clear_log_index();
        let p = d.write("stale/SOFTWARE", &HiveBuilder::software().build_with(10, 9));
        d.write("stale/SOFTWARE.LOG1", &fx.log1);
        let h = Hive::open(&p, &OpenOptions::default()).unwrap();
        assert!(h.info().is_dirty);
        assert!(h.info().logs_found.as_ref().unwrap().log1.is_some(), "located and attributed");
        assert!(diag::has(txlog::code::LOG_STALE));
        assert!(!diag::has(code::RECOVERED));
        diag::clear();
    }

    #[test]
    fn name_and_header_disagreement_and_unknown_kind() {
        diag::clear();
        let d = TempDir::new("open_kind");
        let p = HiveBuilder::software().write(&d.join("SYSTEM"));
        let h = Hive::open(&p, &OpenOptions::default()).unwrap();
        assert_eq!(h.info().kind, HiveKind::Software, "the header wins");
        assert_eq!(h.info().name_kind, HiveKind::System);
        assert_eq!(h.info().header_kind, HiveKind::Software);
        assert!(diag::has(code::NAME_HEADER_MISMATCH));
        diag::clear();
        let p = HiveBuilder::anonymous().write(&d.join("blob.bin"));
        let h = Hive::open(&p, &OpenOptions::default()).unwrap();
        assert_eq!(h.info().kind, HiveKind::Unknown);
        assert!(diag::has(code::KIND_UNRESOLVED));
        diag::clear();
        let p = HiveBuilder::anonymous().write(&d.join("bob_NTUSER.DAT"));
        let h = Hive::open(&p, &OpenOptions::default()).unwrap();
        assert_eq!(h.info().kind, HiveKind::NtUser, "the name speaks when the header is blank");
        assert_eq!(Hive::open(&d.join("missing"), &OpenOptions::default()).unwrap_err().code, code::OPEN_FAILED);
        assert!(diag::summary().errors >= 1);
        diag::clear();
    }

    #[test]
    fn deleted_cells_are_part_of_the_open() {
        let d = TempDir::new("open_del");
        let mut b = HiveBuilder::software();
        b.sz(RUN, "Live", "l").sz(RUN, "Gone", "g").delete_value(RUN, "Gone").sz("Dead\\Key", "v", "x").delete_key("Dead");
        let p = b.write(&d.join("SOFTWARE"));
        let h = Hive::open(&p, &OpenOptions::default()).unwrap();
        assert_eq!(h.deleted_stats().deleted_keys, 2);
        assert_eq!(h.deleted_stats().orphan_values, 1);
        assert_eq!(h.deleted().len(), 3);
        assert_eq!(h.deleted_scan().keys().count(), 2);
        let h = Hive::open(&p, &OpenOptions::default().recover_deleted(false)).unwrap();
        assert!(h.deleted().is_empty());
        assert!(h.deleted_stats().skipped);
    }

    #[test]
    fn real_fixtures_open() {
        diag::clear();
        let mut h = Hive::open(&fixture("clean_hive/testhive"), &OpenOptions::default()).unwrap();
        assert!(!h.info().was_dirty);
        let keys = h.keys().unwrap();
        assert!(keys.len() > 1);
        let mut h = Hive::open(&fixture("dirty_hive/NewDirtyHive"), &OpenOptions::default()).unwrap();
        assert!(h.info().was_dirty);
        assert!(h.info().recovered(), "{:?}", diag::snapshot());
        assert!(!h.info().is_dirty);
        assert_eq!(h.info().kind, HiveKind::Unknown);
        let n = h.keys().unwrap().len();
        assert!(n > 1);
        // The replayed bins match what Windows 10 produced when it loaded the hive itself.
        let windows = std::fs::read(fixture("dirty_hive/RecoveredHive_Windows10")).unwrap();
        let ours = h.bytes();
        let n = ours.len().min(windows.len());
        let diffs = (BASE_BLOCK_SIZE..n).filter(|&i| ours[i] != windows[i]).count();
        assert!(diffs < 64, "{diffs} byte(s) differ from the Windows 10 recovery");
        diag::clear();
    }

    #[test]
    fn old_format_log_is_replayed_like_windows_7() {
        diag::clear();
        let h = Hive::open(&fixture("old_dirty_hive/OldDirtyHive"), &OpenOptions::default()).unwrap();
        assert!(h.info().was_dirty);
        assert!(h.info().recovered(), "{:?}", diag::snapshot());
        assert!(h.info().logs_applied[0].old_format);
        assert!(diag::has(txlog::code::LOG_OLD_FORMAT_APPLIED));
        assert!(diag::has(txlog::code::LOG_LEGACY_FORMAT));
        let windows = std::fs::read(fixture("old_dirty_hive/RecoveredHive_Windows7")).unwrap();
        let ours = &h.bytes()[BASE_BLOCK_SIZE..];
        let theirs = &windows[BASE_BLOCK_SIZE..];
        let n = ours.len().min(theirs.len());
        let diffs: Vec<usize> = (0..n).filter(|i| !(20..28).contains(i)).filter(|&i| ours[i] != theirs[i]).collect();
        assert!(diffs.len() <= 4, "{} byte(s) differ from the Windows 7 recovery, first at {:#x}", diffs.len(), diffs[0]);
        let dirty = std::fs::read(fixture("old_dirty_hive/OldDirtyHive")).unwrap();
        let changed = (0..n).filter(|&i| dirty[BASE_BLOCK_SIZE + i] != theirs[i]).count();
        assert!(changed > 100, "the log must change the hive ({changed} bytes)");
        diag::clear();
    }

    #[test]
    fn options_builder() {
        let o = OpenOptions::new().search_root("/ev").logs(LogPolicy::None).recover_deleted(false);
        assert_eq!(o.search_root.as_deref(), Some(Path::new("/ev")));
        assert_eq!(o.logs, LogPolicy::None);
        assert!(!o.recover_deleted);
        assert_eq!(LogPolicy::default(), LogPolicy::Auto);
    }
}
