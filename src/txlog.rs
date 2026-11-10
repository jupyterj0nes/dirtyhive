//! Transaction logs (`.LOG1` / `.LOG2`): location, validation and the choice of what to replay.
//!
//! Collectors lay evidence out in many ways: KAPE keeps logs next to the hive, image
//! extraction renames user hives to `<user>_NTUSER.DAT`, flattened collectors produce
//! `C_Windows_System32_config_SYSTEM.LOG1`, some put logs in a parallel tree. The locator
//!
//! 1. looks in the hive's own folder (case-insensitive),
//! 2. otherwise indexes every `.LOG1` / `.LOG2` / `.LOG` under the search root and scores
//!    candidates by name and path similarity,
//! 3. verifies every candidate by parsing its base block: the embedded hive name must match
//!    the hive's, which tells the `NTUSER.DAT.LOG1` of two users apart,
//! 4. pre-validates each `HvLE` entry so a truncated or garbage log never makes the parser
//!    panic or allocate absurd buffers; a damaged tail is cut off and only the valid prefix
//!    is replayed.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use walkdir::WalkDir;

use crate::diag::{self, Error, Result};
use crate::header::{HiveHeader, LOG_BASE_BLOCK_SIZE};
use crate::kind::HiveKind;

/// Codes of this module (100-199: transaction logs).
pub mod code {
    crate::codes! {
        LOG_NOT_FOUND = 100, "the hive is dirty and no .LOG1/.LOG2 was found next to it or under the search root; the hive is read in its on-disk state and the last writes may be missing. Collect the logs with the hive";
        LOG_OPEN_FAILED = 101, "a transaction log was located but could not be read (permissions, a vanished file); the hive is read without it";
        LOG_SIGNATURE_INVALID = 102, "a file named like a transaction log does not start with 'regf': it is not a log (zero-filled, garbage, another format) and is ignored";
        LOG_LEGACY_FORMAT = 103, "the log is in the old format (file type 1 or 2, a DIRT dirty vector: Windows XP to 8.0); it is replayed through the old-format path when its timestamp matches the hive";
        LOG_TRUNCATED = 104, "a log entry claims more bytes than the file has: the log was cut while being copied; the entries before the cut are still used";
        LOG_ENTRY_INVALID = 105, "an HvLE entry is structurally wrong (size, flags, page count, page reference out of bounds); the log is cut before it and the valid prefix is used";
        LOG_NO_ENTRIES = 106, "the log has a valid base block but not one usable HvLE entry; nothing to replay from it";
        LOG_SEQUENCE_JUMP = 107, "the entry sequence numbers inside a log are not consecutive; the entries after the jump may not apply";
        LOG_STALE = 108, "every entry of the log is older than the hive's secondary sequence: it was already flushed into the hive; nothing to apply (normal for the other log of the pair)";
        LOG_GAP = 109, "no entry of the log carries the sequence its own base block starts at (or the base block is older than the hive): the log cannot start a recovery, by the format's rule";
        LOG_FOREIGN = 110, "the embedded hive name in the log's base block is not the hive's: the log belongs to another hive (another user's NTUSER.DAT) and is rejected";
        LOG_AMBIGUOUS = 111, "two candidates for the same slot scored equally; the first by path was taken, check the other one";
        LOG_REMOTE_MATCH = 112, "the log was found away from its hive (another folder of the evidence); applied after its header was verified against the hive";
        LOG_PARTIAL = 113, "only a prefix of the log's entries could be used; the tail was damaged or truncated and cut off";
        LOG_CHECKSUM_INVALID = 114, "the log's base block checksum does not match; the entries are still inspected because Windows does not check it either";
        LOG_IS_PRIMARY = 115, "a file named like a log is a primary hive (file type 0): a copy of the hive itself, not a log; ignored";
        LOG_UNKNOWN_FILE_TYPE = 116, "the log's base block carries a file type that is neither primary nor a known log format; ignored";
        LOG_APPLY_FAILED = 117, "the replay engine could not apply the logs (no applicable entry, nothing usable); the hive is read in its on-disk state";
        LOG_REPLAY_FAILED = 118, "the replay failed after the logs were accepted; the hive was reopened in its on-disk state";
        LOG_OLD_FORMAT_SKIPPED = 119, "an old-format log was not applied: its sequence numbers are torn or its timestamp is not the hive's";
        LOG_OLD_FORMAT_APPLIED = 120, "an old-format (DIRT) log was applied to the hive";
        LOG_ENTRIES_REJECTED = 121, "some HvLE entries were rejected by their Marvin32 hashes (written while the machine lost power); the valid ones were applied";
        LOG_REPLAY_GAP = 122, "the replay stopped at a missing sequence number; later entries were not applied";
        LOG_POLICY_NONE = 123, "the hive is dirty but the caller asked for no transaction logs (LogPolicy::None); read as it is on disk";
        LOG_GIVEN_MISSING = 124, "a log path given explicitly (LogPolicy::Only) does not exist or is not a file";
        LOG_SEQUENCE_TOO_FAR = 125, "the hive's primary sequence is more than one ahead of the secondary: more than one write was lost and the logs cannot bring it back consistently; read as it is";
        LOG_APPLIED = 126, "the transaction logs were applied: the hive now holds the writes that had not reached the file";
        LOG_INDEX_BUILT = 127, "the search root was walked once to index every .LOG1/.LOG2/.LOG under it (cached for the next hive)";
        LOG_CANDIDATE = 128, "a file was considered as a log of this hive, with its score";
        LOG_AHEAD = 129, "the log starts after the hive's own sequence, at the sequence its base block names: by the format (regf specification, transaction logs, note 7) recovery starts there, so it is applied, as Windows would; the writes between are in no log any more, so a page they changed and that was not written again keeps its older content";
    }
}

/// Bytes of a sector; HvLE entries are sector-aligned.
pub const SECTOR_SIZE: usize = 512;
/// Bytes of an HvLE entry header.
pub const HVLE_HEADER_SIZE: u64 = 40;
/// The entry signature.
pub const HVLE_MAGIC: &[u8; 4] = b"HvLE";
/// Hive bins are 4 KiB-aligned.
pub const HBIN_ALIGNMENT: u32 = 4096;

/// Which slot a candidate belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogSlot {
    /// `.LOG1`.
    Log1,
    /// `.LOG2`.
    Log2,
    /// A single `.LOG` (Windows XP to 8.0 naming).
    Legacy,
}

impl LogSlot {
    /// The extension, upper case, with the dot.
    pub fn extension(&self) -> &'static str {
        match self {
            LogSlot::Log1 => ".LOG1",
            LogSlot::Log2 => ".LOG2",
            LogSlot::Legacy => ".LOG",
        }
    }
}

/// One HvLE entry, as read from its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// Offset of the entry in the log file.
    pub offset: u64,
    /// Size of the entry in bytes (sector multiple).
    pub size: u32,
    /// Sequence number of the write.
    pub sequence: u32,
    /// Size of the hive bins when the entry was written.
    pub hbin_data_size: u32,
    /// Pages carried.
    pub dirty_pages: u32,
    /// Bytes of page data.
    pub payload_bytes: u64,
}

/// What an inspection of a log found, without the heavy parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSummary {
    /// The file.
    pub path: PathBuf,
    /// Its length.
    pub file_len: u64,
    /// Its base block.
    pub header: HiveHeader,
    /// The valid entries, in file order.
    pub entries: Vec<LogEntry>,
    /// Bytes safe to hand to the replay (`file_len` when fully valid).
    pub usable_len: u64,
    /// Non-fatal problems found.
    pub problems: Vec<Error>,
}

impl LogSummary {
    /// Sequence of the first entry.
    pub fn first_sequence(&self) -> Option<u32> {
        self.entries.first().map(|e| e.sequence)
    }

    /// Sequence of the last entry.
    pub fn last_sequence(&self) -> Option<u32> {
        self.entries.last().map(|e| e.sequence)
    }

    /// A damaged tail has to be cut before the replay.
    pub fn needs_sanitizing(&self) -> bool {
        self.usable_len < self.file_len
    }

    /// The hive name in the log's base block.
    pub fn embedded_name(&self) -> &str {
        &self.header.embedded_name
    }
}

/// How a valid log relates to the hive it was found for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogRelation {
    /// Continues the hive's secondary sequence: will be applied.
    Matching,
    /// Every entry is older than the hive: nothing to apply.
    Stale,
    /// The first entry is ahead of the hive: an intermediate log is missing.
    Gap,
    /// The embedded hive name differs: another hive's log.
    Foreign,
}

/// Inspects a transaction log held in memory.
pub fn inspect_log_bytes(path: &Path, bytes: &[u8]) -> Result<LogSummary> {
    let label = path.display().to_string();
    let file_len = bytes.len() as u64;
    if bytes.len() < SECTOR_SIZE {
        return Err(crate::err!(code::LOG_TRUNCATED, "{label} ({} bytes, need at least {SECTOR_SIZE})", bytes.len()));
    }
    let header = match HiveHeader::parse(&bytes[..LOG_BASE_BLOCK_SIZE], &label) {
        Ok(h) => h,
        Err(e) if e.code == crate::hive::code::SIGNATURE_INVALID => return Err(Error::new(code::LOG_SIGNATURE_INVALID, e.detail)),
        Err(e) => return Err(Error::new(code::LOG_TRUNCATED, e.detail)),
    };
    if header.is_legacy_log() {
        return Err(crate::err!(code::LOG_LEGACY_FORMAT, "{label} (file type {})", header.file_type));
    }
    if header.is_primary() {
        return Err(crate::err!(code::LOG_IS_PRIMARY, "{label} (file type 0: a primary hive, not a log)"));
    }
    if !header.is_new_log() {
        return Err(crate::err!(code::LOG_UNKNOWN_FILE_TYPE, "{label} (file type {})", header.file_type));
    }

    let mut problems = Vec::new();
    if !header.checksum_valid() {
        problems.push(crate::err!(code::LOG_CHECKSUM_INVALID, "{label} (stored 0x{:08x}, calculated 0x{:08x})", header.checksum_stored, header.checksum_calculated));
    }

    let mut entries = Vec::new();
    let mut pos: u64 = SECTOR_SIZE as u64;
    let mut usable_len = file_len;

    loop {
        if pos + HVLE_HEADER_SIZE > file_len {
            break;
        }
        let p = pos as usize;
        if &bytes[p..p + 4] != HVLE_MAGIC {
            break;
        }
        let u32_at = |o: usize| u32::from_le_bytes([bytes[p + o], bytes[p + o + 1], bytes[p + o + 2], bytes[p + o + 3]]);
        let size = u32_at(4);
        let flags = u32_at(8);
        let sequence = u32_at(12);
        let hbin_data_size = u32_at(16);
        let dirty_pages = u32_at(20);
        let n = entries.len() + 1;
        let invalid = |why: String| crate::err!(code::LOG_ENTRY_INVALID, "{label} entry #{n} at offset {pos}: {why}");

        let problem = if (size as u64) < HVLE_HEADER_SIZE {
            Some(invalid(format!("size {size} smaller than the header")))
        } else if !(size as u64).is_multiple_of(SECTOR_SIZE as u64) {
            Some(invalid(format!("size {size} not a multiple of {SECTOR_SIZE}")))
        } else if pos + size as u64 > file_len {
            Some(crate::err!(code::LOG_TRUNCATED, "{label} entry #{n} at offset {pos} claims {size} bytes but only {} remain", file_len - pos))
        } else if flags & !1 != 0 {
            Some(invalid(format!("unexpected flags 0x{flags:08x}")))
        } else if dirty_pages == 0 {
            Some(invalid("zero dirty pages".to_string()))
        } else if hbin_data_size == 0 || !hbin_data_size.is_multiple_of(HBIN_ALIGNMENT) {
            Some(invalid(format!("hbin data size {hbin_data_size} not 4096-aligned")))
        } else if HVLE_HEADER_SIZE + (dirty_pages as u64).saturating_mul(8) > size as u64 {
            Some(invalid(format!("{dirty_pages} page references do not fit in {size} bytes")))
        } else {
            None
        };
        if let Some(e) = problem {
            problems.push(e);
            usable_len = pos;
            break;
        }

        let refs_bytes = dirty_pages as u64 * 8;
        let mut payload: u64 = 0;
        let mut bad_ref: Option<String> = None;
        for i in 0..dirty_pages as usize {
            let r = p + HVLE_HEADER_SIZE as usize + i * 8;
            let off = u32::from_le_bytes([bytes[r], bytes[r + 1], bytes[r + 2], bytes[r + 3]]);
            let sz = u32::from_le_bytes([bytes[r + 4], bytes[r + 5], bytes[r + 6], bytes[r + 7]]);
            if sz == 0 {
                bad_ref = Some(format!("page reference #{i} has zero size"));
                break;
            }
            match off.checked_add(sz) {
                Some(end) if end <= hbin_data_size => {}
                _ => {
                    bad_ref = Some(format!("page reference #{i} (offset {off}, size {sz}) exceeds hbin data size {hbin_data_size}"));
                    break;
                }
            }
            payload = payload.saturating_add(sz as u64);
        }
        if let Some(why) = bad_ref {
            problems.push(invalid(why));
            usable_len = pos;
            break;
        }
        if HVLE_HEADER_SIZE + refs_bytes + payload > size as u64 {
            problems.push(invalid(format!("dirty page payload {payload} bytes does not fit in entry of {size} bytes")));
            usable_len = pos;
            break;
        }

        entries.push(LogEntry { offset: pos, size, sequence, hbin_data_size, dirty_pages, payload_bytes: payload });
        pos += size as u64;
    }

    if entries.is_empty() {
        return Err(crate::err!(code::LOG_NO_ENTRIES, "{label}"));
    }

    for w in entries.windows(2) {
        if w[1].sequence != w[0].sequence.wrapping_add(1) {
            problems.push(crate::err!(code::LOG_SEQUENCE_JUMP, "{label}: entry sequence jumps from {} to {}", w[0].sequence, w[1].sequence));
            break;
        }
    }

    Ok(LogSummary { path: path.to_path_buf(), file_len, header, entries, usable_len, problems })
}

/// Reads and inspects a transaction log on disk.
pub fn inspect_log(path: &Path) -> Result<LogSummary> {
    let bytes = std::fs::read(path).map_err(|e| crate::err!(code::LOG_OPEN_FAILED, "{}: {e}", path.display()))?;
    inspect_log_bytes(path, &bytes)
}

/// Compares an inspected log with the hive it is meant for.
pub fn relation_to_hive(summary: &LogSummary, hive: &HiveHeader) -> LogRelation {
    let log_name = summary.header.embedded_name.trim();
    let hive_name = hive.embedded_name.trim();
    if !log_name.is_empty() && !hive_name.is_empty() && !log_name.eq_ignore_ascii_case(hive_name) {
        return LogRelation::Foreign;
    }
    by_the_format(summary, hive)
}

/// The rule of the regf specification (transaction log files, new format, notes 5 and 7):
/// recovery starts at the log entry whose sequence equals the primary sequence of the
/// log's own base block, and that sequence must not be less than the hive's secondary
/// sequence. A log written before the hive's last complete write is stale. Nothing bounds
/// it from above: a hive copied while it was being written (a live system, a shadow copy)
/// has logs that start later than its own sequence, and they are applied.
fn by_the_format(summary: &LogSummary, hive: &HiveHeader) -> LogRelation {
    let start = summary.header.primary_sequence;
    let last = summary.last_sequence().unwrap_or(0);
    // Every entry at or before the hive's secondary sequence is already in the hive file.
    if last <= hive.secondary_sequence || start < hive.secondary_sequence {
        return LogRelation::Stale;
    }
    if !summary.entries.iter().any(|e| e.sequence == start) {
        return LogRelation::Gap;
    }
    LogRelation::Matching
}

/// A file considered as a log of a hive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The file.
    pub path: PathBuf,
    /// Which slot.
    pub slot: LogSlot,
    /// Found in the hive's own folder.
    pub same_directory: bool,
    /// Higher is closer to the hive (path, name, relation, embedded name).
    pub score: i64,
    /// What the inspection found.
    pub summary: Option<LogSummary>,
    /// How it relates to the hive.
    pub relation: Option<LogRelation>,
}

/// The logs chosen for a hive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSearch {
    /// The `.LOG1` chosen.
    pub log1: Option<Candidate>,
    /// The `.LOG2` chosen.
    pub log2: Option<Candidate>,
    /// Files considered and rejected, with why.
    pub rejected: Vec<(PathBuf, Error)>,
}

impl LogSearch {
    /// Nothing chosen.
    pub fn is_empty(&self) -> bool {
        self.log1.is_none() && self.log2.is_none()
    }

    /// Candidates worth handing to the replay (Matching or Stale; the replay drops old
    /// entries itself).
    pub fn usable(&self) -> Vec<&Candidate> {
        [&self.log1, &self.log2].into_iter().flatten().filter(|c| matches!(c.relation, Some(LogRelation::Matching) | Some(LogRelation::Stale))).collect()
    }

    /// At least one log continues the hive's sequence.
    pub fn has_matching(&self) -> bool {
        [&self.log1, &self.log2].into_iter().flatten().any(|c| c.relation == Some(LogRelation::Matching))
    }

    /// Paths of the chosen logs.
    pub fn paths(&self) -> Vec<PathBuf> {
        [&self.log1, &self.log2].into_iter().flatten().map(|c| c.path.clone()).collect()
    }

    /// Rejected files that are old-format logs (replayable through the old-format path).
    pub fn legacy(&self) -> Vec<PathBuf> {
        self.rejected.iter().filter(|(_, e)| e.code == code::LOG_LEGACY_FORMAT).map(|(p, _)| p.clone()).collect()
    }
}

/// `(upper-case file name, path)` of every log file under a root.
pub type LogIndex = Rc<Vec<(String, PathBuf)>>;

thread_local! {
    static LOG_INDEX: RefCell<HashMap<PathBuf, LogIndex>> = RefCell::new(HashMap::new());
}

/// Every `.LOG1` / `.LOG2` / `.LOG` under `root`, indexed once per root and thread.
pub fn log_index(root: &Path) -> LogIndex {
    let key = root.to_path_buf();
    if let Some(cached) = LOG_INDEX.with(|m| m.borrow().get(&key).cloned()) {
        return cached;
    }
    let mut files = Vec::new();
    for entry in WalkDir::new(root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_uppercase();
        if name.ends_with(".LOG1") || name.ends_with(".LOG2") || name.ends_with(".LOG") {
            files.push((name, entry.path().to_path_buf()));
        }
    }
    files.sort();
    diag::info(code::LOG_INDEX_BUILT, format!("{}: {} log file(s)", root.display(), files.len()));
    let rc = Rc::new(files);
    LOG_INDEX.with(|m| m.borrow_mut().insert(key, rc.clone()));
    rc
}

/// Forgets the cached indexes of this thread (tests reuse folders; the CLI never needs it).
pub fn clear_log_index() {
    LOG_INDEX.with(|m| m.borrow_mut().clear());
}

/// Does `candidate_name` look like the `slot` log of a hive named `hive_name` of `hive_kind`?
pub fn name_matches(hive_name: &str, hive_kind: HiveKind, candidate_name: &str, slot: LogSlot) -> bool {
    let hive_upper = hive_name.to_uppercase();
    let cand = candidate_name.to_uppercase();
    let ext = slot.extension();
    if !cand.ends_with(ext) {
        return false;
    }
    let stem = &cand[..cand.len() - ext.len()];
    if stem == hive_upper {
        return true;
    }
    if let Some(canon) = hive_kind.canonical_file_name() {
        if stem == canon || stem.ends_with(&format!("_{canon}")) || stem.ends_with(&format!("-{canon}")) || stem.ends_with(&format!(".{canon}")) {
            return true;
        }
        if HiveKind::from_file_name(stem) == hive_kind && hive_kind != HiveKind::Unknown {
            return true;
        }
    }
    false
}

fn trailing_components(p: &Path) -> Vec<String> {
    p.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_uppercase()),
            _ => None,
        })
        .collect()
}

/// Path-based score: higher is closer to the hive.
pub fn score_candidate(hive_path: &Path, candidate: &Path) -> i64 {
    let mut score: i64 = 0;
    let hive_parent = hive_path.parent().unwrap_or(hive_path);
    let cand_parent = candidate.parent().unwrap_or(candidate);
    if hive_parent == cand_parent {
        score += 1000;
    }
    let hp = trailing_components(hive_parent);
    let cp = trailing_components(cand_parent);
    let mut matched = 0;
    for (a, b) in hp.iter().rev().zip(cp.iter().rev()) {
        if a == b {
            matched += 1;
        } else {
            break;
        }
    }
    if matched >= 1 {
        score += 300;
    }
    if matched > 1 {
        score += 100 * (matched as i64 - 1).min(3);
    }
    let hive_name = hive_path.file_name().map(|n| n.to_string_lossy().to_uppercase()).unwrap_or_default();
    let cand_name = candidate.file_name().map(|n| n.to_string_lossy().to_uppercase()).unwrap_or_default();
    if cand_name.starts_with(&format!("{hive_name}.")) {
        score += 50;
    }
    score
}

/// What the locator needs to know about the hive.
#[derive(Debug, Clone)]
pub struct LogTarget<'a> {
    /// The hive file.
    pub path: &'a Path,
    /// Its base block.
    pub header: &'a HiveHeader,
    /// Its kind (header and name resolved).
    pub kind: HiveKind,
    /// Where to look beyond the hive's folder; `None` looks only next to the hive.
    pub search_root: Option<&'a Path>,
}

impl LogTarget<'_> {
    fn file_name(&self) -> String {
        self.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
    }
}

/// Every file that could be the `slot` log of the hive, nearest first.
pub fn find_candidates(target: &LogTarget<'_>, slot: LogSlot) -> Vec<PathBuf> {
    let hive_name = target.file_name();
    let mut out: Vec<PathBuf> = Vec::new();

    if let Some(parent) = target.path.parent() {
        if let Ok(rd) = std::fs::read_dir(parent) {
            for e in rd.flatten() {
                if !e.path().is_file() {
                    continue;
                }
                let n = e.file_name().to_string_lossy().to_string();
                if name_matches(&hive_name, target.kind, &n, slot) {
                    out.push(e.path());
                }
            }
        }
    }

    if let Some(root) = target.search_root.filter(|r| r.is_dir()) {
        for (upper, path) in log_index(root).iter() {
            if out.contains(path) {
                continue;
            }
            if name_matches(&hive_name, target.kind, upper, slot) {
                out.push(path.clone());
            }
        }
    }

    out.sort_by(|a, b| score_candidate(target.path, b).cmp(&score_candidate(target.path, a)).then_with(|| a.cmp(b)));
    out
}

fn evaluate(target: &LogTarget<'_>, path: &Path, slot: LogSlot) -> Result<Candidate> {
    let summary = inspect_log(path)?;
    let relation = relation_to_hive(&summary, target.header);
    if relation == LogRelation::Foreign {
        return Err(crate::err!(code::LOG_FOREIGN, "{} says '{}' but hive {} says '{}'", path.display(), summary.header.embedded_name, target.path.display(), target.header.embedded_name));
    }
    let same_directory = target.path.parent() == path.parent();
    let mut score = score_candidate(target.path, path);
    score += match relation {
        LogRelation::Matching => 500,
        LogRelation::Stale | LogRelation::Gap => 100,
        LogRelation::Foreign => -10_000,
    };
    let name = summary.header.embedded_name.trim();
    if !name.is_empty() && name.eq_ignore_ascii_case(target.header.embedded_name.trim()) {
        score += 200;
    }
    diag::info(code::LOG_CANDIDATE, format!("{} for {}: score {score}, {relation:?}", path.display(), target.path.display()));
    Ok(Candidate { path: path.to_path_buf(), slot, same_directory, score, summary: Some(summary), relation: Some(relation) })
}

fn pick(target: &LogTarget<'_>, slot: LogSlot, rejected: &mut Vec<(PathBuf, Error)>) -> Option<Candidate> {
    let mut evaluated: Vec<Candidate> = Vec::new();
    for path in find_candidates(target, slot) {
        match evaluate(target, &path, slot) {
            Ok(c) => evaluated.push(c),
            Err(e) => rejected.push((path, e)),
        }
    }
    if evaluated.is_empty() {
        return None;
    }
    evaluated.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.path.cmp(&b.path)));
    if evaluated.len() > 1 && evaluated[0].score == evaluated[1].score {
        diag::warn(code::LOG_AMBIGUOUS, format!("{} for {}: picked {} over {}", slot.extension(), target.path.display(), evaluated[0].path.display(), evaluated[1].path.display()));
    }
    let chosen = evaluated.swap_remove(0);
    if !chosen.same_directory {
        diag::info(code::LOG_REMOTE_MATCH, format!("{} -> {}", target.path.display(), chosen.path.display()));
    }
    if let Some(summary) = &chosen.summary {
        for p in &summary.problems {
            diag::record(p.diagnostic(diag::Severity::Warning));
        }
    }
    Some(chosen)
}

/// LOG1 and LOG2 alternate, so a log whose first entry is ahead of the hive is fine when
/// the other log supplies the intermediate sequence numbers. Re-evaluates both against the
/// union of their entries.
pub fn reconcile_pair(log1: &mut Option<Candidate>, log2: &mut Option<Candidate>, hive: &HiveHeader) {
    let mut seqs: Vec<u32> = Vec::new();
    for c in [log1.as_ref(), log2.as_ref()].into_iter().flatten() {
        if let Some(s) = &c.summary {
            seqs.extend(s.entries.iter().map(|e| e.sequence));
        }
    }
    seqs.sort_unstable();
    seqs.dedup();
    let mut reachable: Vec<u32> = Vec::new();
    let mut next = hive.secondary_sequence.wrapping_add(1);
    while seqs.binary_search(&next).is_ok() {
        reachable.push(next);
        next = next.wrapping_add(1);
    }
    for c in [log1.as_mut(), log2.as_mut()].into_iter().flatten() {
        if c.relation == Some(LogRelation::Foreign) {
            continue;
        }
        let Some(s) = &c.summary else { continue };
        let mine: Vec<u32> = s.entries.iter().map(|e| e.sequence).collect();
        // Continuing the hive's own sequence, directly or through the other log, or starting
        // where its base block says (the format's rule): either way it is replayed.
        let relation = if mine.iter().any(|q| reachable.contains(q)) {
            LogRelation::Matching
        } else {
            by_the_format(s, hive)
        };
        if relation == LogRelation::Matching && !mine.iter().any(|q| reachable.contains(q)) {
            diag::warn(code::LOG_AHEAD, format!("{}: starts at {} (its base block), the hive's secondary sequence is {}: applied by the format; writes {} to {} are in no log", c.path.display(), s.header.primary_sequence, hive.secondary_sequence, hive.secondary_sequence.wrapping_add(1), s.header.primary_sequence.wrapping_sub(1)));
        }
        c.relation = Some(relation);
    }
}

/// Locates, verifies and ranks the logs of a hive. Every rejection is recorded.
pub fn locate_logs(target: &LogTarget<'_>) -> LogSearch {
    let mut rejected = Vec::new();
    let mut log1 = pick(target, LogSlot::Log1, &mut rejected);
    let mut log2 = pick(target, LogSlot::Log2, &mut rejected);
    reconcile_pair(&mut log1, &mut log2, target.header);
    for c in [log1.as_ref(), log2.as_ref()].into_iter().flatten() {
        match c.relation {
            Some(LogRelation::Gap) => {
                diag::warn(code::LOG_GAP, format!("{}: first entry {} is ahead of the hive's secondary sequence {} (intermediate log missing)", c.path.display(), c.summary.as_ref().and_then(|s| s.first_sequence()).unwrap_or(0), target.header.secondary_sequence));
            }
            Some(LogRelation::Stale) => {
                diag::info(code::LOG_STALE, format!("{}: last entry {} is not after the hive's secondary sequence {}", c.path.display(), c.summary.as_ref().and_then(|s| s.last_sequence()).unwrap_or(0), target.header.secondary_sequence));
            }
            _ => {}
        }
    }

    if log1.is_none() && log2.is_none() {
        for legacy in find_candidates(target, LogSlot::Legacy) {
            if !rejected.iter().any(|(p, _)| *p == legacy) {
                rejected.push((legacy.clone(), crate::err!(code::LOG_LEGACY_FORMAT, "{}", legacy.display())));
            }
        }
    }
    for (_, err) in &rejected {
        let severity = if err.code == code::LOG_LEGACY_FORMAT { diag::Severity::Info } else { diag::Severity::Warning };
        diag::record(err.diagnostic(severity));
    }
    LogSearch { log1, log2, rejected }
}

/// The logs named explicitly by the caller, inspected the same way; missing files are recorded.
pub fn given_logs(target: &LogTarget<'_>, paths: &[PathBuf]) -> LogSearch {
    let mut search = LogSearch::default();
    for p in paths {
        if !p.is_file() {
            search.rejected.push((p.clone(), diag::warned(crate::err!(code::LOG_GIVEN_MISSING, "{}", p.display()))));
            continue;
        }
        let upper = p.file_name().map(|n| n.to_string_lossy().to_uppercase()).unwrap_or_default();
        let slot = if upper.ends_with(".LOG2") { LogSlot::Log2 } else { LogSlot::Log1 };
        match evaluate(target, p, slot) {
            Ok(c) => {
                let slot_ref = match slot {
                    LogSlot::Log2 => &mut search.log2,
                    _ => &mut search.log1,
                };
                if slot_ref.is_none() {
                    *slot_ref = Some(c);
                } else if search.log2.is_none() {
                    search.log2 = Some(c);
                } else {
                    search.rejected.push((p.clone(), diag::warned(crate::err!(code::LOG_AMBIGUOUS, "{}: a third log given for one hive", p.display()))));
                }
            }
            Err(e) => {
                let severity = if e.code == code::LOG_LEGACY_FORMAT { diag::Severity::Info } else { diag::Severity::Warning };
                diag::record(e.diagnostic(severity));
                search.rejected.push((p.clone(), e));
            }
        }
    }
    reconcile_pair(&mut search.log1, &mut search.log2, target.header);
    search
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::*;

    fn hive_bytes() -> Vec<u8> {
        let mut b = HiveBuilder::software();
        b.sz(r"Microsoft\Windows\CurrentVersion\Run", "x", "y");
        b.build_with(6, 5)
    }

    fn page(n: usize) -> Vec<u8> {
        vec![0xAB; n]
    }

    fn log_with(entries: &[LogEntryDef]) -> Vec<u8> {
        build_log(&hive_bytes(), entries)
    }

    fn entry(seq: u32, pages: Vec<(u32, Vec<u8>)>) -> LogEntryDef {
        LogEntryDef { sequence: seq, hbin_data_size: 8192, pages }
    }

    fn inspect(bytes: &[u8]) -> Result<LogSummary> {
        inspect_log_bytes(Path::new("test.LOG1"), bytes)
    }

    fn two_entries() -> Vec<u8> {
        log_with(&[entry(6, vec![(0, page(4096))]), entry(7, vec![(0, page(4096))])])
    }

    fn second_entry_offset(b: &[u8]) -> usize {
        inspect(b).unwrap().entries[1].offset as usize
    }

    #[test]
    fn fatal_rejections() {
        assert_eq!(inspect(&[0u8; 100]).unwrap_err().code, code::LOG_TRUNCATED);
        assert_eq!(inspect(&[0u8; 1024]).unwrap_err().code, code::LOG_SIGNATURE_INVALID);
        let mut b = hive_bytes();
        patch_base_block(&mut b, 6, 6, 1);
        assert_eq!(inspect(&b[..1024]).unwrap_err().code, code::LOG_LEGACY_FORMAT);
        patch_base_block(&mut b, 6, 6, 2);
        assert_eq!(inspect(&b[..1024]).unwrap_err().code, code::LOG_LEGACY_FORMAT);
        let e = inspect(&hive_bytes()).unwrap_err();
        assert_eq!(e.code, code::LOG_IS_PRIMARY);
        patch_base_block(&mut b, 6, 6, 42);
        assert_eq!(inspect(&b[..1024]).unwrap_err().code, code::LOG_UNKNOWN_FILE_TYPE);
        let empty = log_with(&[]);
        assert_eq!(empty.len(), 512);
        assert_eq!(inspect(&empty).unwrap_err().code, code::LOG_NO_ENTRIES);
        let mut padded = log_with(&[]);
        padded.extend_from_slice(&[0u8; 4096]);
        assert_eq!(inspect(&padded).unwrap_err().code, code::LOG_NO_ENTRIES);
        let mut first_bad = log_with(&[entry(6, vec![(0, page(4096))])]);
        first_bad[512 + 20..512 + 24].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(inspect(&first_bad).unwrap_err().code, code::LOG_NO_ENTRIES);
    }

    #[test]
    fn valid_logs() {
        let b = log_with(&[entry(6, vec![(0, page(4096))])]);
        let s = inspect(&b).unwrap();
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.entries[0].sequence, 6);
        assert_eq!(s.entries[0].offset, 512);
        assert_eq!(s.entries[0].dirty_pages, 1);
        assert_eq!(s.entries[0].payload_bytes, 4096);
        assert_eq!(s.entries[0].hbin_data_size, 8192);
        assert_eq!(s.entries[0].size as usize, (40 + 8 + 4096usize).div_ceil(512) * 512);
        assert_eq!(s.file_len, b.len() as u64);
        assert_eq!(s.usable_len, s.file_len);
        assert!(!s.needs_sanitizing());
        assert!(s.problems.is_empty());
        assert_eq!(s.first_sequence(), Some(6));
        assert_eq!(s.last_sequence(), Some(6));
        assert_eq!(s.embedded_name(), r"emRoot\System32\Config\SOFTWARE");
        assert!(s.header.is_new_log());
        assert!(s.header.checksum_valid());

        let b = log_with(&[entry(6, vec![(0, page(4096))]), entry(7, vec![(4096, page(4096))]), entry(8, vec![(0, page(512))])]);
        let s = inspect(&b).unwrap();
        assert_eq!(s.entries.iter().map(|e| e.sequence).collect::<Vec<_>>(), vec![6, 7, 8]);
        assert!(s.problems.is_empty());

        let b = log_with(&[entry(6, vec![(0, page(4096)), (4096, page(4096))])]);
        let s = inspect(&b).unwrap();
        assert_eq!(s.entries[0].dirty_pages, 2);
        assert_eq!(s.entries[0].payload_bytes, 8192);

        let mut b = log_with(&[entry(6, vec![(0, page(4096))])]);
        b.extend_from_slice(&[0u8; 8192]);
        let s = inspect(&b).unwrap();
        assert_eq!(s.entries.len(), 1);
        assert!(!s.needs_sanitizing());

        let mut b = log_with(&[entry(6, vec![(0, page(4096))])]);
        b.extend_from_slice(b"JUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNKJUNK");
        assert_eq!(inspect(&b).unwrap().entries.len(), 1);

        let b = log_with(&[entry(6, vec![(0, page(4096))]), entry(9, vec![(0, page(4096))])]);
        let s = inspect(&b).unwrap();
        assert_eq!(s.entries.len(), 2);
        assert!(s.problems.iter().any(|p| p.code == code::LOG_SEQUENCE_JUMP));

        let mut b = log_with(&[entry(6, vec![(0, page(4096))])]);
        b[0x40] ^= 0x55;
        let s = inspect(&b).unwrap();
        assert!(s.problems.iter().any(|p| p.code == code::LOG_CHECKSUM_INVALID));
        assert_eq!(s.entries.len(), 1);
    }

    #[test]
    fn damaged_tails_are_cut() {
        let b = two_entries();
        let off2 = second_entry_offset(&b);
        let s = inspect(&b[..off2 + 1000]).unwrap();
        assert_eq!(s.entries.len(), 1);
        assert!(s.needs_sanitizing());
        assert_eq!(s.usable_len, off2 as u64);
        assert!(s.problems.iter().any(|p| p.code == code::LOG_TRUNCATED));

        let cases: Vec<(usize, u32, &str)> = vec![
            (4, 16, "smaller than the header"),
            (4, 4096 + 100, "not a multiple"),
            (8, 0xF0, "flags"),
            (20, 0, "zero dirty pages"),
            (20, 0xFFFF_FFFF, "do not fit"),
            (16, 4097, "4096-aligned"),
            (44, 0, "zero size"),
            (44, 0x7FFF_FFF0, "exceeds hbin data size"),
            (44, 8192, "does not fit in entry"),
        ];
        for (off, val, text) in cases {
            let mut b = two_entries();
            let off2 = second_entry_offset(&b);
            b[off2 + off..off2 + off + 4].copy_from_slice(&val.to_le_bytes());
            let s = inspect(&b).unwrap();
            assert_eq!(s.entries.len(), 1, "{text}");
            assert!(s.needs_sanitizing(), "{text}");
            assert!(s.problems.iter().any(|p| p.detail.contains(text)), "{text}: {:?}", s.problems);
        }

        let mut b = two_entries();
        let off2 = second_entry_offset(&b);
        b[off2 + 40..off2 + 44].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        b[off2 + 44..off2 + 48].copy_from_slice(&0x100u32.to_le_bytes());
        assert_eq!(inspect(&b).unwrap().entries.len(), 1, "offset overflow");

        let mut b = log_with(&[entry(6, vec![(0, page(512))]), entry(7, vec![(0, page(512))]), entry(8, vec![(0, page(512))])]);
        let off3 = inspect(&b).unwrap().entries[2].offset as usize;
        b[off3 + 20..off3 + 24].copy_from_slice(&0u32.to_le_bytes());
        let s = inspect(&b).unwrap();
        assert_eq!(s.entries.len(), 2);
        assert_eq!(s.usable_len, off3 as u64);
    }

    fn hive_header(primary: u32, secondary: u32, name: &str) -> HiveHeader {
        HiveHeader::parse(&base_block(primary, secondary, 0x20, 4096, name, 0, 5), "h").unwrap()
    }

    #[test]
    fn relations() {
        let sw = r"emRoot\System32\Config\SOFTWARE";
        let s = inspect(&log_with(&[entry(6, vec![(0, page(512))])])).unwrap();
        assert_eq!(relation_to_hive(&s, &hive_header(6, 5, sw)), LogRelation::Matching);
        assert_eq!(relation_to_hive(&s, &hive_header(6, 5, r"emRoot\System32\Config\SYSTEM")), LogRelation::Foreign);
        assert_eq!(relation_to_hive(&s, &hive_header(6, 5, "")), LogRelation::Matching);
        assert_eq!(relation_to_hive(&s, &hive_header(6, 5, &sw.to_uppercase())), LogRelation::Matching);
        let s = inspect(&log_with(&[entry(4, vec![(0, page(512))]), entry(5, vec![(0, page(512))])])).unwrap();
        assert_eq!(relation_to_hive(&s, &hive_header(6, 5, sw)), LogRelation::Stale);
        // A log that starts after the hive, at its own base block's sequence: the format
        // applies it (a hive copied while it was being written).
        let s = inspect(&log_with(&[entry(9, vec![(0, page(512))])])).unwrap();
        assert_eq!(relation_to_hive(&s, &hive_header(6, 5, sw)), LogRelation::Matching);
        // A log whose entries never reach the sequence its base block starts at cannot start.
        let mut s = inspect(&log_with(&[entry(9, vec![(0, page(512))]), entry(10, vec![(0, page(512))])])).unwrap();
        s.header.primary_sequence = 8;
        assert_eq!(relation_to_hive(&s, &hive_header(6, 5, sw)), LogRelation::Gap);
        // Its base block older than the hive's last complete write: stale.
        let mut s = inspect(&log_with(&[entry(9, vec![(0, page(512))])])).unwrap();
        s.header.primary_sequence = 4;
        assert_eq!(relation_to_hive(&s, &hive_header(6, 5, sw)), LogRelation::Stale);
        let s = inspect(&log_with(&[entry(5, vec![(0, page(512))]), entry(6, vec![(0, page(512))])])).unwrap();
        assert_eq!(relation_to_hive(&s, &hive_header(6, 5, sw)), LogRelation::Matching);
    }

    #[test]
    fn names() {
        assert!(name_matches("SYSTEM", HiveKind::System, "SYSTEM.LOG1", LogSlot::Log1));
        assert!(name_matches("SYSTEM", HiveKind::System, "system.log1", LogSlot::Log1));
        assert!(!name_matches("SYSTEM", HiveKind::System, "SYSTEM.LOG2", LogSlot::Log1));
        assert!(name_matches("bob_NTUSER.DAT", HiveKind::NtUser, "bob_NTUSER.DAT.LOG1", LogSlot::Log1));
        assert!(name_matches("bob_NTUSER.DAT", HiveKind::NtUser, "NTUSER.DAT.LOG1", LogSlot::Log1));
        assert!(name_matches("SOFTWARE", HiveKind::Software, "HOST_SOFTWARE.LOG2", LogSlot::Log2));
        assert!(name_matches("SOFTWARE", HiveKind::Software, "C_Windows_System32_config_SOFTWARE.LOG2", LogSlot::Log2));
        assert!(name_matches("SOFTWARE.hve", HiveKind::Software, "SOFTWARE.LOG1", LogSlot::Log1));
        assert!(name_matches("SYSTEM", HiveKind::System, "SYSTEM.LOG", LogSlot::Legacy));
        assert!(!name_matches("SYSTEM", HiveKind::System, "SYSTEM.LOG1", LogSlot::Legacy));
        assert!(!name_matches("SYSTEM", HiveKind::System, "SOFTWARE.LOG1", LogSlot::Log1));
        assert!(!name_matches("NTUSER.DAT", HiveKind::NtUser, "UsrClass.dat.LOG1", LogSlot::Log1));
        assert!(name_matches("blob.bin", HiveKind::Unknown, "blob.bin.LOG1", LogSlot::Log1));
        assert!(!name_matches("blob.bin", HiveKind::Unknown, "SYSTEM.LOG1", LogSlot::Log1));
        assert_eq!(LogSlot::Log1.extension(), ".LOG1");
        assert_eq!(LogSlot::Log2.extension(), ".LOG2");
        assert_eq!(LogSlot::Legacy.extension(), ".LOG");
    }

    #[test]
    fn scores() {
        let h = Path::new("/ev/C/Windows/System32/config/SYSTEM");
        let same = score_candidate(h, Path::new("/ev/C/Windows/System32/config/SYSTEM.LOG1"));
        let other = score_candidate(h, Path::new("/ev/logs/config/SYSTEM.LOG1"));
        assert!(same > other);
        assert!(same >= 1000);
        let h = Path::new("/ev/files/C/Users/bob/NTUSER.DAT");
        let bob = score_candidate(h, Path::new("/ev/logs/C/Users/bob/NTUSER.DAT.LOG1"));
        let alice = score_candidate(h, Path::new("/ev/logs/C/Users/alice/NTUSER.DAT.LOG1"));
        assert!(bob > alice, "{bob} vs {alice}");
        let h = Path::new("/ev/x/bob_NTUSER.DAT");
        let exact = score_candidate(h, Path::new("/ev/y/bob_NTUSER.DAT.LOG1"));
        let canon = score_candidate(h, Path::new("/ev/y/NTUSER.DAT.LOG1"));
        assert!(exact > canon);
        let h = Path::new("/ev/C/Users/Bob/NTUSER.DAT");
        let a = score_candidate(h, Path::new("/ev/logs/users/bob/NTUSER.DAT.LOG1"));
        let b = score_candidate(h, Path::new("/ev/logs/users/alice/NTUSER.DAT.LOG1"));
        assert!(a > b);
    }

    #[test]
    fn inspect_on_disk() {
        assert_eq!(inspect_log(Path::new("Z:/nope/SYSTEM.LOG1")).unwrap_err().code, code::LOG_OPEN_FAILED);
        let l1 = inspect_log(&fixture("dirty_hive/NewDirtyHive.LOG1")).unwrap();
        assert_eq!(l1.entries.len(), 1);
        assert_eq!(l1.entries[0].sequence, 2);
        assert_eq!(l1.entries[0].dirty_pages, 1);
        assert_eq!(l1.entries[0].payload_bytes, 0x5000);
        assert!(l1.problems.is_empty(), "{:?}", l1.problems);
        let l2 = inspect_log(&fixture("dirty_hive/NewDirtyHive.LOG2")).unwrap();
        assert!(!l2.entries.is_empty());
        assert!(l2.problems.is_empty(), "{:?}", l2.problems);
        let hive = crate::header::read_header(&fixture("dirty_hive/NewDirtyHive")).unwrap();
        assert_eq!(relation_to_hive(&l1, &hive), LogRelation::Stale);
        assert_eq!(relation_to_hive(&l2, &hive), LogRelation::Matching);
    }

    #[test]
    fn search_helpers_and_index() {
        let sel = LogSearch::default();
        assert!(sel.is_empty());
        assert!(sel.usable().is_empty());
        assert!(sel.paths().is_empty());
        assert!(sel.legacy().is_empty());
        assert!(!sel.has_matching());

        let d = TempDir::new("loc_index");
        d.write("a/SOFTWARE.LOG1", b"x");
        clear_log_index();
        diag::clear();
        let first = log_index(&d.path);
        assert_eq!(first.len(), 1);
        assert!(diag::has(code::LOG_INDEX_BUILT));
        d.write("b/SYSTEM.LOG2", b"y");
        assert_eq!(log_index(&d.path).len(), 1, "cached");
        clear_log_index();
        assert_eq!(log_index(&d.path).len(), 2);
        clear_log_index();
        diag::clear();
    }

    #[test]
    fn candidates_and_reconcile() {
        let d = TempDir::new("loc_cands");
        let base = HiveBuilder::software();
        let mut step = HiveBuilder::software();
        step.sz("K", "Marker", "m");
        let fx = build_dirty(&base, &[&step], 5, false);
        let hive = d.write("cfg/SOFTWARE", &fx.primary);
        d.write("cfg/SOFTWARE.LOG1", &fx.log1);
        d.write("other/HOST_SOFTWARE.LOG1", &fx.log1);
        d.write("other/SYSTEM.LOG1", &fx.log1);
        clear_log_index();
        let header = crate::header::read_header(&hive).unwrap();
        let target = LogTarget { path: &hive, header: &header, kind: HiveKind::Software, search_root: Some(&d.path) };
        let c = find_candidates(&target, LogSlot::Log1);
        assert_eq!(c, vec![d.join("cfg/SOFTWARE.LOG1"), d.join("other/HOST_SOFTWARE.LOG1")]);
        assert!(find_candidates(&target, LogSlot::Log2).is_empty());
        // A single-file root never walks.
        let target_file = LogTarget { search_root: Some(&hive), ..target.clone() };
        let sel = locate_logs(&target_file);
        assert!(sel.log1.is_some());
        assert!(sel.has_matching());
        assert_eq!(sel.paths(), vec![d.join("cfg/SOFTWARE.LOG1")]);

        let mut s1 = HiveBuilder::software();
        s1.sz("K", "A", "a");
        let mut s2 = HiveBuilder::software();
        s2.sz("K", "B", "b");
        let fx = build_dirty(&base, &[&s1, &s2], 5, true);
        let hive = HiveHeader::parse(&fx.primary, "h").unwrap();
        let l1 = inspect_log_bytes(Path::new("1"), &fx.log1).unwrap();
        let l2 = inspect_log_bytes(Path::new("2"), fx.log2.as_ref().unwrap()).unwrap();
        assert_eq!(relation_to_hive(&l2, &hive), LogRelation::Matching, "alone, LOG2 starts at its own base block's sequence: applicable by the format");
        let mut c1 = Some(Candidate { path: "1".into(), slot: LogSlot::Log1, same_directory: true, score: 0, relation: Some(relation_to_hive(&l1, &hive)), summary: Some(l1) });
        let mut c2 = Some(Candidate { path: "2".into(), slot: LogSlot::Log2, same_directory: true, score: 0, relation: Some(LogRelation::Gap), summary: Some(l2) });
        reconcile_pair(&mut c1, &mut c2, &hive);
        assert_eq!(c1.as_ref().unwrap().relation, Some(LogRelation::Matching));
        assert_eq!(c2.as_ref().unwrap().relation, Some(LogRelation::Matching));
        clear_log_index();
        diag::clear();
    }
}
