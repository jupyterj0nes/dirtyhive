//! Diagnostics: stable codes, the error type and the per-thread sink.
//!
//! Every failure, skip or decision an analyst may need to trace carries a code
//! `DH###_NAME`. Each module declares its codes with [`codes!`](crate::codes) in a `pub mod code`
//! block inside its range; [`catalog`] gathers them all and a test checks that no
//! number is used twice.
//!
//! | Range   | Area |
//! |---------|------|
//! | 000-099 | opening a hive: file, base block, classification, parser |
//! | 100-199 | transaction logs: location, validation, replay |
//! | 200-299 | hive bins and cells: deleted keys and values |
//! | 300-399 | keys and values: lookup, walk, decoding |
//! | 400-449 | discovery of hives under a folder |
//!
//! Degraded paths do not stop the work: they [`record`] a [`Diagnostic`] in the sink
//! of the current thread and carry on. A caller (a tool, a test) drains the sink to
//! report or assert what happened. Nothing is printed unless [`set_echo`] asks for it.

use std::cell::RefCell;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

/// A stable diagnostic code: `DH` + three digits + a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Code {
    /// The number, unique across the crate.
    pub id: u16,
    /// The constant's name, in upper snake case.
    pub name: &'static str,
    /// What it means and what to do about it.
    pub help: &'static str,
}

impl Code {
    /// `DH###_NAME`.
    pub fn tag(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DH{:03}_{}", self.id, self.name)
    }
}

/// Declares a module's codes and its `CODES` list:
///
/// ```ignore
/// pub mod code {
///     dirtyhive::codes! {
///         LOG_NOT_FOUND = 100, "the hive is dirty and no transaction log was found";
///     }
/// }
/// ```
#[macro_export]
macro_rules! codes {
    ($( $konst:ident = $id:literal, $help:literal; )*) => {
        $(
            #[doc = $help]
            pub const $konst: $crate::diag::Code = $crate::diag::Code { id: $id, name: stringify!($konst), help: $help };
        )*
        /// Every code of this module.
        pub const CODES: &[$crate::diag::Code] = &[$($konst),*];
    };
}

/// How bad a diagnostic is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// Nothing was lost; a decision worth tracing (a log applied, a candidate chosen).
    Info,
    /// The work went on in a degraded way (a dirty hive kept dirty, a log cut short).
    Warning,
    /// The item could not be processed.
    Error,
}

impl Severity {
    /// `INFO`, `WARN` or `ERROR`.
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Error => "ERROR",
        }
    }
}

/// One recorded event: a code, how bad it was, and the detail (paths, numbers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// The code.
    pub code: Code,
    /// How bad.
    pub severity: Severity,
    /// The specifics: file, offset, counts.
    pub detail: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity.label(), self.code, self.detail)
    }
}

/// An error returned to the caller: a code and its detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The code.
    pub code: Code,
    /// The specifics.
    pub detail: String,
}

impl Error {
    /// A new error.
    pub fn new(code: Code, detail: impl Into<String>) -> Self {
        Error { code, detail: detail.into() }
    }

    /// The same error as a diagnostic of the given severity.
    pub fn diagnostic(&self, severity: Severity) -> Diagnostic {
        Diagnostic { code: self.code, severity, detail: self.detail.clone() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Error {}

/// The crate's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Builds an [`Error`]: `err!(code::X, "{}: {e}", path.display())`.
#[macro_export]
macro_rules! err {
    ($code:expr, $($arg:tt)+) => { $crate::diag::Error::new($code, format!($($arg)+)) };
}

thread_local! {
    static SINK: RefCell<Vec<Diagnostic>> = const { RefCell::new(Vec::new()) };
}
static ECHO: AtomicBool = AtomicBool::new(false);
static ECHO_INFO: AtomicBool = AtomicBool::new(false);

/// Also print every warning and error to stderr as it is recorded (`echo_info` adds the
/// infos). Off by default: a library stays silent.
pub fn set_echo(echo: bool, echo_info: bool) {
    ECHO.store(echo, Ordering::Relaxed);
    ECHO_INFO.store(echo_info, Ordering::Relaxed);
}

/// Records a diagnostic in this thread's sink and returns it.
pub fn record(d: Diagnostic) -> Diagnostic {
    if ECHO.load(Ordering::Relaxed) && (d.severity != Severity::Info || ECHO_INFO.load(Ordering::Relaxed)) {
        eprintln!("{d}");
    }
    SINK.with(|s| s.borrow_mut().push(d.clone()));
    d
}

/// Records `code` at the given severity.
pub fn note(severity: Severity, code: Code, detail: impl Into<String>) -> Diagnostic {
    record(Diagnostic { code, severity, detail: detail.into() })
}

/// Records an info.
pub fn info(code: Code, detail: impl Into<String>) -> Diagnostic {
    note(Severity::Info, code, detail)
}

/// Records a warning.
pub fn warn(code: Code, detail: impl Into<String>) -> Diagnostic {
    note(Severity::Warning, code, detail)
}

/// Records an error and returns it, for `return Err(diag::error(e))`.
pub fn error(e: Error) -> Error {
    record(e.diagnostic(Severity::Error));
    e
}

/// Records an error as a warning (the work went on without the item) and returns it.
pub fn warned(e: Error) -> Error {
    record(e.diagnostic(Severity::Warning));
    e
}

/// Removes and returns every recorded diagnostic of this thread.
pub fn drain() -> Vec<Diagnostic> {
    SINK.with(|s| std::mem::take(&mut *s.borrow_mut()))
}

/// A copy of every recorded diagnostic of this thread.
pub fn snapshot() -> Vec<Diagnostic> {
    SINK.with(|s| s.borrow().clone())
}

/// Forgets everything recorded on this thread.
pub fn clear() {
    SINK.with(|s| s.borrow_mut().clear());
}

/// Puts diagnostics recorded elsewhere (a worker thread) into this thread's sink.
pub fn absorb(list: Vec<Diagnostic>) {
    SINK.with(|s| s.borrow_mut().extend(list));
}

/// How many times `code` was recorded on this thread.
pub fn count(code: Code) -> usize {
    SINK.with(|s| s.borrow().iter().filter(|d| d.code == code).count())
}

/// Whether `code` was recorded on this thread.
pub fn has(code: Code) -> bool {
    count(code) > 0
}

/// Per-severity counters of what this thread recorded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Errors.
    pub errors: usize,
    /// Warnings.
    pub warnings: usize,
    /// Infos.
    pub infos: usize,
}

impl Summary {
    /// Everything.
    pub fn total(&self) -> usize {
        self.errors + self.warnings + self.infos
    }
}

/// Counts what this thread recorded.
pub fn summary() -> Summary {
    SINK.with(|s| {
        let mut out = Summary::default();
        for d in s.borrow().iter() {
            match d.severity {
                Severity::Error => out.errors += 1,
                Severity::Warning => out.warnings += 1,
                Severity::Info => out.infos += 1,
            }
        }
        out
    })
}

/// The text of a caught panic.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

/// Every code of the crate, by number.
pub fn catalog() -> Vec<Code> {
    let mut all: Vec<Code> = Vec::new();
    all.extend_from_slice(crate::hive::code::CODES);
    all.extend_from_slice(crate::txlog::code::CODES);
    all.extend_from_slice(crate::deleted::code::CODES);
    all.extend_from_slice(crate::value::code::CODES);
    all.extend_from_slice(crate::discover::code::CODES);
    all.sort_by_key(|c| c.id);
    all
}

/// The code with this number or name (`DH100_LOG_NOT_FOUND`, `DH100`, `LOG_NOT_FOUND`, `100`).
pub fn lookup(what: &str) -> Option<Code> {
    let w = what.trim();
    let w = w.strip_prefix("DH").or_else(|| w.strip_prefix("dh")).unwrap_or(w);
    let (num, name) = match w.split_once('_') {
        Some((n, rest)) if n.chars().all(|c| c.is_ascii_digit()) => (n.parse::<u16>().ok(), Some(rest)),
        _ => (w.parse::<u16>().ok(), if w.chars().all(|c| c.is_ascii_digit()) { None } else { Some(w) }),
    };
    catalog().into_iter().find(|c| num == Some(c.id) || name.is_some_and(|n| n.eq_ignore_ascii_case(c.name)))
}

/// The catalogue as Markdown (what `docs/codes.md` holds).
pub fn catalog_markdown() -> String {
    let mut out = String::from("# Diagnostic codes\n\nEvery code `dirtyhive` can record or return, by number. Generated from the source: `DIRTYHIVE_WRITE_DOCS=1 cargo test --release codes_doc`.\n\n| Code | Meaning |\n|------|---------|\n");
    for c in catalog() {
        out.push_str(&format!("| `{c}` | {} |\n", c.help));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_in_range() {
        let all = catalog();
        assert!(all.len() >= 60, "the crate should carry many codes, has {}", all.len());
        let mut ids: Vec<u16> = all.iter().map(|c| c.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), all.len(), "a code number is used twice");
        let mut names: Vec<&str> = all.iter().map(|c| c.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all.len(), "a code name is used twice");
        for c in &all {
            assert!(c.id < 1000, "{c}");
            assert!(!c.help.is_empty(), "{c} has no help");
            assert!(c.help.len() >= 20, "{c}: help too short to be useful");
            assert!(c.name.chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_'), "{c}");
        }
        for c in crate::hive::code::CODES {
            assert!(c.id < 100, "{c} outside the open range");
        }
        for c in crate::txlog::code::CODES {
            assert!((100..200).contains(&c.id), "{c} outside the log range");
        }
        for c in crate::deleted::code::CODES {
            assert!((200..300).contains(&c.id), "{c} outside the cells range");
        }
        for c in crate::value::code::CODES {
            assert!((300..400).contains(&c.id), "{c} outside the values range");
        }
        for c in crate::discover::code::CODES {
            assert!((400..450).contains(&c.id), "{c} outside the discovery range");
        }
    }

    #[test]
    fn display_and_lookup() {
        let c = crate::txlog::code::LOG_NOT_FOUND;
        assert_eq!(c.to_string(), format!("DH{:03}_LOG_NOT_FOUND", c.id));
        assert_eq!(lookup(&c.to_string()), Some(c));
        assert_eq!(lookup(&format!("DH{:03}", c.id)), Some(c));
        assert_eq!(lookup(&c.id.to_string()), Some(c));
        assert_eq!(lookup("log_not_found"), Some(c));
        assert_eq!(lookup("nothing_like_this"), None);
        let e = Error::new(c, "SYSTEM");
        assert_eq!(e.to_string(), format!("{c}: SYSTEM"));
    }

    #[test]
    fn sink_records_counts_and_drains() {
        clear();
        let c = crate::txlog::code::LOG_NOT_FOUND;
        warn(c, "a");
        info(crate::hive::code::RECOVERED, "b");
        assert!(has(c));
        assert_eq!(count(c), 1);
        assert_eq!(summary(), Summary { errors: 0, warnings: 1, infos: 1 });
        assert_eq!(summary().total(), 2);
        let e = error(Error::new(c, "x"));
        assert_eq!(e.detail, "x");
        assert_eq!(summary().errors, 1);
        let got = drain();
        assert_eq!(got.len(), 3);
        assert!(snapshot().is_empty());
        absorb(got);
        assert_eq!(snapshot().len(), 3);
        assert!(snapshot()[0].to_string().starts_with("[WARN] DH"));
        clear();
    }

    #[test]
    fn markdown_lists_every_code() {
        let md = catalog_markdown();
        for c in catalog() {
            assert!(md.contains(&format!("`{c}`")), "{c} missing from the markdown");
        }
    }

    #[test]
    fn panic_message_reads_both_payloads() {
        let p: Box<dyn std::any::Any + Send> = Box::new("static");
        assert_eq!(panic_message(&*p), "static");
        let p: Box<dyn std::any::Any + Send> = Box::new(String::from("owned"));
        assert_eq!(panic_message(&*p), "owned");
        let p: Box<dyn std::any::Any + Send> = Box::new(7u8);
        assert_eq!(panic_message(&*p), "unknown panic payload");
    }
}
