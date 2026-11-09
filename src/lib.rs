//! Windows registry hives read the forensic way: transaction logs applied, deleted keys
//! and values recovered, the clean hive handed to `nt_hive2`.
//!
//! Skeleton: the modules below name the layers; their contents are being written.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The crate version, for the tools to print.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
