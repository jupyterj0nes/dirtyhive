//! Registry values: their types, their decoded data, and the timestamps around them.

use chrono::{DateTime, TimeZone, Utc};
use nt_hive2::{KeyValue, RegistryValue};

/// Codes of this module (300-399: keys and values).
pub mod code {
    crate::codes! {
        KEY_NOT_FOUND = 300, "the key path asked for does not exist in the hive; check the path against the hive's own layout (NTUSER.DAT has no HKLM subtree, SYSTEM has ControlSetNNN rather than CurrentControlSet)";
        SUBKEYS_FAILED = 301, "the subkey list of a key could not be read: the list cell is damaged or points outside the hive; the key's values are still usable, its subtree is not";
        ROOT_KEY_FAILED = 302, "the root key cell could not be parsed; the hive is unusable through the parser (the deleted-cell scan may still work on the raw bytes)";
        VALUE_UNDECODABLE = 303, "a value's data could not be decoded as its declared type (bad UTF-16, a DWORD of the wrong size); the raw bytes are kept as binary";
        VALUE_TYPE_UNKNOWN = 304, "a value carries a type number that is not a documented REG_* type (seen in SAM); the data is kept as binary";
        PATH_EMPTY = 305, "an empty key path was asked for; the root key is reached with root(), not with key(\"\")";
        WALK_DEPTH_LIMIT = 306, "the walk stopped descending at the depth limit; raise WalkLimits::max_depth if the hive really nests that deep";
        WALK_KEY_LIMIT = 307, "the walk stopped at the key limit; raise WalkLimits::max_keys for a complete listing";
        MULTI_SZ_UNTERMINATED = 308, "a REG_MULTI_SZ value does not end with the double NUL the format requires; the strings read so far are kept";
        DATA_SIZE_MISMATCH = 309, "a value's data is shorter than its declared size; it was cut by the hive or the log, and what is there is decoded";
        STRING_NOT_UTF16 = 310, "a string value is not valid UTF-16LE; it was decoded leniently with replacement characters";
        FILETIME_OUT_OF_RANGE = 311, "a FILETIME cannot be represented as a date (zero, or beyond year 9999); shown empty";
        KEY_PARSE_FAILED = 312, "a key cell could not be parsed by nt_hive2 (truncated or overwritten); the key and its subtree are skipped";
        VALUE_PARSE_PANIC = 313, "the parser panicked on a key's values; the key is reported without them";
    }
}

/// A registry value type, by number (`REG_SZ` is 1, `REG_DWORD` 4, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValueType(pub u32);

impl ValueType {
    /// `REG_NONE`.
    pub const NONE: ValueType = ValueType(0);
    /// `REG_SZ`.
    pub const SZ: ValueType = ValueType(1);
    /// `REG_EXPAND_SZ`.
    pub const EXPAND_SZ: ValueType = ValueType(2);
    /// `REG_BINARY`.
    pub const BINARY: ValueType = ValueType(3);
    /// `REG_DWORD`.
    pub const DWORD: ValueType = ValueType(4);
    /// `REG_DWORD_BIG_ENDIAN`.
    pub const DWORD_BIG_ENDIAN: ValueType = ValueType(5);
    /// `REG_LINK`.
    pub const LINK: ValueType = ValueType(6);
    /// `REG_MULTI_SZ`.
    pub const MULTI_SZ: ValueType = ValueType(7);
    /// `REG_RESOURCE_LIST`.
    pub const RESOURCE_LIST: ValueType = ValueType(8);
    /// `REG_FULL_RESOURCE_DESCRIPTOR`.
    pub const FULL_RESOURCE_DESCRIPTOR: ValueType = ValueType(9);
    /// `REG_RESOURCE_REQUIREMENTS_LIST`.
    pub const RESOURCE_REQUIREMENTS_LIST: ValueType = ValueType(10);
    /// `REG_QWORD`.
    pub const QWORD: ValueType = ValueType(11);
    /// `REG_FILETIME` (undocumented, 16).
    pub const FILETIME: ValueType = ValueType(16);

    /// The `REG_*` name, or `REG_<n>` for an unknown number.
    pub fn name(&self) -> String {
        match self.0 {
            0 => "REG_NONE".into(),
            1 => "REG_SZ".into(),
            2 => "REG_EXPAND_SZ".into(),
            3 => "REG_BINARY".into(),
            4 => "REG_DWORD".into(),
            5 => "REG_DWORD_BIG_ENDIAN".into(),
            6 => "REG_LINK".into(),
            7 => "REG_MULTI_SZ".into(),
            8 => "REG_RESOURCE_LIST".into(),
            9 => "REG_FULL_RESOURCE_DESCRIPTOR".into(),
            10 => "REG_RESOURCE_REQUIREMENTS_LIST".into(),
            11 => "REG_QWORD".into(),
            16 => "REG_FILETIME".into(),
            n => format!("REG_{n}"),
        }
    }

    /// A documented type.
    pub fn is_known(&self) -> bool {
        matches!(self.0, 0..=11 | 16)
    }

    /// A string type (`REG_SZ`, `REG_EXPAND_SZ`, `REG_LINK`).
    pub fn is_string(&self) -> bool {
        matches!(self.0, 1 | 2 | 6)
    }

    /// From the parser's type name (`RegSZ`, `RegDWord`, ...; the type itself is not exported).
    fn from_nt_name(name: &str) -> ValueType {
        match name {
            "RegNone" => ValueType::NONE,
            "RegSZ" => ValueType::SZ,
            "RegExpandSZ" => ValueType::EXPAND_SZ,
            "RegBinary" => ValueType::BINARY,
            "RegDWord" => ValueType::DWORD,
            "RegDWordBigEndian" => ValueType::DWORD_BIG_ENDIAN,
            "RegLink" => ValueType::LINK,
            "RegMultiSZ" => ValueType::MULTI_SZ,
            "RegResourceList" => ValueType::RESOURCE_LIST,
            "RegFullResourceDescriptor" => ValueType::FULL_RESOURCE_DESCRIPTOR,
            "RegResourceRequirementsList" => ValueType::RESOURCE_REQUIREMENTS_LIST,
            "RegQWord" => ValueType::QWORD,
            "RegFileTime" => ValueType::FILETIME,
            _ => ValueType(u32::MAX),
        }
    }
}

impl std::fmt::Display for ValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}

/// Decoded value data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    /// `REG_NONE` or no data.
    None,
    /// `REG_SZ`.
    Sz(String),
    /// `REG_EXPAND_SZ` (unexpanded).
    ExpandSz(String),
    /// `REG_LINK`.
    Link(String),
    /// `REG_MULTI_SZ`.
    MultiSz(Vec<String>),
    /// `REG_DWORD`.
    Dword(u32),
    /// `REG_DWORD_BIG_ENDIAN`.
    DwordBigEndian(u32),
    /// `REG_QWORD`.
    Qword(u64),
    /// `REG_FILETIME`, as the raw 64-bit value.
    FileTime(u64),
    /// `REG_BINARY`, the resource types, and anything that could not be decoded.
    Binary(Vec<u8>),
}

/// Bytes of a `Binary` shown in full before the hex is cut.
pub const BINARY_SHOWN: usize = 64;

impl Data {
    /// Decodes raw bytes as `kind`. Lenient: what cannot be decoded is kept as `Binary`
    /// and a diagnostic is recorded.
    pub fn from_raw(kind: ValueType, raw: &[u8]) -> Data {
        match kind {
            ValueType::NONE => {
                if raw.is_empty() {
                    Data::None
                } else {
                    Data::Binary(raw.to_vec())
                }
            }
            ValueType::SZ => Data::Sz(decode_utf16(raw)),
            ValueType::EXPAND_SZ => Data::ExpandSz(decode_utf16(raw)),
            ValueType::LINK => Data::Link(decode_utf16(raw)),
            ValueType::MULTI_SZ => Data::MultiSz(decode_multi_sz(raw)),
            ValueType::DWORD => match raw.len() {
                4 => Data::Dword(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])),
                0 => Data::None,
                n => {
                    crate::diag::info(code::VALUE_UNDECODABLE, format!("REG_DWORD of {n} bytes"));
                    if n < 4 {
                        let mut b = [0u8; 4];
                        b[..n].copy_from_slice(raw);
                        Data::Dword(u32::from_le_bytes(b))
                    } else {
                        Data::Binary(raw.to_vec())
                    }
                }
            },
            ValueType::DWORD_BIG_ENDIAN => match raw.len() {
                4 => Data::DwordBigEndian(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]])),
                0 => Data::None,
                n => {
                    crate::diag::info(code::VALUE_UNDECODABLE, format!("REG_DWORD_BIG_ENDIAN of {n} bytes"));
                    Data::Binary(raw.to_vec())
                }
            },
            ValueType::QWORD | ValueType::FILETIME => match raw.len() {
                8 => {
                    let mut b = [0u8; 8];
                    b.copy_from_slice(raw);
                    let v = u64::from_le_bytes(b);
                    if kind == ValueType::QWORD {
                        Data::Qword(v)
                    } else {
                        Data::FileTime(v)
                    }
                }
                0 => Data::None,
                n => {
                    crate::diag::info(code::VALUE_UNDECODABLE, format!("{kind} of {n} bytes"));
                    Data::Binary(raw.to_vec())
                }
            },
            ValueType::BINARY | ValueType::RESOURCE_LIST | ValueType::FULL_RESOURCE_DESCRIPTOR | ValueType::RESOURCE_REQUIREMENTS_LIST => Data::Binary(raw.to_vec()),
            other => {
                crate::diag::info(code::VALUE_TYPE_UNKNOWN, format!("type {} ({} bytes)", other.0, raw.len()));
                Data::Binary(raw.to_vec())
            }
        }
    }

    /// From a parsed value.
    pub fn from_nt(v: &RegistryValue) -> Data {
        match v {
            RegistryValue::RegNone | RegistryValue::RegUnknown => Data::None,
            RegistryValue::RegSZ(s) => Data::Sz(s.clone()),
            RegistryValue::RegExpandSZ(s) => Data::ExpandSz(s.clone()),
            RegistryValue::RegLink(s) => Data::Link(s.clone()),
            RegistryValue::RegMultiSZ(l) => Data::MultiSz(l.clone()),
            RegistryValue::RegDWord(n) => Data::Dword(*n),
            RegistryValue::RegDWordBigEndian(n) => Data::DwordBigEndian(*n),
            RegistryValue::RegQWord(n) => Data::Qword(*n),
            RegistryValue::RegFileTime => Data::None,
            RegistryValue::RegBinary(b) => Data::Binary(b.clone()),
            RegistryValue::RegResourceList(s) | RegistryValue::RegFullResourceDescriptor(s) | RegistryValue::RegResourceRequirementsList(s) => Data::Binary(s.as_bytes().to_vec()),
        }
    }

    /// The text of a string value (`Sz`, `ExpandSz`, `Link`), or the strings of a
    /// `MultiSz` joined with ` | `.
    pub fn as_str(&self) -> Option<String> {
        match self {
            Data::Sz(s) | Data::ExpandSz(s) | Data::Link(s) => Some(s.clone()),
            Data::MultiSz(l) => Some(l.join(" | ")),
            _ => None,
        }
    }

    /// The number of a `Dword`, `DwordBigEndian`, `Qword` or `FileTime`.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Data::Dword(n) | Data::DwordBigEndian(n) => Some(*n as u64),
            Data::Qword(n) | Data::FileTime(n) => Some(*n),
            _ => None,
        }
    }

    /// The bytes of a `Binary`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Data::Binary(b) => Some(b),
            _ => None,
        }
    }

    /// One line for a listing: strings as they are, numbers in decimal with hex, a
    /// FILETIME as a date, binary as hex (cut after [`BINARY_SHOWN`] bytes with its length).
    pub fn display(&self) -> String {
        match self {
            Data::None => String::new(),
            Data::Sz(s) | Data::ExpandSz(s) | Data::Link(s) => s.clone(),
            Data::MultiSz(l) => l.join(" | "),
            Data::Dword(n) | Data::DwordBigEndian(n) => format!("{n} (0x{n:08x})"),
            Data::Qword(n) => format!("{n} (0x{n:016x})"),
            Data::FileTime(ft) => match filetime_to_utc(*ft) {
                Some(t) => format!("{} ({ft})", format_utc(&t)),
                None => format!("{ft}"),
            },
            Data::Binary(b) => {
                let shown: String = b.iter().take(BINARY_SHOWN).map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ");
                if b.len() > BINARY_SHOWN {
                    format!("{shown} … ({} bytes)", b.len())
                } else {
                    shown
                }
            }
        }
    }

    /// Size of the data in bytes, as it would be stored.
    pub fn len(&self) -> usize {
        match self {
            Data::None => 0,
            Data::Sz(s) | Data::ExpandSz(s) | Data::Link(s) => (s.encode_utf16().count() + 1) * 2,
            Data::MultiSz(l) => l.iter().map(|s| (s.encode_utf16().count() + 1) * 2).sum::<usize>() + 2,
            Data::Dword(_) | Data::DwordBigEndian(_) => 4,
            Data::Qword(_) | Data::FileTime(_) => 8,
            Data::Binary(b) => b.len(),
        }
    }

    /// No data at all.
    pub fn is_empty(&self) -> bool {
        matches!(self, Data::None)
    }
}

/// UTF-16LE up to the first NUL, leniently.
pub fn decode_utf16(raw: &[u8]) -> String {
    if raw.len() % 2 == 1 {
        crate::diag::info(code::STRING_NOT_UTF16, format!("odd length {} bytes", raw.len()));
    }
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    match String::from_utf16(&units) {
        Ok(s) => s,
        Err(_) => {
            crate::diag::info(code::STRING_NOT_UTF16, format!("{} units with unpaired surrogates", units.len()));
            String::from_utf16_lossy(&units)
        }
    }
}

/// `REG_MULTI_SZ`: NUL-separated UTF-16LE strings ending with an empty one.
pub fn decode_multi_sz(raw: &[u8]) -> Vec<String> {
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut out = Vec::new();
    let mut cur: Vec<u16> = Vec::new();
    let mut terminated = false;
    let mut i = 0;
    while i < units.len() {
        let u = units[i];
        if u == 0 {
            if cur.is_empty() {
                terminated = true;
                break;
            }
            out.push(String::from_utf16_lossy(&cur));
            cur.clear();
        } else {
            cur.push(u);
        }
        i += 1;
    }
    if !cur.is_empty() {
        out.push(String::from_utf16_lossy(&cur));
        terminated = false;
    }
    if !terminated && !raw.is_empty() {
        crate::diag::info(code::MULTI_SZ_UNTERMINATED, format!("{} bytes, {} string(s)", raw.len(), out.len()));
    }
    out
}

/// A registry value: name, type and decoded data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// The name; `(Default)` for the unnamed value.
    pub name: String,
    /// The declared type.
    pub kind: ValueType,
    /// Declared size of the data in bytes.
    pub size: u32,
    /// The data.
    pub data: Data,
    /// Data of 4 bytes or less stored inside the value cell itself.
    pub resident: bool,
}

/// The name of the unnamed value.
pub const DEFAULT_VALUE_NAME: &str = "(Default)";

impl Value {
    /// From a parsed value.
    pub fn from_nt(v: &KeyValue) -> Value {
        let kind = v.data_type().map(|dt| ValueType::from_nt_name(&dt.to_string())).unwrap_or_else(|| {
            crate::diag::info(code::VALUE_TYPE_UNKNOWN, format!("value {:?}", v.name()));
            ValueType(u32::MAX)
        });
        let size = v.data_size();
        let resident = v.is_resident();
        // Data of 4 bytes or less lives in the offset field; the parser hands it back as a
        // DWORD whatever the type, so a short string or binary is rebuilt from those bytes.
        let data = match (resident, v.value()) {
            (true, RegistryValue::RegDWord(n)) if kind != ValueType::DWORD => {
                let raw = n.to_le_bytes();
                Data::from_raw(kind, &raw[..(size as usize).min(4)])
            }
            (_, other) => Data::from_nt(other),
        };
        Value { name: v.name().to_string(), kind, size, data, resident }
    }

    /// The unnamed value.
    pub fn is_default(&self) -> bool {
        self.name.is_empty() || self.name == DEFAULT_VALUE_NAME
    }
}

/// Windows FILETIME (100 ns since 1601-01-01) to UTC. `None` for zero or out of range.
pub fn filetime_to_utc(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None;
    }
    const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
    let secs = (ft / 10_000_000) as i64 - EPOCH_DIFF_SECS;
    let nanos = ((ft % 10_000_000) * 100) as u32;
    match Utc.timestamp_opt(secs, nanos) {
        chrono::LocalResult::Single(t) if t.year_ok() => Some(t),
        _ => {
            crate::diag::info(code::FILETIME_OUT_OF_RANGE, format!("{ft}"));
            None
        }
    }
}

trait YearOk {
    fn year_ok(&self) -> bool;
}

impl YearOk for DateTime<Utc> {
    fn year_ok(&self) -> bool {
        use chrono::Datelike;
        (1601..=9999).contains(&self.year())
    }
}

/// The family's timestamp text: `YYYY-MM-DDTHH:MM:SS.ffffffZ`, fixed width, sorts as text.
pub fn format_utc(t: &DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

/// A FILETIME as the family's text, or empty.
pub fn filetime_text(ft: u64) -> String {
    filetime_to_utc(ft).map(|t| format_utc(&t)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        let mut out: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        out.extend_from_slice(&[0, 0]);
        out
    }

    #[test]
    fn parser_type_names_map() {
        assert_eq!(ValueType::from_nt_name("RegSZ"), ValueType::SZ);
        assert_eq!(ValueType::from_nt_name("RegExpandSZ"), ValueType::EXPAND_SZ);
        assert_eq!(ValueType::from_nt_name("RegBinary"), ValueType::BINARY);
        assert_eq!(ValueType::from_nt_name("RegDWord"), ValueType::DWORD);
        assert_eq!(ValueType::from_nt_name("RegDWordBigEndian"), ValueType::DWORD_BIG_ENDIAN);
        assert_eq!(ValueType::from_nt_name("RegLink"), ValueType::LINK);
        assert_eq!(ValueType::from_nt_name("RegMultiSZ"), ValueType::MULTI_SZ);
        assert_eq!(ValueType::from_nt_name("RegResourceList"), ValueType::RESOURCE_LIST);
        assert_eq!(ValueType::from_nt_name("RegFullResourceDescriptor"), ValueType::FULL_RESOURCE_DESCRIPTOR);
        assert_eq!(ValueType::from_nt_name("RegResourceRequirementsList"), ValueType::RESOURCE_REQUIREMENTS_LIST);
        assert_eq!(ValueType::from_nt_name("RegQWord"), ValueType::QWORD);
        assert_eq!(ValueType::from_nt_name("RegFileTime"), ValueType::FILETIME);
        assert_eq!(ValueType::from_nt_name("RegNone"), ValueType::NONE);
        assert_eq!(ValueType::from_nt_name("Whatever"), ValueType(u32::MAX));
    }

    #[test]
    fn type_names() {
        assert_eq!(ValueType::SZ.name(), "REG_SZ");
        assert_eq!(ValueType::QWORD.to_string(), "REG_QWORD");
        assert_eq!(ValueType(99).name(), "REG_99");
        assert!(ValueType::FILETIME.is_known());
        assert!(!ValueType(12).is_known());
        assert!(ValueType::LINK.is_string());
        assert!(!ValueType::BINARY.is_string());
    }

    #[test]
    fn decode_strings() {
        crate::diag::clear();
        assert_eq!(Data::from_raw(ValueType::SZ, &utf16("hello")), Data::Sz("hello".into()));
        assert_eq!(Data::from_raw(ValueType::EXPAND_SZ, &utf16("%SystemRoot%\\x.exe")), Data::ExpandSz("%SystemRoot%\\x.exe".into()));
        assert_eq!(Data::from_raw(ValueType::LINK, &utf16("\\Registry\\Machine")), Data::Link("\\Registry\\Machine".into()));
        // Text after the first NUL is not part of the string.
        let mut tail = utf16("ab");
        tail.extend_from_slice(&utf16("cd"));
        assert_eq!(Data::from_raw(ValueType::SZ, &tail), Data::Sz("ab".into()));
        assert!(crate::diag::snapshot().is_empty(), "clean decodes record nothing");
        // Odd length and lone surrogates are lenient.
        assert_eq!(Data::from_raw(ValueType::SZ, &[0x61, 0x00, 0x62]), Data::Sz("a".into()));
        assert!(crate::diag::has(code::STRING_NOT_UTF16));
        crate::diag::clear();
        assert_eq!(decode_utf16(&[0x00, 0xd8, 0x61, 0x00]), "\u{fffd}a");
        assert!(crate::diag::has(code::STRING_NOT_UTF16));
        crate::diag::clear();
    }

    #[test]
    fn decode_multi() {
        crate::diag::clear();
        let mut raw = Vec::new();
        raw.extend_from_slice(&utf16("one"));
        raw.extend_from_slice(&utf16("two"));
        raw.extend_from_slice(&[0, 0]);
        assert_eq!(Data::from_raw(ValueType::MULTI_SZ, &raw), Data::MultiSz(vec!["one".into(), "two".into()]));
        assert!(crate::diag::snapshot().is_empty());
        // Missing the final double NUL.
        let cut = &raw[..raw.len() - 2];
        assert_eq!(decode_multi_sz(cut), vec!["one".to_string(), "two".to_string()]);
        assert!(crate::diag::has(code::MULTI_SZ_UNTERMINATED));
        crate::diag::clear();
        assert_eq!(decode_multi_sz(&utf16("solo")[..8]), vec!["solo".to_string()]);
        assert!(crate::diag::has(code::MULTI_SZ_UNTERMINATED));
        crate::diag::clear();
        assert_eq!(decode_multi_sz(&[]), Vec::<String>::new());
        assert_eq!(decode_multi_sz(&[0, 0]), Vec::<String>::new());
        assert!(crate::diag::snapshot().is_empty());
    }

    #[test]
    fn decode_numbers() {
        crate::diag::clear();
        assert_eq!(Data::from_raw(ValueType::DWORD, &0x1234u32.to_le_bytes()), Data::Dword(0x1234));
        assert_eq!(Data::from_raw(ValueType::DWORD_BIG_ENDIAN, &[0, 0, 0x12, 0x34]), Data::DwordBigEndian(0x1234));
        assert_eq!(Data::from_raw(ValueType::QWORD, &7u64.to_le_bytes()), Data::Qword(7));
        assert_eq!(Data::from_raw(ValueType::FILETIME, &133_500_000_000_000_000u64.to_le_bytes()), Data::FileTime(133_500_000_000_000_000));
        assert_eq!(Data::from_raw(ValueType::DWORD, &[]), Data::None);
        assert!(crate::diag::snapshot().is_empty());
        assert_eq!(Data::from_raw(ValueType::DWORD, &[1, 2]), Data::Dword(0x0201), "a short DWORD is padded");
        assert!(crate::diag::has(code::VALUE_UNDECODABLE));
        crate::diag::clear();
        assert_eq!(Data::from_raw(ValueType::DWORD, &[1, 2, 3, 4, 5]), Data::Binary(vec![1, 2, 3, 4, 5]));
        assert_eq!(Data::from_raw(ValueType::QWORD, &[1, 2, 3]), Data::Binary(vec![1, 2, 3]));
        assert_eq!(Data::from_raw(ValueType::DWORD_BIG_ENDIAN, &[1]), Data::Binary(vec![1]));
        assert_eq!(crate::diag::count(code::VALUE_UNDECODABLE), 3);
        crate::diag::clear();
    }

    #[test]
    fn decode_binary_none_and_unknown() {
        crate::diag::clear();
        assert_eq!(Data::from_raw(ValueType::BINARY, &[9, 8]), Data::Binary(vec![9, 8]));
        assert_eq!(Data::from_raw(ValueType::RESOURCE_LIST, &[1]), Data::Binary(vec![1]));
        assert_eq!(Data::from_raw(ValueType::NONE, &[]), Data::None);
        assert_eq!(Data::from_raw(ValueType::NONE, &[5]), Data::Binary(vec![5]));
        assert!(crate::diag::snapshot().is_empty());
        assert_eq!(Data::from_raw(ValueType(0x1234), &[1]), Data::Binary(vec![1]));
        assert!(crate::diag::has(code::VALUE_TYPE_UNKNOWN));
        crate::diag::clear();
    }

    #[test]
    fn accessors_and_display() {
        assert_eq!(Data::Sz("a".into()).as_str().as_deref(), Some("a"));
        assert_eq!(Data::MultiSz(vec!["a".into(), "b".into()]).as_str().as_deref(), Some("a | b"));
        assert_eq!(Data::Dword(3).as_str(), None);
        assert_eq!(Data::Dword(3).as_u64(), Some(3));
        assert_eq!(Data::Qword(u64::MAX).as_u64(), Some(u64::MAX));
        assert_eq!(Data::Sz("x".into()).as_u64(), None);
        assert_eq!(Data::Binary(vec![1]).as_bytes(), Some(&[1u8][..]));
        assert_eq!(Data::None.as_bytes(), None);
        assert_eq!(Data::None.display(), "");
        assert!(Data::None.is_empty());
        assert_eq!(Data::Dword(255).display(), "255 (0x000000ff)");
        assert_eq!(Data::Qword(1).display(), "1 (0x0000000000000001)");
        assert_eq!(Data::Binary(vec![0xde, 0xad]).display(), "de ad");
        let big = Data::Binary(vec![0u8; 100]);
        let shown = big.display();
        assert!(shown.ends_with("… (100 bytes)"), "{shown}");
        assert_eq!(shown.matches("00").count(), BINARY_SHOWN + 1, "64 bytes plus the '100' is not hex; {shown}");
        assert_eq!(Data::FileTime(133_500_000_000_000_000).display(), "2024-01-17T21:20:00.000000Z (133500000000000000)");
        assert_eq!(Data::FileTime(0).display(), "0");
        assert_eq!(Data::Sz("ab".into()).len(), 6);
        assert_eq!(Data::MultiSz(vec!["a".into(), "b".into()]).len(), 10);
        assert_eq!(Data::Dword(0).len(), 4);
        assert_eq!(Data::Qword(0).len(), 8);
        assert_eq!(Data::Binary(vec![1, 2, 3]).len(), 3);
        assert_eq!(Data::None.len(), 0);
    }

    #[test]
    fn filetimes() {
        crate::diag::clear();
        assert_eq!(filetime_to_utc(0), None);
        assert!(crate::diag::snapshot().is_empty(), "zero is silent");
        let t = filetime_to_utc(133_500_000_000_000_000).unwrap();
        assert_eq!(format_utc(&t), "2024-01-17T21:20:00.000000Z");
        assert_eq!(filetime_text(133_500_000_000_000_000), "2024-01-17T21:20:00.000000Z");
        assert_eq!(filetime_text(116_444_736_000_000_000), "1970-01-01T00:00:00.000000Z");
        assert_eq!(filetime_text(116_444_736_000_000_001), "1970-01-01T00:00:00.000000Z", "100 ns are below the microsecond");
        assert_eq!(filetime_text(116_444_736_000_000_010), "1970-01-01T00:00:00.000001Z");
        assert_eq!(filetime_text(u64::MAX), "");
        assert!(crate::diag::has(code::FILETIME_OUT_OF_RANGE));
        crate::diag::clear();
        assert_eq!(filetime_text(1), "1601-01-01T00:00:00.000000Z");
    }

    #[test]
    fn value_default_name() {
        let v = Value { name: DEFAULT_VALUE_NAME.into(), kind: ValueType::SZ, size: 0, data: Data::None, resident: false };
        assert!(v.is_default());
        let v = Value { name: "Path".into(), ..v };
        assert!(!v.is_default());
    }
}
