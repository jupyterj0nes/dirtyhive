//! Which well-known hive a file is, from its name and from its base block.
//!
//! A hive is classified by two independent sources: the file name (`SYSTEM`,
//! `bob_NTUSER.DAT`, `C_Windows_System32_config_SOFTWARE`, `SOFTWARE.hve`) and the tail of
//! the original path stored in the base block (`emRoot\System32\Config\SOFTWARE`). The
//! header wins when both speak; when neither does the hive is [`HiveKind::Unknown`] and
//! still opened, so a renamed hive never loses its contents.

use std::fmt;

/// The well-known hives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HiveKind {
    /// `SYSTEM`: services, drivers, control sets, mounted devices.
    System,
    /// `SOFTWARE`: installed programs, machine-wide settings, Run keys.
    Software,
    /// `SAM`: local accounts.
    Sam,
    /// `SECURITY`: LSA policy and secrets.
    Security,
    /// `DEFAULT`: the default user profile.
    Default,
    /// `NTUSER.DAT`: a user's profile.
    NtUser,
    /// `UsrClass.dat`: a user's classes and shellbags.
    UsrClass,
    /// `Amcache.hve`: program inventory.
    Amcache,
    /// `BCD`: boot configuration.
    Bcd,
    /// `COMPONENTS`: servicing stack.
    Components,
    /// `DRIVERS`: driver database.
    Drivers,
    /// `BBI`: background broker infrastructure.
    Bbi,
    /// `ELAM`: early-launch anti-malware.
    Elam,
    /// `userdiff`: profile migration.
    UserDiff,
    /// None of the above (a renamed or exotic hive).
    Unknown,
}

impl HiveKind {
    /// Every kind, `Unknown` last.
    pub const ALL: [HiveKind; 15] = [
        HiveKind::System,
        HiveKind::Software,
        HiveKind::Sam,
        HiveKind::Security,
        HiveKind::Default,
        HiveKind::NtUser,
        HiveKind::UsrClass,
        HiveKind::Amcache,
        HiveKind::Bcd,
        HiveKind::Components,
        HiveKind::Drivers,
        HiveKind::Bbi,
        HiveKind::Elam,
        HiveKind::UserDiff,
        HiveKind::Unknown,
    ];

    /// Canonical on-disk file name, upper case; `None` for `Unknown`.
    pub fn canonical_file_name(&self) -> Option<&'static str> {
        match self {
            HiveKind::System => Some("SYSTEM"),
            HiveKind::Software => Some("SOFTWARE"),
            HiveKind::Sam => Some("SAM"),
            HiveKind::Security => Some("SECURITY"),
            HiveKind::Default => Some("DEFAULT"),
            HiveKind::NtUser => Some("NTUSER.DAT"),
            HiveKind::UsrClass => Some("USRCLASS.DAT"),
            HiveKind::Amcache => Some("AMCACHE.HVE"),
            HiveKind::Bcd => Some("BCD"),
            HiveKind::Components => Some("COMPONENTS"),
            HiveKind::Drivers => Some("DRIVERS"),
            HiveKind::Bbi => Some("BBI"),
            HiveKind::Elam => Some("ELAM"),
            HiveKind::UserDiff => Some("USERDIFF"),
            HiveKind::Unknown => None,
        }
    }

    /// The canonical name, or `UNKNOWN`.
    pub fn label(&self) -> &'static str {
        self.canonical_file_name().unwrap_or("UNKNOWN")
    }

    /// Where the hive is mounted in a live registry (`HKLM\SYSTEM`, `HKU\<sid>`, …).
    pub fn mount_point(&self) -> &'static str {
        match self {
            HiveKind::System => r"HKLM\SYSTEM",
            HiveKind::Software => r"HKLM\SOFTWARE",
            HiveKind::Sam => r"HKLM\SAM",
            HiveKind::Security => r"HKLM\SECURITY",
            HiveKind::Default => r"HKU\.DEFAULT",
            HiveKind::NtUser => r"HKCU",
            HiveKind::UsrClass => r"HKCU\Software\Classes",
            HiveKind::Amcache => r"Amcache",
            HiveKind::Bcd => r"HKLM\BCD00000000",
            HiveKind::Components => r"HKLM\COMPONENTS",
            HiveKind::Drivers => r"HKLM\DRIVERS",
            HiveKind::Bbi => r"HKLM\BBI",
            HiveKind::Elam => r"HKLM\ELAM",
            HiveKind::UserDiff => r"userdiff",
            HiveKind::Unknown => "",
        }
    }

    /// `NTUSER.DAT` and `DEFAULT` share the HKCU layout.
    pub fn is_user_profile(&self) -> bool {
        matches!(self, HiveKind::NtUser | HiveKind::Default)
    }

    /// A hive that belongs to one user (profile or classes).
    pub fn is_per_user(&self) -> bool {
        matches!(self, HiveKind::NtUser | HiveKind::UsrClass)
    }

    /// Tokens tried against file names, longest first so `NTUSER.DAT` wins over `DAT`.
    const NAME_TOKENS: [(&'static str, HiveKind); 14] = [
        ("USRCLASS.DAT", HiveKind::UsrClass),
        ("AMCACHE.HVE", HiveKind::Amcache),
        ("NTUSER.DAT", HiveKind::NtUser),
        ("COMPONENTS", HiveKind::Components),
        ("SECURITY", HiveKind::Security),
        ("SOFTWARE", HiveKind::Software),
        ("USERDIFF", HiveKind::UserDiff),
        ("DEFAULT", HiveKind::Default),
        ("DRIVERS", HiveKind::Drivers),
        ("SYSTEM", HiveKind::System),
        ("ELAM", HiveKind::Elam),
        ("SAM", HiveKind::Sam),
        ("BCD", HiveKind::Bcd),
        ("BBI", HiveKind::Bbi),
    ];

    /// Suffixes collectors append to copied hives.
    const EXTRA_SUFFIXES: [&'static str; 9] = [".HVE", ".HIV", ".BAK", ".ORIG", ".COPY", ".BIN", ".REGF", ".RAW", ".OLD"];

    fn matches_token(name: &str, token: &str) -> bool {
        name == token || name.ends_with(&format!("_{token}")) || name.ends_with(&format!("-{token}")) || name.ends_with(&format!(".{token}"))
    }

    fn strip_extra_suffixes(name: &str) -> String {
        let mut n = name.to_string();
        loop {
            let before = n.clone();
            for suf in Self::EXTRA_SUFFIXES {
                if n.len() > suf.len() && n.ends_with(suf) {
                    n.truncate(n.len() - suf.len());
                }
            }
            if n == before {
                return n;
            }
        }
    }

    /// The kind a file name alone suggests (case-insensitive).
    ///
    /// Accepts canonical names, collector prefixes (`HOST_SYSTEM`, `bob-NTUSER.DAT`,
    /// `C_Windows_System32_config_SOFTWARE`), copy suffixes (`SOFTWARE.hve`) and the
    /// mandatory-profile `NTUSER.MAN`.
    pub fn from_file_name(name: &str) -> HiveKind {
        let n = name.trim().to_uppercase();
        if n.is_empty() || is_companion_file(&n) {
            return HiveKind::Unknown;
        }
        for (tok, kind) in Self::NAME_TOKENS {
            if Self::matches_token(&n, tok) {
                return kind;
            }
        }
        let stripped = Self::strip_extra_suffixes(&n);
        if stripped != n {
            for (tok, kind) in Self::NAME_TOKENS {
                if Self::matches_token(&stripped, tok) {
                    return kind;
                }
            }
        }
        let last = stripped.rsplit(['_', '-']).next().unwrap_or(&stripped);
        if last.starts_with("NTUSER.") {
            return HiveKind::NtUser;
        }
        if last.starts_with("USRCLASS.") {
            return HiveKind::UsrClass;
        }
        HiveKind::Unknown
    }

    /// The kind the path embedded in the base block says (`emRoot\System32\Config\SOFTWARE`).
    pub fn from_embedded_name(embedded: &str) -> HiveKind {
        let trimmed = embedded.trim_matches(char::from(0)).trim();
        if trimmed.is_empty() {
            return HiveKind::Unknown;
        }
        let last = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed).to_uppercase();
        match last.as_str() {
            "SYSTEM" => HiveKind::System,
            "SOFTWARE" => HiveKind::Software,
            "SAM" => HiveKind::Sam,
            "SECURITY" => HiveKind::Security,
            "DEFAULT" => HiveKind::Default,
            "NTUSER.DAT" | "NTUSER.MAN" => HiveKind::NtUser,
            "USRCLASS.DAT" => HiveKind::UsrClass,
            "AMCACHE.HVE" => HiveKind::Amcache,
            "BCD" => HiveKind::Bcd,
            "COMPONENTS" => HiveKind::Components,
            "DRIVERS" => HiveKind::Drivers,
            "BBI" => HiveKind::Bbi,
            "ELAM" => HiveKind::Elam,
            "USERDIFF" => HiveKind::UserDiff,
            _ => HiveKind::Unknown,
        }
    }

    /// Header first, then the name; a disagreement is reported by the caller.
    pub fn resolve(header_kind: HiveKind, name_kind: HiveKind) -> HiveKind {
        match (header_kind, name_kind) {
            (HiveKind::Unknown, n) => n,
            (h, _) => h,
        }
    }
}

impl fmt::Display for HiveKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Registry companion files that must never be parsed as primary hives.
pub fn is_companion_file(name: &str) -> bool {
    let n = name.trim().to_uppercase();
    n.ends_with(".LOG")
        || n.ends_with(".LOG1")
        || n.ends_with(".LOG2")
        || n.ends_with(".BLF")
        || n.ends_with(".REGTRANS-MS")
        || n.ends_with(".TMP")
        || n.ends_with(".SAV")
        || n.ends_with(".TM")
        || n.contains(".TMCONTAINER")
        || n.contains(".TM.BLF")
}

/// For a companion file (`SYSTEM.LOG1`, `NTUSER.DAT{guid}.TM.blf`), the hive it belongs to.
pub fn companion_base_kind(name: &str) -> HiveKind {
    let n = name.trim().to_uppercase();
    let base = match n.find('{') {
        Some(pos) => n[..pos].to_string(),
        None => {
            let mut b = n.clone();
            for suf in [".LOG1", ".LOG2", ".LOG", ".BLF", ".REGTRANS-MS", ".TMP", ".SAV", ".TM"] {
                if b.ends_with(suf) {
                    b.truncate(b.len() - suf.len());
                    break;
                }
            }
            b
        }
    };
    HiveKind::from_file_name(&base)
}

/// Extensions that may hide a hive under an unusual name.
pub fn has_hive_like_extension(name: &str) -> bool {
    let n = name.to_uppercase();
    [".HVE", ".DAT", ".HIV", ".BAK", ".BIN", ".REGF", ".RAW", ".OLD", ".MAN"].iter().any(|s| n.ends_with(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_names() {
        assert_eq!(HiveKind::from_file_name("SYSTEM"), HiveKind::System);
        assert_eq!(HiveKind::from_file_name("software"), HiveKind::Software);
        assert_eq!(HiveKind::from_file_name("NtUser.dat"), HiveKind::NtUser);
        assert_eq!(HiveKind::from_file_name("SAM"), HiveKind::Sam);
        assert_eq!(HiveKind::from_file_name("SECURITY"), HiveKind::Security);
        assert_eq!(HiveKind::from_file_name("DEFAULT"), HiveKind::Default);
        assert_eq!(HiveKind::from_file_name("UsrClass.dat"), HiveKind::UsrClass);
        assert_eq!(HiveKind::from_file_name("Amcache.hve"), HiveKind::Amcache);
        assert_eq!(HiveKind::from_file_name("BCD"), HiveKind::Bcd);
        assert_eq!(HiveKind::from_file_name("COMPONENTS"), HiveKind::Components);
        assert_eq!(HiveKind::from_file_name("DRIVERS"), HiveKind::Drivers);
        assert_eq!(HiveKind::from_file_name("BBI"), HiveKind::Bbi);
        assert_eq!(HiveKind::from_file_name("ELAM"), HiveKind::Elam);
        assert_eq!(HiveKind::from_file_name("userdiff"), HiveKind::UserDiff);
    }

    #[test]
    fn collector_layouts() {
        assert_eq!(HiveKind::from_file_name("bob_NTUSER.DAT"), HiveKind::NtUser);
        assert_eq!(HiveKind::from_file_name("Administrator_ntuser.dat"), HiveKind::NtUser);
        assert_eq!(HiveKind::from_file_name("HOST01-SYSTEM"), HiveKind::System);
        assert_eq!(HiveKind::from_file_name("alice-NTUSER.DAT"), HiveKind::NtUser);
        assert_eq!(HiveKind::from_file_name("C_Windows_System32_config_SOFTWARE"), HiveKind::Software);
        assert_eq!(HiveKind::from_file_name("C_Users_bob_NTUSER.DAT"), HiveKind::NtUser);
        assert_eq!(HiveKind::from_file_name("host.SYSTEM"), HiveKind::System);
        assert_eq!(HiveKind::from_file_name("  SYSTEM  "), HiveKind::System);
    }

    #[test]
    fn copy_suffixes_and_mandatory_profiles() {
        assert_eq!(HiveKind::from_file_name("SOFTWARE.hve"), HiveKind::Software);
        assert_eq!(HiveKind::from_file_name("SYSTEM.bak"), HiveKind::System);
        assert_eq!(HiveKind::from_file_name("system.hiv"), HiveKind::System);
        assert_eq!(HiveKind::from_file_name("SOFTWARE.hve.bak"), HiveKind::Software);
        assert_eq!(HiveKind::from_file_name("NTUSER.MAN"), HiveKind::NtUser);
        assert_eq!(HiveKind::from_file_name("bob_NTUSER.MAN"), HiveKind::NtUser);
        assert_eq!(HiveKind::from_file_name("UsrClass.dat.bak"), HiveKind::UsrClass);
    }

    #[test]
    fn unknown_names() {
        for n in ["evidence.bin", "hive", "", "   ", "SYSTEM.LOG1", "SOFTWARE.LOG2", "NTUSER.DAT{016888bd}.TM.blf", "MYSYSTEMNOTES.TXT", "samba.conf", "softwarelist.csv"] {
            assert_eq!(HiveKind::from_file_name(n), HiveKind::Unknown, "{n:?}");
        }
    }

    #[test]
    fn embedded_names() {
        assert_eq!(HiveKind::from_embedded_name(r"emRoot\System32\Config\SOFTWARE"), HiveKind::Software);
        assert_eq!(HiveKind::from_embedded_name(r"emRoot\System32\Config\SYSTEM"), HiveKind::System);
        assert_eq!(HiveKind::from_embedded_name(r"\??\C:\Users\bob\ntuser.dat"), HiveKind::NtUser);
        assert_eq!(HiveKind::from_embedded_name(r"ers\averylongusername\ntuser.dat"), HiveKind::NtUser);
        assert_eq!(HiveKind::from_embedded_name(r"Local\Microsoft\Windows\UsrClass.dat"), HiveKind::UsrClass);
        assert_eq!(HiveKind::from_embedded_name(r"emRoot\System32\Config\DEFAULT"), HiveKind::Default);
        assert_eq!(HiveKind::from_embedded_name(r"temRoot\System32\Config\SAM"), HiveKind::Sam);
        assert_eq!(HiveKind::from_embedded_name(r"emRoot\System32\Config\SECURITY"), HiveKind::Security);
        assert_eq!(HiveKind::from_embedded_name(r"AppCompat\Programs\Amcache.hve"), HiveKind::Amcache);
        assert_eq!(HiveKind::from_embedded_name(r"\Device\HarddiskVolume1\Boot\BCD"), HiveKind::Bcd);
        assert_eq!(HiveKind::from_embedded_name("Config/SOFTWARE\0\0"), HiveKind::Software);
        assert_eq!(HiveKind::from_embedded_name(r"config\software"), HiveKind::Software);
        assert_eq!(HiveKind::from_embedded_name(r"System32\config\BBI"), HiveKind::Bbi);
        assert_eq!(HiveKind::from_embedded_name(r"ers\user\Desktop\1\NewDirtyHive"), HiveKind::Unknown);
        assert_eq!(HiveKind::from_embedded_name(""), HiveKind::Unknown);
        assert_eq!(HiveKind::from_embedded_name("\0\0\0"), HiveKind::Unknown);
    }

    #[test]
    fn properties_and_round_trips() {
        assert!(HiveKind::NtUser.is_user_profile());
        assert!(HiveKind::Default.is_user_profile());
        assert!(!HiveKind::UsrClass.is_user_profile());
        assert!(HiveKind::UsrClass.is_per_user());
        assert!(!HiveKind::Software.is_per_user());
        assert_eq!(HiveKind::Unknown.canonical_file_name(), None);
        assert_eq!(HiveKind::Unknown.label(), "UNKNOWN");
        assert_eq!(HiveKind::System.to_string(), "SYSTEM");
        assert_eq!(HiveKind::System.mount_point(), r"HKLM\SYSTEM");
        assert_eq!(HiveKind::Unknown.mount_point(), "");
        assert_eq!(HiveKind::ALL.len(), 15);
        for k in HiveKind::ALL {
            if let Some(name) = k.canonical_file_name() {
                assert_eq!(HiveKind::from_file_name(name), k);
                assert_eq!(HiveKind::from_file_name(&format!("HOST_{name}")), k);
                assert_eq!(HiveKind::from_file_name(&name.to_lowercase()), k);
                assert_eq!(HiveKind::from_embedded_name(&format!(r"x\y\{name}")), k, "{k}");
            }
        }
        assert_eq!(HiveKind::resolve(HiveKind::Unknown, HiveKind::System), HiveKind::System);
        assert_eq!(HiveKind::resolve(HiveKind::Software, HiveKind::System), HiveKind::Software);
        assert_eq!(HiveKind::resolve(HiveKind::Unknown, HiveKind::Unknown), HiveKind::Unknown);
    }

    #[test]
    fn companions() {
        for n in ["SYSTEM.LOG1", "software.log2", "SYSTEM.LOG", "NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf", "NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms", "UsrClass.dat{guid}.TM", "SOFTWARE.TMP", "SYSTEM.sav"] {
            assert!(is_companion_file(n), "{n}");
        }
        for n in ["SYSTEM", "NTUSER.DAT", "SOFTWARE.hve", "catalog.log.txt"] {
            assert!(!is_companion_file(n), "{n}");
        }
        assert_eq!(companion_base_kind("SYSTEM.LOG1"), HiveKind::System);
        assert_eq!(companion_base_kind("bob_NTUSER.DAT.LOG2"), HiveKind::NtUser);
        assert_eq!(companion_base_kind("NTUSER.DAT{016888bd}.TM.blf"), HiveKind::NtUser);
        assert_eq!(companion_base_kind("random.LOG1"), HiveKind::Unknown);
        assert!(has_hive_like_extension("blob.hve"));
        assert!(has_hive_like_extension("x.DAT"));
        assert!(!has_hive_like_extension("x.txt"));
    }
}
