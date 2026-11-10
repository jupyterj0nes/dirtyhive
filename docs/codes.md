# Diagnostic codes

Every code `dirtyhive` can record or return, by number. Generated from the source: `DIRTYHIVE_WRITE_DOCS=1 cargo test --release codes_doc`.

| Code | Meaning |
|------|---------|
| `DH001_OPEN_FAILED` | the hive file could not be opened or read (missing, locked, permissions); nothing of it is available |
| `DH002_EMPTY_FILE` | the hive file is zero bytes: the collector copied a locked file and got nothing; look for a copy in a shadow copy or in the logs |
| `DH003_SIGNATURE_INVALID` | the file does not start with 'regf': it is not a registry hive (or the first sector was overwritten) |
| `DH004_HEADER_TRUNCATED` | the file is shorter than a base block (4096 bytes for a primary, 512 for a log); it was cut while copied |
| `DH005_CHECKSUM_INVALID` | the base block checksum does not match its bytes: the first sector was damaged; the hive is opened by its root cell offset and the logs cannot be replayed |
| `DH006_NOT_PRIMARY` | the file is a transaction log (file type 1, 2 or 6), not a primary hive; give the primary and the logs are found from it |
| `DH007_UNSUPPORTED_VERSION` | the hive format version is not 1.3 to 1.6; the parser does not know it (Windows NT 3.x, or garbage in the header) |
| `DH008_UNEXPECTED_FILE_TYPE` | the base block carries a file type that is neither primary nor log; the file is damaged or not a hive |
| `DH009_KIND_UNRESOLVED` | neither the file name nor the embedded path says which hive this is; it is opened as Unknown and every path is tried against it |
| `DH010_NAME_HEADER_MISMATCH` | the file name says one hive and the embedded path another; the header wins (collectors rename, Windows does not) |
| `DH011_PARSE_FAILED` | nt_hive2 could not parse the hive (root cell or bin structure damaged); the deleted-cell scan may still read it |
| `DH012_PARSE_PANIC` | nt_hive2 panicked while parsing the hive; reported instead of crashing, the hive is skipped |
| `DH013_OPENED_WITHOUT_BASE_BLOCK` | the hive was opened by its root cell offset because its base block checksum is wrong; keys and values are read, sequence numbers are not trusted |
| `DH014_IO_ERROR` | an input/output error while reading the hive; the device or the file system failed mid-read |
| `DH015_SEQUENCE_TOO_FAR` | the primary sequence is more than one ahead of the secondary: several writes were lost; the logs cannot bring the hive to a consistent state and it is read as it is |
| `DH016_DIRTY_KEPT` | the hive is dirty and stays so: no usable log; its last writes may be missing |
| `DH017_RECOVERED` | the hive was dirty and its transaction logs were applied: it now holds the writes the file had not received |
| `DH018_OPENED` | the hive was opened: kind, version, sequence numbers, dirty or clean |
| `DH019_ROOT_READ_FAILED` | the root key could not be read after parsing; the hive is unusable through the parser |
| `DH020_BYTES_WITHOUT_PATH` | a hive given as bytes has no file, so logs can only be given explicitly (LogPolicy::Only); Auto found nothing |
| `DH021_SAVE_FAILED` | the rebuilt hive could not be written to the path asked for |
| `DH022_SAVED` | the rebuilt hive (logs applied) was written to disk |
| `DH023_NOT_DIRTY_LOGS_IGNORED` | the hive is clean, so the transaction logs given or found were not applied (Windows ignores them too) |
| `DH100_LOG_NOT_FOUND` | the hive is dirty and no .LOG1/.LOG2 was found next to it or under the search root; the hive is read in its on-disk state and the last writes may be missing. Collect the logs with the hive |
| `DH101_LOG_OPEN_FAILED` | a transaction log was located but could not be read (permissions, a vanished file); the hive is read without it |
| `DH102_LOG_SIGNATURE_INVALID` | a file named like a transaction log does not start with 'regf': it is not a log (zero-filled, garbage, another format) and is ignored |
| `DH103_LOG_LEGACY_FORMAT` | the log is in the old format (file type 1 or 2, a DIRT dirty vector: Windows XP to 8.0); it is replayed through the old-format path when its timestamp matches the hive |
| `DH104_LOG_TRUNCATED` | a log entry claims more bytes than the file has: the log was cut while being copied; the entries before the cut are still used |
| `DH105_LOG_ENTRY_INVALID` | an HvLE entry is structurally wrong (size, flags, page count, page reference out of bounds); the log is cut before it and the valid prefix is used |
| `DH106_LOG_NO_ENTRIES` | the log has a valid base block but not one usable HvLE entry; nothing to replay from it |
| `DH107_LOG_SEQUENCE_JUMP` | the entry sequence numbers inside a log are not consecutive; the entries after the jump may not apply |
| `DH108_LOG_STALE` | every entry of the log is older than the hive's secondary sequence: it was already flushed into the hive; nothing to apply (normal for the other log of the pair) |
| `DH109_LOG_GAP` | no entry of the log carries the sequence its own base block starts at (or the base block is older than the hive): the log cannot start a recovery, by the format's rule |
| `DH110_LOG_FOREIGN` | the embedded hive name in the log's base block is not the hive's: the log belongs to another hive (another user's NTUSER.DAT) and is rejected |
| `DH111_LOG_AMBIGUOUS` | two candidates for the same slot scored equally; the first by path was taken, check the other one |
| `DH112_LOG_REMOTE_MATCH` | the log was found away from its hive (another folder of the evidence); applied after its header was verified against the hive |
| `DH113_LOG_PARTIAL` | only a prefix of the log's entries could be used; the tail was damaged or truncated and cut off |
| `DH114_LOG_CHECKSUM_INVALID` | the log's base block checksum does not match; the entries are still inspected because Windows does not check it either |
| `DH115_LOG_IS_PRIMARY` | a file named like a log is a primary hive (file type 0): a copy of the hive itself, not a log; ignored |
| `DH116_LOG_UNKNOWN_FILE_TYPE` | the log's base block carries a file type that is neither primary nor a known log format; ignored |
| `DH117_LOG_APPLY_FAILED` | the replay engine could not apply the logs (no applicable entry, nothing usable); the hive is read in its on-disk state |
| `DH118_LOG_REPLAY_FAILED` | the replay failed after the logs were accepted; the hive was reopened in its on-disk state |
| `DH119_LOG_OLD_FORMAT_SKIPPED` | an old-format log was not applied: its sequence numbers are torn or its timestamp is not the hive's |
| `DH120_LOG_OLD_FORMAT_APPLIED` | an old-format (DIRT) log was applied to the hive |
| `DH121_LOG_ENTRIES_REJECTED` | some HvLE entries were rejected by their Marvin32 hashes (written while the machine lost power); the valid ones were applied |
| `DH122_LOG_REPLAY_GAP` | the replay stopped at a missing sequence number; later entries were not applied |
| `DH123_LOG_POLICY_NONE` | the hive is dirty but the caller asked for no transaction logs (LogPolicy::None); read as it is on disk |
| `DH124_LOG_GIVEN_MISSING` | a log path given explicitly (LogPolicy::Only) does not exist or is not a file |
| `DH125_LOG_SEQUENCE_TOO_FAR` | the hive's primary sequence is more than one ahead of the secondary: more than one write was lost and the logs cannot bring it back consistently; read as it is |
| `DH126_LOG_APPLIED` | the transaction logs were applied: the hive now holds the writes that had not reached the file |
| `DH127_LOG_INDEX_BUILT` | the search root was walked once to index every .LOG1/.LOG2/.LOG under it (cached for the next hive) |
| `DH128_LOG_CANDIDATE` | a file was considered as a log of this hive, with its score |
| `DH129_LOG_AHEAD` | the log starts after the hive's own sequence, at the sequence its base block names: by the format (regf specification, transaction logs, note 7) recovery starts there, so it is applied, as Windows would; the writes between are in no log any more, so a page they changed and that was not written again keeps its older content |
| `DH200_CELLS_NOT_A_HIVE` | the bytes handed to the deleted-cell scan do not start with a base block and a hive bin; the scan was skipped |
| `DH201_CELLS_SCAN_PANIC` | the cell walker panicked on this hive (a shape it has never seen); the deleted entries of this hive are not reported, the live ones are |
| `DH202_CELLS_SCANNED` | the deleted-cell scan ran: bins, cells, live keys, deleted keys and orphan values counted |
| `DH203_CELLS_CHAIN_BROKEN` | a deleted key's parent chain could not be followed to the root (a parent cell was reused); its path starts with '?\' and the reachable tail |
| `DH204_CELLS_VALUE_NO_DATA` | a deleted value's data cell was reused or is out of bounds; the value is reported by name and type without data |
| `DH205_CELLS_DELETED_KEY` | a deleted key was recovered |
| `DH206_CELLS_ORPHAN_VALUE` | a deleted value whose key is gone was recovered |
| `DH207_CELLS_SKIPPED` | the deleted-cell scan was not asked for (OpenOptions::recover_deleted = false) |
| `DH300_KEY_NOT_FOUND` | the key path asked for does not exist in the hive; check the path against the hive's own layout (NTUSER.DAT has no HKLM subtree, SYSTEM has ControlSetNNN rather than CurrentControlSet) |
| `DH301_SUBKEYS_FAILED` | the subkey list of a key could not be read: the list cell is damaged or points outside the hive; the key's values are still usable, its subtree is not |
| `DH302_ROOT_KEY_FAILED` | the root key cell could not be parsed; the hive is unusable through the parser (the deleted-cell scan may still work on the raw bytes) |
| `DH303_VALUE_UNDECODABLE` | a value's data could not be decoded as its declared type (bad UTF-16, a DWORD of the wrong size); the raw bytes are kept as binary |
| `DH304_VALUE_TYPE_UNKNOWN` | a value carries a type number that is not a documented REG_* type (seen in SAM); the data is kept as binary |
| `DH305_PATH_EMPTY` | an empty key path was asked for; the root key is reached with root(), not with key("") |
| `DH306_WALK_DEPTH_LIMIT` | the walk stopped descending at the depth limit; raise WalkLimits::max_depth if the hive really nests that deep |
| `DH307_WALK_KEY_LIMIT` | the walk stopped at the key limit; raise WalkLimits::max_keys for a complete listing |
| `DH308_MULTI_SZ_UNTERMINATED` | a REG_MULTI_SZ value does not end with the double NUL the format requires; the strings read so far are kept |
| `DH309_DATA_SIZE_MISMATCH` | a value's data is shorter than its declared size; it was cut by the hive or the log, and what is there is decoded |
| `DH310_STRING_NOT_UTF16` | a string value is not valid UTF-16LE; it was decoded leniently with replacement characters |
| `DH311_FILETIME_OUT_OF_RANGE` | a FILETIME cannot be represented as a date (zero, or beyond year 9999); shown empty |
| `DH312_KEY_PARSE_FAILED` | a key cell could not be parsed by nt_hive2 (truncated or overwritten); the key and its subtree are skipped |
| `DH313_VALUE_PARSE_PANIC` | the parser panicked on a key's values; the key is reported without them |
| `DH400_DISCOVERY_IO` | a folder or file could not be listed or read while walking for hives; the rest of the tree was still walked |
| `DH401_COMPANION_SKIPPED` | a registry companion file (.LOG1/.LOG2/.blf/.regtrans-ms/.TMP/.SAV) was seen and left for the log locator; it is not a hive |
| `DH402_DUPLICATE_SKIPPED` | the same hive file was reached twice (a link or a double path); counted once |
| `DH403_NOT_REGF_SKIPPED` | a file named like a hive does not start with 'regf'; it is not a hive (empty, text, a stub) and was skipped |
| `DH404_HIVE_FOUND` | a primary hive was found and classified |
| `DH405_UNREADABLE_HIVE` | a file that starts with 'regf' could not be read as a primary hive (log, truncated, wrong version); skipped with the reason |
| `DH406_DISCOVERY_DONE` | the walk finished: files seen, hives found, dirty hives |
| `DH407_ROOT_MISSING` | the folder given to walk does not exist |
