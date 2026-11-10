# dirtyhive

Windows registry hives read the forensic way, in pure Rust. A hive copied from a live
machine, pulled out of a triage package or carved from an image is usually *dirty*: its last
writes sit in the transaction logs (`.LOG1` / `.LOG2`), not in the file. The keys and values
deleted before the copy are still in its free cells. dirtyhive opens a hive the way an
analyst needs it:

1. **Base block.** Reads and checks the `regf` header (sequence numbers, file type, version,
   checksum, the tail of the original path) and classifies the hive from the header first,
   the file name second, so `bob_NTUSER.DAT`, `C_Windows_System32_config_SOFTWARE` and
   `SOFTWARE.hve` are what they are.
2. **Transaction logs.** Finds `.LOG1` / `.LOG2` next to the hive or anywhere under the
   evidence root even when the collector renamed or moved them, tells the `NTUSER.DAT.LOG1`
   of two users apart by the hive name embedded in each log, validates every `HvLE` entry
   so a truncated or garbage log can never make the parser panic, cuts a damaged tail and
   replays the valid prefix. Old-format (`DIRT`, Windows XP to 8.0) logs are replayed too.
   The replay engine is [blockcarve](https://github.com/jupyterj0nes/blockcarve)'s, shared
   with caarea, faramir and masstin.
3. **Keys and values.** Hands the clean bytes to [nt_hive2](https://crates.io/crates/nt_hive2)
   and exposes keys with their paths and timestamps, values with typed data (`REG_SZ`,
   `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`, …), a walk with
   limits, and the rebuilt bytes to write to disk.
4. **Deleted cells.** Walks every hive bin with blockcarve's bounds-checked cell walker and
   returns the deleted keys with their rebuilt paths and values, and the orphan values whose
   key is gone.

Every degraded path records a diagnostic with a stable code (`DH###_NAME`) and the work goes
on with what is there: a dirty hive without logs is still read, a log with a damaged tail is
still applied up to the damage. Nothing is printed unless asked.

It is the hive layer of [hivedump](https://github.com/jupyterj0nes/hivedump) and
[agentc00pr](https://github.com/jupyterj0nes/agentc00pr), extracted from the modules that
[faramir](https://github.com/jupyterj0nes/faramir) has run on real cases, so the tools read a
hive the same way.

## Usage

```rust
use dirtyhive::{Hive, OpenOptions, Walk, WalkLimits, Deleted};

let opts = OpenOptions::new().search_root("D:/evidence/host01");
let mut hive = Hive::open(std::path::Path::new("D:/evidence/host01/C/Windows/System32/config/SOFTWARE"), &opts)?;

let info = hive.info();
println!("{}", info.summary()); // SOFTWARE [dirty, 2 log(s) applied]
for log in &info.logs_applied {
    println!("applied {} ({} entries)", log.path.display(), log.entries);
}

// One row per value, the whole hive.
hive.walk(&WalkLimits::default(), |key| {
    for v in &key.values {
        println!("{}\t{}\t{}\t{}\t{}", key.last_written_text(), key.path, v.name, v.kind, v.data.display());
    }
    Walk::Continue
})?;

// A single value.
let shell = hive.string_value(r"Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell")?;

// What was deleted.
for d in hive.deleted() {
    match d {
        Deleted::Key(k) => println!("deleted key {} ({} values, last written {:?})", k.path, k.values.len(), k.last_written),
        Deleted::Value(v) => println!("orphan value {} = {}", v.name, v.data.display()),
    }
}

// The hive with its logs applied, for another tool.
hive.save(std::path::Path::new("processed/SOFTWARE.rebuilt"))?;

// What happened, with codes.
for d in dirtyhive::diag::drain() {
    eprintln!("{d}"); // [WARN] DH113_LOG_PARTIAL: ...LOG1: using the first 24576 of 65536 bytes (3 valid entries)
}
# Ok::<(), dirtyhive::Error>(())
```

`OpenOptions`:

| Field | Default | Meaning |
|-------|---------|---------|
| `logs` | `LogPolicy::Auto` | `Auto` finds the logs; `Only(paths)` uses the files given; `None` reads the hive as it is |
| `search_root` | none | Where to look for logs beyond the hive's own folder (the evidence root; indexed once per root) |
| `recover_deleted` | `true` | Walk the free cells for deleted keys and values |

`Hive::from_bytes` opens a hive held in memory (a carved hive, a file read from an image);
logs are then used only when given with `LogPolicy::Only`.

Lower layers are public for tools that need them: `header::read_header`, `kind::HiveKind`,
`txlog::{inspect_log, locate_logs, LogTarget}`, `deleted::scan`, `discover::discover` (every
primary hive under a folder, companion files skipped).

## Diagnostics

Each module declares its codes in a range; [`docs/codes.md`](docs/codes.md) lists all of
them with what they mean and what to do.

| Range | Area |
|-------|------|
| `DH000`-`DH099` | opening a hive: file, base block, classification, parser |
| `DH100`-`DH199` | transaction logs: location, validation, replay |
| `DH200`-`DH299` | hive bins and cells: deleted keys and values |
| `DH300`-`DH399` | keys and values: lookup, walk, decoding |
| `DH400`-`DH449` | discovery of hives under a folder |

The sink is per thread: `diag::drain()` / `snapshot()` / `has(code)` / `count(code)` /
`summary()`. A tool that works on several threads records in each and `absorb`s the lists in
the main one. `diag::set_echo(true, false)` prints warnings and errors to stderr as they
happen. Errors returned to the caller are `Error { code, detail }`, displayed as
`DH003_SIGNATURE_INVALID: <detail>`.

## Correctness

- The replay of the Windows 10 test vectors (`tests/fixtures/dirty_hive`) matches the hive
  Windows 10 produced when it loaded them; the old-format replay matches the Windows 7
  recovery of the `yarp` test vector (`tests/fixtures/old_dirty_hive`).
- `dirtyhive::testing` is a spec-faithful writer of hives and `HvLE` logs (keys, every value
  type, deleted keys and values as free cells, Marvin32 hashes), so every path is exercised
  with hand-built evidence; the tools built on dirtyhive use it in their own tests.
- Tests over the lab's real triage packages (`D:\evidence`, skipped where absent) cover a
  dirty `NTUSER.DAT` whose logs start after its primary (recovered by the format's rule, the
  writes no log holds named), a
  dirty `Amcache.hve` without logs, clean `SYSTEM` and `SOFTWARE` walked completely, every
  user hive of a triage, and the deleted-cell scan over every hive of `config`.
- `cargo test --release`, `cargo clippy --all-targets` clean, `#![forbid(unsafe_code)]`.

## Known limits

- A resident value of 1 or 2 bytes (data stored inside the `vk` cell) comes back through the
  parser's `DWORD`; dirtyhive rebuilds the bytes from it, which is right when the unused bytes
  are zero, as Windows leaves them.
- Big data (`db` cells, values over 16 KiB) is read by nt_hive2; `REG_LINK` and the resource
  types come back as binary.
- Logs that start after the hive's own sequence (a hive copied while it was being written: a
  live system, a shadow copy) are applied from the sequence their own base block names, as
  the regf specification says (transaction logs, note 7: the first entry equals the log's
  base block primary sequence and is not less than the hive's secondary sequence) and as
  Windows does on boot. The writes between are in no log any more: a page they changed and
  that was not written again keeps its older content. `DH129_LOG_AHEAD` says so for each
  log. A log that cannot start (no entry at its own base block's sequence) is reported
  (`DH109_LOG_GAP`) and not applied.

## License

AGPL-3.0-only. The test fixtures under `tests/fixtures` carry their own notices (nt_hive2's
Windows 10 vectors, yarp's Windows 7 vectors, GPL-3.0).
