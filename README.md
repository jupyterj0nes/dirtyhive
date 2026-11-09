# dirtyhive

Windows registry hives read the forensic way, in pure Rust. Given a hive from an image or a
triage package, dirtyhive finds its transaction logs (`.LOG1`/`.LOG2`) even when the collector
renamed or moved them, validates them against the base block, replays them so the hive is no
longer dirty, and recovers the keys and values that were deleted but still sit in the free
cells. The clean hive goes to [nt_hive2](https://crates.io/crates/nt_hive2) for parsing.

It is the hive layer of [hivedump](https://github.com/jupyterj0nes/hivedump) and
[agentc00pr](https://github.com/jupyterj0nes/agentc00pr), extracted from the transaction-log and
deleted-key modules that [faramir](https://github.com/jupyterj0nes/faramir) has run on real
cases, so the three tools read a hive the same way.

## Status

Skeleton. The modules are being moved in; nothing here is usable yet.

## Planned

- `txlog`: locate `.LOG1`/`.LOG2` next to the hive or anywhere under the evidence root, score
  the candidates, verify them by parsing their base block, apply them in sequence.
- `deleted`: walk every hive bin with a bounds-checked parser, find the free cells that still
  hold a key or a value, rebuild each deleted key's path.
- `open`: one call that returns the parsed hive, the logs applied, the dirty flag, and the
  deleted entries.

## License

AGPL-3.0-only.
