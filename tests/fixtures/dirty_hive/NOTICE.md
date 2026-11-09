# Dirty hive fixture

`NewDirtyHive`, `NewDirtyHive.LOG1` and `NewDirtyHive.LOG2` are the Windows 10
dirty-hive test vectors shipped with the `nt_hive2` crate
(https://codeberg.org/janstarke/nt_hive2, GPL-3.0, `tests/data/NewDirtyHive1`).
They are used here only as test fixtures to prove that Faramir locates and
replays real transaction logs produced by Windows.

`NewDirtyHive.rla-replayed` is the same hive after replaying LOG1 and LOG2 with
Eric Zimmerman's `rla.exe` 1.6.0.0 (RECmd suite). It is the independent oracle
the test-suite compares Faramir's own replay against.
