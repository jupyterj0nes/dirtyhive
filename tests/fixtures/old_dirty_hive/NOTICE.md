# Old-format dirty hive fixture

`OldDirtyHive` and `OldDirtyHive.LOG1` are the Windows 7 dirty-hive test vectors of
the `yarp` registry library by Maxim Suhanov (https://github.com/msuhanov/yarp,
GPL-3.0, `hives_for_tests/OldDirtyHive`). The log is in the old format (file
type 1, `DIRT` dirty vector).

`RecoveredHive_Windows7` is the same hive after Windows 7 loaded it and applied
the log itself. It is the oracle the test-suite compares Faramir's replay
against.
