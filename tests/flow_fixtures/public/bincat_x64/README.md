# BinCAT Windows x64 public corpus

This directory pins a fetch-only copy of the authoritative
`airbus-seclab/bincat` `doc/get_key` sample. The PE, PDB, and upstream sources
are deliberately not redistributed here. Run `scripts/acquire_bincat_x64.py`
into an empty, isolated output directory to obtain and verify them.

`identity.json` proves only the PE/PDB GUID-age relationship. It deliberately
classifies source correspondence as unproven because upstream does not include
the Windows compiler invocation or a source digest embedded in the build.
Binary-level IDA observations are therefore authoritative; source is reference
evidence only.

`oracle.json` is a hand-authored project oracle, not a copy of BinCAT tutorial
expectations. `ida_static_receipt.json` was recorded by loading the verified PE
and matching PDB in IDA 9.3 without executing the target or attaching a
debugger.
