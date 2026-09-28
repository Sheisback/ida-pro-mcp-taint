"""Windows kernel-driver triage stages (read-only IDA adapters).

Module layout mirrors DriverBuddyReloaded's pipeline stages one-to-one so the
port stays recognizable, while every implementation here is original,
read-only code written for this repository's MCP tools:

- ``context``: per-run state + shared IDA helpers (cf. utils.AnalysisContext)
- ``dispatch``: framework classification + dispatcher discovery (cf. wdm/wdf)
- ``ioctl_scan``: IOCTL discovery over dispatchers (cf. ioctl_decoder)
- ``devices``: device names + symbolic links (cf. device_name_finder)
- ``acl``: device ACL/SDDL audit (cf. utils device-create audit)
- ``pooltags``: pool-tag collection (cf. dump_pool_tags)
- ``flagging``: risky routine match surface (cf. utils xref surface scan)
- ``opcodes``: privileged-instruction collection (cf. find_opcodes)
- ``callchain``: handler-to-sink paths (cf. callchain)
- ``heuristics``: review leads, never verdicts (cf. heuristics)
- ``scoring``: per-IOCTL risk finalization (cf. scoring)
- ``exports_audit``: zero-xref exports (cf. exports_audit)
- ``pipeline``: ordered full-run driver (cf. analysis.run_analysis)

Nothing in this package mutates the database: no renames, no struct/enum
application, no file output. Report rendering is the MCP response itself.
"""

from .context import DriverContext

__all__ = ["DriverContext"]
