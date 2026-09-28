# Windows driver triage (`driver_*` tools)

Read-only static triage for Windows kernel drivers, exposed as ten MCP tools.
Start with `driver_survey`, decode or discover IOCTLs, then review device,
pool, sink, and heuristic leads. Nothing here mutates the database.

## Tool map

| Tool | Stage | What it returns |
| --- | --- | --- |
| `driver_survey` | dispatch | PE/driver check, DriverEntry, framework, dispatchers |
| `driver_decode_ioctls` | decode | Field split, plausibility, base score for given codes |
| `driver_find_ioctls` | ioctl_scan + scoring | Discovered IOCTLs with method, confidence, severity |
| `driver_find_devices` | devices | Device paths and symbolic-link path evidence |
| `driver_audit_acl` | acl | Default-ACL and SDDL review leads |
| `driver_find_pooltags` | pooltags | Resolved pool tags with call sites |
| `driver_flag_functions` | flagging | Risky-routine matches with xref evidence |
| `driver_audit_exports` | exports_audit | Exports with no internal callers |
| `driver_trace_calls` | callchain | Bounded dispatcher-to-sink paths |
| `driver_triage_leads` | heuristics | Eleven heuristic leads (see below) |

Use the restricted profile for driver work:

```sh
uv run idalib-mcp --stdio --profile profiles/driver-readonly.txt path/to/disposable/driver.sys
```

## Leads, not verdicts

Heuristic output (`driver_triage_leads`, ACL/export leads, IOCTL severity)
is a prioritized review queue. Every lead carries `requires_manual_review`,
a `method` note, and address evidence. Severity answers "look here first",
never "this is a vulnerability".

The eleven checks: `unvalidated_copy`, `pool_alloc_unguarded`,
`stack_alloc`, `privileged_insn`, `physical_memory_ref`, `unsafe_mdl`,
`irql_cooccurrence`, `missing_priv_gate`, `arbitrary_write_shape`,
`double_fetch`, `use_after_free`.

## Scope and honesty rules

- Static IDA analysis only; the target binary is never executed.
- x64 is the primary width. x86 dispatcher slots are derived arithmetically,
  but IRP-offset corroboration, double-fetch, and intra-function UAF stay
  x64-only and say so in `limitations`.
- The decompiler is optional. Without Hex-Rays, ctree collection and the
  write-shape check report unavailable while disassembly stages still run.
- IOCTL sink bumps use dispatcher-closure attribution, capped and labeled
  imprecise. Per-case attribution is a documented future step.
- Indirect calls are never guessed; call-chain stats keep them unresolved.
- `database` arguments elsewhere in this repo mean session IDs, not paths;
  these tools always operate on the currently open database.

## Origin and license note

The triage workflow mirrors the publicly documented behavior of
DriverBuddyReloaded (GPL-3.0), with a 1:1 stage mapping kept in
`src/ida_pro_mcp/ida_mcp/driver/`. No code, text, or data table was copied
from that project: every module, table, and threshold here is an independent
implementation written for this repository (MIT). Do not paste third-party
lists into the driver stages; extend the curated tables with original,
reviewed entries instead.

## Verification status

- SDK-free core: `uv run pytest -q tests/flow_core/test_driver_triage.py`
- IDA shape/negative paths: `test_api_driver.py` via `ida-mcp-test` on the
  ELF fixtures (non-driver behavior only).
- Positive driver paths: owned fixture `tests/driver_fixture.sys` (built
  from `tests/driver_fixture.c`, never executed) verified on licensed
  IDA 9.3 headless: 2 dispatchers, 2/2 IOCTLs via the decompiler, pool tag,
  device/symlink strings, world-SDDL ACL lead, thunk-aware flagging and
  call chain, and the planted heuristic leads. Re-run on a disposable copy:

```sh
work=$(mktemp -d)
cp tests/driver_fixture.sys "$work/driver_fixture.sys"
uv run ida-mcp-test "$work/driver_fixture.sys" -p '*driver*' -q
```

Real-world drivers (jump-table dispatch, packed imports, 32-bit images)
remain untested; treat those paths as experimental until such a smoke passes.
