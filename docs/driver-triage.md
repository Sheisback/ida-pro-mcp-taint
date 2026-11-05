# Windows driver triage (`driver_*` tools)

Read-only static triage for Windows kernel drivers, exposed as ten MCP tools.
Start with `driver_survey`, decode or discover IOCTL and FSCTL leads, then review device,
pool, sink, and heuristic leads. Nothing here mutates the database.

## Tool map

| Tool | Stage | What it returns |
| --- | --- | --- |
| `driver_survey` | dispatch | PE/driver check, DriverEntry, framework, dispatchers |
| `driver_decode_ioctls` | decode | Field split, plausibility, base score for given codes |
| `driver_find_ioctls` | ioctl_scan + scoring | Discovered IOCTL/FSCTL leads with method, confidence, severity |
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
a `method` note, and address evidence. Within one evidence class, severity answers "look here first",
never "this is a vulnerability".
The control-code fallback now collects decompiler switch cases and comparisons,
IDA switch cases, and corroborated immediates for each code-reading function.
The review queue orders exact selector facts first, then collection evidence
quality, then decoded severity. A low-confidence
immediate with a high decoded risk score cannot hide a structural switch case.
All leads remain visible, and a structural case without exact route/selector
proof is still a lead rather than a trigger fact.
For an exact ctree case, `driver_find_ioctls` also reports
`handler_function`/`handler_function_addr` only when the case body has one
unique direct internal function target. Multiple targets, indirect calls,
imports, or a self-call leave the handler unknown. This narrows static review;
`function_addr` remains the dispatcher and the handler never becomes external
route proof.

The eleven checks: `unvalidated_copy`, `pool_alloc_unguarded`,
`stack_alloc`, `privileged_insn`, `physical_memory_ref`, `unsafe_mdl`,
`irql_cooccurrence`, `missing_priv_gate`, `arbitrary_write_shape`,
`double_fetch`, `use_after_free`.

## Scope and honesty rules

- Static IDA analysis only; the target binary is never executed.
- A slot-like memory store is a dispatch lead only when it is reached by a
  direct call chain from the entry and a typed `DRIVER_OBJECT.MajorFunction`
  member write names an exact handler function. A bulk or indirect registration
  that cannot be proved stays unresolved. `GsDriverEntry` reports the exact
  `DriverEntry` continuation when it is directly called after initialization.
- Direct `IRP_MJ_FILE_SYSTEM_CONTROL` registrations are surveyed alongside
  device and internal controls. x64 control-code corroboration uses the WDK
  `IO_STACK_LOCATION` `+0x18` member offset, including address-temporary and
  compare-read forms. An unregistered code match remains a heuristic lead,
  never proof of an externally reachable route or a vulnerability.
- The fallback examines every corroborated function until EOF or the tool
  deadline, whether or not another dispatcher already yielded codes. The
  same code in two functions retains both leads. Deadline expiry reports a
  partial limitation; it cannot make a truncated scan clean.
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
  IDA 9.3 headless: three direct dispatchers, two IOCTLs, one direct FSCTL,
  later and duplicate-code heuristic leads, unrelated-slot rejection, pool tag,
  device/symlink strings, world-SDDL ACL lead, thunk-aware flagging and
  call chain, and the planted heuristic leads. The separate
  `driver_stub_fixture.sys` proves the cookie-wrapper continuation. Re-run on
  disposable copies:

```sh
work=$(mktemp -d)
cp tests/driver_fixture.sys "$work/driver_fixture.sys"
uv run ida-mcp-test "$work/driver_fixture.sys" -p '*driver*' -q
cp tests/driver_stub_fixture.sys "$work/driver_stub_fixture.sys"
uv run ida-mcp-test "$work/driver_stub_fixture.sys" -c api_driver -q
```

The owned fixture also has an unregistered multi-case FSCTL handler. The
auto-discovery fallback must retain it as a high-confidence ctree lead without
inventing `selector_fact`. A disposable symbolized driver smoke changed a
known FSCTL lead from low-confidence immediate positions 41/42 of 75 to
ctree-case positions 20/21 of 101; the unrelated high-severity immediate moved
from position 1 to 59. This changes review order, not route authority.

An RDBSS-shaped indirect MajorFunction initializer and second-level dispatch
vector are still unresolved by the typed route producer. A read-only smoke on
a symbolized Windows driver found the FSCTL code leads in the internal handler,
but did not prove their external route. Jump-table dispatch, packed imports,
and 32-bit images likewise remain experimental.
