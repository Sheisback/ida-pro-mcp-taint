# Flow operator guide

## Safety boundary

Use the flow pipeline for static analysis only. **Never execute the target**,
attach a debugger, or use a dynamic proof-of-concept while producing or
validating these receipts. Every committed receipt must retain
`target_executed: false`. Run licensed IDA capture only in the protected CI or
release environment; untrusted pull requests must not receive license secrets
or a licensed runner.

## Install and activate IDA

1. Install Python 3.11 or newer, `uv`, and a supported IDA Pro installation.
2. Activate idalib with IDA's `py-activate-idalib.py` script for the host OS.
3. Install from the wheel used for release, or create a development environment
   with `uv sync --dev`.
4. Confirm the source, wheel, headless process, and (when actually available)
   GUI process report the same build ID. A GUI acceptance gate is a blocker,
   not evidence of GUI success; do not accept an EULA as part of automation.

## Audit committed support evidence

The audit reads JSON only. It neither imports IDA nor opens a target:

```bash
uv run python scripts/audit_flow_support.py \
  --root . \
  --check tests/flow_fixtures/manifests/support_receipts.json
```

To regenerate the derived summary after independently reviewed receipt changes:

```bash
uv run python scripts/audit_flow_support.py \
  --root . \
  --output tests/flow_fixtures/manifests/support_receipts.json
```

Review the diff. The audit validates the P0 result bodies, recomputes the
normal, format, and RV32 semantic receipt graph, and then compares the derived
support manifest. It does not trust copied digest labels. A successful audit
means the committed receipt graph is internally consistent and reproducible;
it is not a support promotion or a P6 release-readiness verdict.

## Interpret results conservatively

- `normal` identifies the native Hex-Rays observation path for the exact
  recorded configuration.
- `fallback` is a separate evidence path. RV32 remains partial and unverified;
  never merge it into normal evidence or label it fully supported.
- `partial` and `unknown` are soundness states. Preserve unresolved calls,
  memory effects, paths, and unsupported operations in downstream reports.
- A processor/decompiler file inventory or license declaration is not proof
  that extraction succeeds. Only an actual static receipt can prove the exact
  observed configuration.

For a pinned conformance fixture, call `flow_create_snapshot` with its reviewed
`profile`; the default `routing_mode=exact_fixture` also requires the frozen
input digest. For another analyst-owned binary, set
`routing_mode=analyst_selected` and provide both the explicit `profile` and
`abi`. This mode validates the open database's processor, bitness, data
endianness, format, and exact IDA/Hex-Rays builds against reviewed normal
configuration evidence. It does not infer the ABI from the binary or claim that
the binary was previously measured. The worker binds the selection to the
current binary digest and fails follow-up work as stale if the input changes.
RV32 cannot be selected until normal evidence exists.

## Packaging and release expectations

- Run focused support-audit tests before the full suite.
- Require Ruff, scoped Pyright, compileall, sdist/wheel builds, and isolated
  wheel imports.
- Verify build-ID parity across every process mode actually exercised.
- Aggregate protected licensed-IDA results into release CI without exposing
  credentials to untrusted jobs.
- Treat `record_flow_licensed_normal.py` as a content/binding validator, not a
  standalone clock or provenance authority. Temporal freshness comes from the
  protected workflow producing the P0 and semantic matrices in the same job;
  never copy archival receipts to a new directory and label them a current run.
- Retain receipt inputs, source digests, named limitations, and
  `target_executed: false`; do not delete or weaken evidence to make a gate pass.
- Require a current, normal receipt for each of the 16 mandatory profiles in
  `profiles/flow-release-scope.json`. RV32 is an optional, partial fallback,
  never a passing normal receipt. A fallback for any **required** profile,
  skip, empty required profile list, stale/unbound receipt, missing benchmark,
  or absent permitted GUI-process observation still blocks release.

If IDA, a processor/decompiler module, license entitlement, or GUI acceptance
is unavailable, report that exact blocker and leave the corresponding claim
unverified.

## Program-derived bounded path checks

`flow_check_path` is the sole registered path-proof tool. Submit with
`graph_artifact`, `request_key`, and `path` containing:

```json
{"bindings":{"snapshot_id":"snapshot-v1:…","graph_digest":"sha256-v1:…","profile_digest":"sha256-v1:…","ruleset_digest":"sha256-v1:…","summary_digests":["sha256-v1:…"]},"blocks":[0,1],"schema_version":1}
```

The selector requires explicit `schema_version: 1`; omission is rejected.
Use owned graph metadata and CFG block indices. The sequence must begin at the
function entry and follow actual CFG edges. Poll `flow_get_job` (or cancel via
`flow_cancel_job`). Page its `path_proof_artifact` by calling `flow_check_path`
with **only** `artifact_id`, optional `cursor`, and `limit`. Pages include the
internally derived constraints, variable domains, assumptions, proof and witness
evidence; normal immutable paging and character limits apply.

The bounded scope is *reaching the final selected block before executing it*.
The initial supported correspondence is an acyclic scalar prefix with structured
conditional comparisons, constants, copies, selected modular arithmetic, and
complete input domains up to 8 bits. Bounds are internally fixed at zero loop
unrolls and zero calls. Unsupported effects (including memory, calls, selects,
phi/loop dependencies), wide symbolic domains, missing branch correspondence,
and prefixes without modeled branches return `unknown`/`incomplete`, not a
negative proof. Solver budgets can also yield Unknown. Exact SAT still requires
independent witness replay; exact exhaustive UNSAT is confined to this prefix.

Caller-authored equations, variables, predicates, origins, domains, assumptions,
and bounds are not accepted, even when accompanied by an existing evidence ID.
All artifact/profile/ruleset/summary bindings must match. The former
`flow_create_path_proof` and `flow_get_path_proof` names are not registered public
tools; archived smoke receipts containing them do not validate this surface.
No target execution, runnable input generation, or vulnerability verdict occurs.

### Reproduce the static public path acceptance receipt

Run `PYTHONPATH=src:. uv run python tests/flow_core/native_path_smoke.py
 tests/flow_fixtures/manifests/path_public_smoke.json` as one command on the
licensed Apple-clang/IDA host. The script pins the compiler and SDK versions,
compiles the repository-owned `path_anchor.c` twice per architecture, requires
identical hashes, and analyzes disposable x86_64/AArch64 copies. It never runs a
target. Public CFG successors select the paths; both byte-bit outcomes must have
exact feasible proofs with independently replayable witnesses. The pure receipt
gate checks current implementation/source/script hashes, BUILD_ID, response
limits, actual input domains and witness predicates. A changed source/build needs
a genuine rerun, not relabelled receipt hashes.

The scalar correspondence explicitly maps SSA bitwise operator names to canonical
bit-vector operators. A byte mask on `concat_low(byte, high_bits)` may be projected
for equality/inequality only when the mask and compared constant fit the low
byte. This exact identity does not assume high input bits are zero or truncate
the domain of a wide input. Wider masks and signed projections remain Unknown.
Informational extraction diagnostics do not imply missing semantics; unsupported
function diagnostics still prevent a definite result.
