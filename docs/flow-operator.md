# Flow operator guide

## Safety boundary

Use the flow pipeline for static analysis only. **Never execute the target**,
attach a debugger, or use a dynamic proof-of-concept while producing or
validating these receipts. Every committed receipt must retain
`target_executed: false`. Run licensed IDA capture only in a trusted local
analyst environment or protected CI/release environment; untrusted pull
requests must not receive license secrets or a licensed runner.

The separate licensed distribution gate requires **IDA 9.3 only**. Its frozen
performance baseline is for a protected `linux-x86_64` runner; the same static
extraction can be measured on macOS, but those timings do not satisfy the Linux
baseline.

## Install and activate IDA

1. Install Python 3.11 or newer, `uv`, and a supported IDA Pro installation.
2. Activate idalib with IDA's `py-activate-idalib.py` script for the host OS.
3. Install from the wheel used for release, or create a development environment
   with `uv sync --dev --extra solver` (the extra enables symbolic refinement).
4. Confirm the source, wheel, headless process, and (when actually available)
   GUI process report the same build ID. A GUI acceptance gate is a blocker,
   not evidence of GUI success. Do not create or overwrite EULA acceptance
   during the evidence probe.

The GUI-process receipt proves installed-bundle loading and capability discovery
in a real IDA GUI process. It does **not** prove GUI semantic flow extraction;
use completed static flow jobs for that narrower claim.

For an explicitly authorized local GUI check on a host that **already** accepted
the IDA EULA, `record_flow_gui_ci.py --accepted-registry ~/.idapro/ida.reg`
copies the existing IDA registry into a disposable `IDAUSR`. It does not alter
the original registry, accept a new agreement, or substitute for protected CI.
The protected workflow also reuses an existing accepted registry when present;
if its image lacks one, GUI proof remains blocked. License-owner-approved image
provisioning can use [Hex-Rays HCLI's documented
`ida install --accept-eula`](https://hcli.docs.hex-rays.com/advanced/ci-cd-integration/)
option; the probe itself must not fabricate acceptance.

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

At IDA 9.3 `MMAT_CALLS`, a final native `BLT_STOP` block records regular
termination but has no native return instruction. It becomes a synthetic
value-less `Exit` unless the current IDB function type supplies a scalar
register return location that round-trips through the SDK's register mapping.
Only then is a synthetic `Return` bound to that register's reaching value.
Neither synthetic node invents a source EA, and the **correctness of the IDB
type is an analyst assumption**, not an inferred ABI proof. `BLT_0WAY` and
unresolved exits remain separate. Do not treat `Exit` as a clean return value.

Likewise, SDK-mapped register arguments in the IDB function type produce
read-only `argument_bindings` on `flow_get_function_ssa` pages. Each binding
names exact entry atom IDs and its type-assumption provenance. Missing or
unsupported arglocs are not fabricated. Seeded taint can remain `partial`
because memory or call effects are unresolved even when exit and entry
locations are known.

For an analyst-designated external input such as a driver request buffer,
first verify the transfer method, buffer pointer, length check, and the
microcode `Load` that reads the specific byte or field. Page
`flow_get_function_ssa`/`flow_get_evidence`; then submit a whole-value
`{node_id, labels}` seed for that **Load value** to
`flow_create_implicit_analysis`. This follows the value *after* the read.
Seeding the pointer's `InputValue` instead tracks its address/provenance, not
every byte of the pointee. This API does not automatically classify OS
buffers as user-controlled or prove that the read is reachable. Inspect
`flow_get_memory_analysis` for access candidates and
`flow_explain_implicit_analysis` for local uncertainty before interpreting
downstream Store/Return labels.

### Explicit pointee byte sources (experimental)

`flow_create_implicit_analysis` additionally accepts `kind: "pointee_range"`:

```json
{
  "kind": "pointee_range",
  "schema_version": 1,
  "pointer_node_id": "node-v1:<owned pointer node>",
  "interval": {"start": 0, "end": 8},
  "labels": {
    "explicit": ["REQUEST"], "control": [], "unknown_provenance": false,
    "any_explicit_source": false, "any_control_source": false
  },
  "binding_mode": "analyst_assumed_exact",
  "point": "after_pointer_definition"
}
```

This is an assertion about the bytes **after this pointer definition**, not a
read of runtime memory, an OS buffer classifier, or a claim about earlier reads.
Select a full-address-width entry `InputValue` or a pointer-valued `Load` outside
CFG cycles. A field-loaded pointer is allowed. A source cannot be placed inside
a loop and repeatedly re-taint cleared bytes. There are at most 16 ranges / 16
named source labels, with at most 512 bytes per range; overlapping ranges for one
pointer and mixed binding modes are rejected.

`require_program_derived_exact` requires the existing memory analysis to identify
one non-null singleton candidate. `analyst_assumed_exact` explicitly permits a
new valid, non-null singleton symbolic view when that relation is unavailable.
It does **not** prove disjointness from other pointers or the current frame.
Both modes require the analyst to justify the **content taint** assertion.
Unresolved calls, weak aliases and unsupported effects retain uncertainty.

The completed job returns a separate `ssa_artifact`, `graph_artifact`, and
`pointee_certificate_artifact`. The original SSA/graph is unchanged. Page the
certificate with `flow_get_pointee_evidence`; it replays the base-to-bound graph
and binds effective source labels to the implicit result's source digest. Use
the **returned bound graph** for subsequent traces/evidence and the implicit
artifact for seeded facts/explanations. Its memory result describes the bound
structural analysis; seeded labels live in `flow_get_implicit_analysis` facts.

Facts may additionally expose `explicit_bit_ranges`, each containing `label`,
`bit_offset`, and `width_bits`. These are **value-relative bit positions**, not
absolute memory addresses. For a little-endian 64-bit Load after a precise
4-byte clear of a seeded `[0,8)` range, only `{bit_offset:32,width_bits:32}`
survives. Big-endian mapping follows the snapshot endianness. Unsupported scalar
operations can widen these ranges. Missing ranges alone are not a clean result:
inspect whole-value labels, `unknown_provenance`, access precision and diagnostics.

### Generic function-address Store evidence (experimental)

Submit `flow_check_store` with `ssa_artifact`, `store_node_id`, `base_node_id`,
`byte_offset`, `target_function` (name/address), and `request_key`. Optionally
provide `member_path`, for example `["callbacks", 14]`, to compare the numeric
offset and width with the current IDB layout of an exactly bound entry argument.
Field names are data, never WDM-specific engine rules. Poll `flow_get_job`, then
page the same tool using only its returned `store_evidence_artifact` as
`artifact_id` (plus cursor/limit).

The certificate combines a bounded graph-derived numeric Store relation with
a fresh exact-function-entry observation and optional structure/array layout.
It cites immutable nodes/evidence, snapshot/graph/memory digests and assumptions;
paging replays the numeric proof. Current IDB types/names remain analyst
assumptions. Truncation/reextension, different phi arms, unresolved memory loads,
ambiguous layouts, non-function targets and insufficient budgets cannot produce
`proven_in_scope`. `mismatch` is a mismatch with the supplied relation, not a
claim that no alternative registration exists.

Even `proven_in_scope` means **this Store writes this function address to this
slot if reached, under the recorded assumptions**. It does not prove reachable
execution, all-path registration, final slot contents after later overwrites,
OS callback semantics, or a vulnerability. No Windows-driver support is promoted.
For high addresses use a `flow-wire/2` snapshot; source payload integers and
the Store `byte_offset` use tagged integers. Bounded member indices and paging
controls remain ordinary safe JSON integers.

### Scalar sources and shared uncertainty

When an analyst has an independently calibrated, whole-byte subrange of an
`InputValue` but no exact entry atom, `flow_create_implicit_analysis` also
accepts a seed with `kind: "bit_range"`, `schema_version: 1`, `node_id`,
`labels`, `bit_offset`, and `width_bits`. The offset is relative to that input
node, not a native register number. Only named explicit labels on a bounded
input window are accepted. Direct `trunc`/`high`/`extract`/`concat`/extension
projections preserve the selected bits; unsupported scalar operations widen
conservatively. Queries are bounded to 16 bit-range seeds and 16 distinct
named bit-range labels. A bounded whole-value seed on an exact entry atom also
projects its full bit window through precise concat/constant-shift operations.
A single-candidate strong whole-byte Store records selected source bits per
byte; an exact Load reconstructs them under the snapshot's endianness.
Weak/may-alias Stores with only *part* of the data bits selected, width
mismatches, or unresolved ranges retain possible labels and
`bit_seed_byte_store_widened`/`partial`. A weak Store whose entire data value is
selected does not need that bit-precision diagnostic. This is not general
ABI-argument inference or a fault/path proof.

The current implicit-flow job replays its bound memory plan with the supplied
value seeds and checks that the memory dependency graph is unchanged. This can
remove the older blanket Load/Store `unresolved_boundary` on a modeled access;
it does not infer a return value from `Exit`. Seeds on effect nodes that the
byte-memory model cannot represent fall back to the conservative scalar path
with `seeded_memory_source_unavailable` and remain partial. Check each observed
fact's `unknown_provenance` even when the analysis computation is
`complete_in_scope`; completion is not an exact-alias or no-taint verdict.

To inspect *why* a memory result is bounded or partial, page the completed
snapshot's `memory_result_artifact` with `flow_get_memory_analysis`. Access
items expose candidate objects/byte intervals, `precision`, `unresolved`, and
reasons derived from that access's pointer and candidate evidence;
dependencies and facts remain separate items. Two finite candidates with
`may_alias` mean possible access to either, not definite access to both.
The page is scoped to the current database and returns no automatic verdict.

For one **seeded observation**, call `flow_explain_implicit_analysis` with the
completed `implicit_artifact` and that fact's `node_id`. It pages bounded
`cause` items (node/edge/evidence, alias precision and direct affected node)
separately from function-wide `global_diagnostic` items. A cause is a
candidate on the structural backward slice—not a feasible path, definite
source-to-sink relation, or vulnerability verdict. `truncated=true` means the
explanation budget ended before all candidates were visited. A locally known
fact may have zero local causes even while the overall analysis is `partial`.
New implicit jobs bind their verified memory plan/result as owned artifacts so
paging checks those relations without rerunning the fixed point; older v1
implicit artifacts remain read-only and use a conservative replay.

If a job itself fails, `flow_get_job.error` keeps `code=handler_failed` plus a
bounded `phase` and allowlisted `reason` (for example a microcode-generation
failure, stale context, or SSA budget). Unclassified failures say
`internal_error`; cancellation and deadlines retain their separate codes.
Exception messages, native EAs, and host paths are never copied into the
durable error envelope. A failed extraction may have no node/evidence ID to
cite—do not invent one or reinterpret the job failure as a clean taint fact.

For typed functions, a normal scalar `Return` is synthesized only from an
exact IDB return argloc. IDA 9.3 may name an x86_64 one-byte location AL/DIL
on the reverse mapping even when the IDB type names RAX/RDI; the alias is
accepted only if mapping it back proves the same microregister byte.
`typed_void_return` yields a value-less normal `Exit`; `typed_noreturn` is an
unsupported non-return terminal, **not** a normal Exit. A stack or otherwise
unmapped formal has `typed_argument_unmapped` and no fabricated SSA entry
binding; an unmapped scalar return has `typed_return_unmapped` instead of a
fabricated value. These are type/SDK observations, not proof that an IDB type
is right.

The memory model distinguishes an incoming pointer whose register location
**and pointer type** are bound by the current IDB function type (`typed_entry`)
from an untyped or integer-typed entry value (`argument`). The pointer flag
uses IDAPython's documented [`tinfo_t.is_ptr()`](https://python.docs.hex-rays.com/classida__typeinf_1_1tinfo__t.html)
and requires a full-width exact argloc; casting an integer formal to an
address does not grant this no-alias assumption. The `typed_entry` versus
current-frame `no_alias` result is **conditional** on more than that type:
the analyst must also assume that incoming pointer values obey valid
source-object provenance and are not forged numeric addresses into the
callee's future frame. IDB type metadata alone cannot prove this property of
arbitrary machine code. Two typed incoming pointers can still alias each
other; untyped/unknown pointers remain conservative. A fixed program global
is likewise distinct from the current frame under the documented
flat-user-space assumption. These distinctions do not validate the analyst's
IDB type or establish fault/path feasibility.

The MCP default for an **untyped** input pointer versus the current frame is
unchanged: `may_alias_unknown`, never an inferred clean result. In
`flow_get_memory_analysis`, inspect each dependency's `alias_boundary` and
the page metadata's `alias_policy` and
`untyped_current_frame_alias_dependency_count`. The boundary code
`untyped_input_current_frame_noalias_unproven` identifies the source/target
object pair, reports `status: unknown` and `alias_relation: may_alias`, and
explains why possible taint is retained. For an observation, call
`flow_explain_implicit_analysis` with its node ID; matching local causes carry
the same boundary, and metadata includes
`untyped_current_frame_alias_cause_count`. These are structural candidate
reasons, not proof that a particular execution aliases, and no MCP output
offers an automatic opt-in that silently converts them to no-alias.

An untyped entry value spilled to the stack can regain a **possible pointee
object** when one full-width Store dominates the reload and exactly that
Store reaches every byte. Partial overwrites, may-alias writers, and bypass
paths leave the pointer unresolved; a second analysis discards the recovery
if the new alias graph invalidates that proof. This repairs pointer value provenance,
**not** a no-alias proof: an untyped incoming pointer may still numerically
overlap the current frame under the flat binary model. Inspect
`flow_get_memory_analysis` dependencies for `cross_object_may_alias`, source
candidate object IDs, and the directly affected Load; trace forward from
that Load for downstream impact.

Recovery also recognizes a single full-width spill reload beneath same-width
copies, addition, or the left side of subtraction in a bounded address expression.
Multiple reload occurrences (including `p+p`/`p-p`), width-changing wrappers,
unsupported arithmetic, cycles, and traversal-budget exhaustion do not establish
a base this way. Existing finite-displacement rules can then resolve bounded
indices such as `i & 1`. An unbounded index, including an unconstrained
memory-carried string-loop counter, still widens the final access and remains
partial even when the base pointer's provenance is recovered. A recovered base
is not evidence that every offset stays inside that object.

If that spill's entry pointer was split into smaller SSA atoms, recovery
requires contiguous low-to-high bits from **one** exact IDB `m_arg` register
location, not merely adjacent bits or two different formals. Only then does
the recovered pointee keep the `typed_entry` assumption and its current-frame
no-alias relation. Untyped fragments still stay unknown.

For `analyst_selected` binaries, a **separate unreviewed derived-static path**
may inspect a bounded set of exact same-binary direct callees. A scalar
return dependency is attached to the caller only when the callee's typed,
branch-free return analysis completes with no unknown provenance and every
call argument has an exact type-backed entry binding. Inspect
`flow_get_job.result.derived_call_returns`, page each
`derived_call_evidence` artifact with `flow_get_derived_call_evidence`, and
check `callee_closure.boundaries`. A proven zero-argument constant helper can
have an empty `argument_indices` set: this means no input taint reaches its
scalar return, **not** by itself that its memory effects are known. Inspect
`derived_call_evidence.memory_effects`: `none` requires a complete whole-callee
scan without any modeled load, store, call, or unknown effect. Only in that
case is caller memory havoc omitted; scalar call/spoiler uncertainty may still
make the overall job `partial`. `unknown` retains memory havoc. If optimization
removes the call, a clean return is only evidence about the optimized graph;
it is not evidence that the derived-call path handled a call.

A separate `derived_call_memory_writes` result can certify **one** branch-free,
typed output-pointer write at byte offset zero when the callee's exact Store
copies one typed scalar argument, all other Stores are local stack accesses,
and there are no Loads, unknown effects, or nested calls. The caller then gets
an evidence-bound synthetic Store after the Call instead of blanket memory
havoc. Page its `derived_call_memory_evidence` ID with
`flow_get_derived_call_evidence`; the page rederives the proof from both owned
snapshots and the bound call metadata. Other call effects, multiple writes,
arithmetic outputs, indirect output-pointer writes, and scalar spoilers remain
unresolved.

The same result can separately certify **one fixed-global scalar write** by
an exact same-binary direct callee. Its data must be a proven typed argument
slice (including a checked zero-extension) or constant; other external
Stores, external Loads, branches, nested calls, and unknown effects are
rejected. Exact current-frame stack accesses may be tolerated only when
independently modeled. The caller gets one synthetic Store at the proven
global address; `memory_effects=none` is **not** claimed. Page the
`derived_call_memory_evidence` artifact to rederive the fixed-global proof.
Scalar return/spoiler uncertainty may still make the whole job `partial`.

A native direct `m_call` with a `mop_v` target can bind the target address even
when `mcallinfo_t.callee` is unavailable. The snapshot records this as
`call_target_from_direct_operand` information. A conflicting target is left
unresolved with `call_target_conflict`; `m_icall` and non-global targets are
never promoted by this rule. A resolved target alone does not prove argument
bindings or a derived return. This operand distinction follows the
[Hex-Rays microcode call example](https://hex-rays.com/blog/whats-new-in-the-ida-domain-api).

Separately, an `analyst_selected` `m_icall` may have a **bounded derived scalar
return** when its SSA target is a complete set of at most eight address-of
function values through exact Copy/Phi/Select or byte-concatenation structure.
Every candidate must be an exact same-binary local function entry with a
same-scope typed scalar return certificate. The caller joins the candidates'
argument bit windows into its actual CallResult; high-only source bits are not
silently promoted to a narrow formal argument. The proven dispatch target is a
control dependency of that result, so choosing between constant-return
callees is not reported as clean when the selector is tainted. Inspect
`callee_closure.finite_target_sets`, `derived_indirect_returns`, and page each
`derived_indirect_evidence` ID via `flow_get_derived_call_evidence`. The page
replays the target-set and every callee-return proof. Unknown target inputs,
cycles, budget limits, a missing/stale candidate, recursion, or an unproved
callee retain an unknown call boundary. This rule does not derive indirect
output-pointer writes or make an unreviewed callee a reviewed summary.

Loop predicates may have an evidence-bound `loop_feedback` control relation to
their own static SSA node. Its finite label fixed point represents dependence
of later loop iterations on an earlier predicate evaluation; the old blanket
`self_control_dependency_unresolved` status is not needed when this relation
converges. This does **not** prove termination or path feasibility. Closed
loops, incomplete exits, and exhausted budgets remain `partial`.

This is **not** a packaged reviewed summary or blanket proof of call effects.
Unless the explicit `none` certificate is present, the caller's Call still
havocs memory. Incomplete indirect, external, recursive, or otherwise unresolved
calls retain
unknown effects. An empty derived-effect list is not evidence of safety.

- `normal` identifies the native Hex-Rays observation path for the exact
  recorded configuration.
- `fallback` is a separate evidence path. RV32 remains partial and unverified;
  never merge it into normal evidence or label it fully supported.
- `partial` and `unknown` are soundness states. Preserve unresolved calls,
  memory effects, paths, and unsupported operations in downstream reports.
- Information-level extraction diagnostics remain visible on the snapshot but
  do not by themselves downgrade SSA or memory semantics. Unsupported
  diagnostics and actual unknown effects still require `partial`/`opaque`.
- `complete_in_scope` means the modeled computation finished; it does not turn
  an edge marked `may_alias` into a definite alias or data-flow proof.
- Instruction-derived SSA evidence copies only the native EAs observed on its
  cited snapshot instruction. Synthetic/no-origin evidence may have no EA, and
  optimized-away native origins are not reconstructed.
- For `analyst_selected`, a selected `routing.profile_id` means the current
  configuration is eligible, not that Hex-Rays extracted this binary.
  `supported_profiles` stays empty and analysis features stay `unverified`;
  inspect the exact completed `flow_get_job` result before claiming a current
  observation. A queued or failed job is not support evidence.
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

The **implementation-completion** scope approved on 2026-09-23 uses actual
IDA 9.3 static/GUI evidence, the 16 required profiles plus four format rows,
support-receipt audit, package/build-ID parity, retained regressions, and
independent final review. Provisioning a protected Linux runner and producing
an official licensed 5-warmup/30-measurement benchmark receipt are **not**
implementation-completion requirements. A local Mac timing result remains
diagnostic, not a Linux benchmark pass.

The separate tag/manual `flow-release` workflow is a stricter distribution
gate. It retains the protected licensed runner and frozen Linux benchmark checks;
without those inputs it must fail closed and must not produce a verified
release aggregate. A passing implementation audit must not be described as a
passing distribution release gate.

- Run focused support-audit tests before the full suite.
- Require Ruff, scoped Pyright, compileall, sdist/wheel builds, and isolated
  wheel imports.
- Verify build-ID parity across every process mode actually exercised.
- If running the separate distribution gate, aggregate protected licensed-IDA
  results without exposing credentials to untrusted jobs.
- Treat `record_flow_licensed_normal.py` as a content/binding validator, not a
  standalone clock or provenance authority. Temporal freshness comes from the
  protected workflow producing the P0 and semantic matrices in the same job;
  never copy archival receipts to a new directory and label them a current run.
- Retain receipt inputs, source digests, named limitations, and
  `target_executed: false`; do not delete or weaken evidence to make a gate pass.
- Require current normal evidence for each of the 16 mandatory profiles in
  `profiles/flow-release-scope.json`. RV32 is an optional, partial fallback,
  never a passing normal receipt. For the separate distribution gate, a fallback
  for any **required** profile, skip, empty required profile list,
  stale/unbound receipt, missing benchmark, or absent permitted GUI-process
  observation still blocks its release aggregate.

If IDA, a processor/decompiler module, license entitlement, or GUI acceptance
is unavailable, report that exact blocker and leave the corresponding claim
unverified.

## Large trace items

`flow_trace_forward` and `flow_trace_backward` return structural reachability,
not an automatic source-to-sink or vulnerability verdict. Continue an active
trace with `flow_continue_trace(trace_id, expected_revision, cursor,
request_key)` using the IDs from the previous page.

When one node has too many selected relations for a bounded response, its
trace item has `edges_externalized` **instead of** an inline `edges` list. The
reference names the immutable `graph_artifact`/`graph_digest`, `node_id`,
`direction`, `edge_kinds`, `edge_count`, and `edge_ids_digest`. Page that
artifact with `flow_get_graph` until `next_cursor` is null. Keep edges of the
listed kinds whose `source` matches `node_id` for forward traces or whose
`target` matches it for backward traces; the count and digest bind the complete
set. `edge_ids_digest` is the project's `sha256-v1` digest of canonical JSON
for the lexicographically sorted selected `edge_id` strings. This is output
externalization only: traversal still visits every selected
relation and preserves unresolved/opaque status. Do not treat absent inline
`edges` as zero edges or as evidence of a safe path.

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

## Opt-in symbolic refinement (experimental)

`flow_refine_path_proof` and `flow_refine_memory_proof` replay a v1 baseline
and then run only the explicitly requested symbolic tiers. Submit with the
same artifacts a v1 proof uses, plus a complete `refinement` object such as
`{"schema_version": 1, "symbolic_path": true, "symbolic_memory": false,
"solver_timeout_ms": 5000}`. All fields are required on the wire; tiers stay
off unless explicitly true. An all-off refinement
carries the v1 baseline verbatim (same digests, status, unresolved) with
`solver_not_invoked`; the solver never runs by default. Poll
`flow_get_job`, cancel via `flow_cancel_job`, and page the refined artifact
with the submitting tool's `artifact_id` mode, exactly like v1 proofs.

Refined artifacts (`flow-refined-path-artifact/1`,
`flow-refined-memory-artifact/1`) record the original/baseline digests, the
refined verdict with engine versions and solver stamps, the baseline/refined
agreement (`consistent`, `refined`, or `contradiction`), and evidence links.
Witness integers are hex-encoded so any width stays wire-safe. An optional
`proof_artifact` cross-checks a quoted v1 original (mismatch refuses); optional
`inline` entries splice explicit callee bodies by artifact reference with exact
parameter/return/argument node IDs. No ABI inference happens: the caller
asserts the mapping and the fragment records it. Refinement needs the
z3-solver extra; without it, requested tiers return unknown with
`solver_unavailable` while the baseline stays intact. Wire v2 graphs are
refused explicitly until the symbolic layer gains tagged-int plumbing.

Profile recommendation: keep both refinement tools in the read-only profile.
They are static, additive (no existing tool path changes), and solver-free
unless a request explicitly opts in.

Environment note: the solver runs in the Python executing the tools.
Headless idalib workers inherit the launch environment, so installing the
`solver` extra (or `--with "z3-solver>=5.1,<6"` for `uvx`) enables the
tiers there. A GUI-plugin deployment instead uses IDA's configured Python
(`idapyswitch` on macOS); if `z3-solver` is not installed there, requested
tiers degrade to `solver_unavailable` without touching the baseline.
