---
name: ida-flow
description: Use this fork's read-only IDA MCP flow tools for static SSA, analyst-selected taint, memory provenance, bounded path checks, and Store evidence. Use when the connected server exposes flow_* tools; not for debugger operations, IDAPython scripting, patching, or automatic vulnerability verdicts.
---

# IDA flow analysis

Analyze the requested function and analyst-selected sources using the connected
MCP server's actual tool schemas. Tool names below omit the client's namespace
prefix. This skill supplies instructions, not an MCP connection or IDA license.

## Establish scope

- Require the fork's `flow_get_capabilities` and `flow_create_snapshot`. If they
  are missing, report the connection/profile mismatch; do not invent tools or
  bypass the profile through Python/debugger operations.
- Use a disposable input/IDB copy. With the supervisor, open it using
  `idb_open(input_path=..., mode="force_headless")`; pass the returned
  `session.session_id` as `database`. Neither a path nor a preferred alias is
  authoritative. Do not close unrelated/adopted sessions as if you owned them.
- IDA 9.3 and the exact reviewed processor/ABI/format/build route are required.
  `exact_fixture` is for pinned fixtures. For another binary, use
  `analyst_selected` with explicit, justified `profile` and `abi`; do not guess
  a profile to evade a rejected route. RV32 has no normal route.
- Capability discovery is not proof of successful extraction. An analyst-selected
  route may still show empty `supported_profiles` and `unverified` features.

## Complete one bounded analysis

1. Submit `flow_create_snapshot` for an exact function entry. Keep v1 unless
   lossless large integers require `wire_version: "flow-wire/2"`.
2. Poll its exact `flow_get_job` ID until terminal. Only `complete` supplies
   usable result artifacts. On failed/stale/cancelled/interrupted or a local
   wait limit, report the state rather than inventing results or widening scope.
   If abandoning your own pending job, request `flow_cancel_job` before cleanup;
   cancellation is cooperative, so do not assume a native call stopped instantly.
3. Inspect returned SSA/CFG/graph/evidence artifacts. Follow `next_cursor` until
   null; one page is not a whole graph. Keep artifact IDs in the same database,
   snapshot, wire version and analysis lineage.
4. Choose the analysis from the table below. New jobs need polling and their
   own returned artifact IDs. Reuse a `request_key` only for an identical
   request; use a new key for changed arguments or the next trace operation.
5. Report the selected source, observed fact, evidence IDs, assumptions and
   unresolved effects. Separate `explicit`, `control`, `unknown_provenance`,
   alias precision and `partial`; none is an automatic safe/vulnerable verdict.
6. Finish paging before closing an owned test session with
   `idb_close(database=..., save=False)`. Targets are never run natively.

## Choose the right evidence

| Question | Tool and interpretation |
| --- | --- |
| What structurally depends on a value? | `flow_trace_forward` / `flow_trace_backward`; reachability, not seeded taint or path feasibility |
| Where does an analyst-selected input value flow? | `flow_create_implicit_analysis` with `{node_id, labels}`, then `flow_get_implicit_analysis` / `flow_explain_implicit_analysis` |
| Which entry-value bits are sources? | `kind: "bit_range"` for an `InputValue`; specify bit offset and width |
| Which pointee bytes are sources? | `kind: "pointee_range"` after a full-width entry pointer or acyclic pointer Load; explicit binding mode and byte interval |
| What memory access was modeled? | `flow_get_memory_analysis`; do not turn may-alias or unknown effects into no-alias |
| Does this Store write this function address? | `flow_check_store`; conditional Store-site evidence, not final registration, callback execution, or proof of reaching the Store |
| What call effects were composed? | `flow_get_derived_call_evidence` / `flow_get_call_compositions`; reviewed summaries are exact-identity scoped, not general library recognition |
| Can this CFG prefix be reached? | `flow_check_path`; entry-rooted blocks and exact metadata bindings, no caller-written equations; the final block is reached, not executed |
| Can the optional engine refine that path? | `flow_refine_path_proof` with explicit `symbolic_angr: true`; x64/v1 only, configured sidecar, unknown preserved |
| Can I quote a Load/Store pair's memory evidence? | `flow_refine_memory_proof`; evidence-only replay, no alias-narrowing engine |

### Select sources deliberately

A whole-value seed on a `Load` marks the value read there. A pointer's
`InputValue` labels its address, **not** every pointee byte. Input/control status
must come from the analyst's evidence, not an OS buffer name or field offset.

For `pointee_range`, choose `require_program_derived_exact` when the existing
analysis proves the non-null singleton relation, or explicitly justified
`analyst_assumed_exact` when it does not. The latter does not imply no-alias.
The source applies after that pointer definition, not to earlier reads or every
later write. Use the completed job's **new bound** `ssa_artifact` and
`graph_artifact`; page `pointee_certificate_artifact` with
`flow_get_pointee_evidence`. Seeded labels are in the implicit-analysis facts,
not a claim that every structural memory fact now carries the source label.

### Pagination and integer handling

- Trace continuation/cancellation uses its returned `trace_id`, `cursor`, and
  `revision` as `expected_revision`. Preserve a tagged revision as-is. Frontier
  exhaustion alone does not remove unresolved effects.
- For `edges_externalized`, retrieve the referenced edges/evidence through the
  graph and evidence tools instead of treating the absent inline list as empty.
- Reassemble `canonical_json_chunk` items in offset order and use a lossless
  JSON integer parser. A small v1 item can also be chunked because of wide values.
- Preserve v2 `{"$int":"..."}` integers; do not coerce them to JavaScript
  `Number` or strip tags to reuse v1 IDs. The refinement tools and reviewed-summary
  snapshot route currently reject v2. Report the limitation; do not narrow addresses.
- For an exact graph digest, use `flow_get_graph_digest_bytes`: decode base64url,
  concatenate all bytes, verify offsets/total/digest **before** JSON parsing.
  Identity v2 includes a domain/version wrapper. Oversized exports fail rather
  than supplying a truncated proof.

### Optional engine boundary

`IDA_MCP_ANGR_PYTHON` selects a separate interpreter configured by the operator.
Discovery's `configured_unverified` means files exist, not that angr imports or
the query succeeds. Do not install packages into IDA's interpreter automatically.
Only explicitly requested refinement launches the sidecar. Missing engines,
unrepresentable prefixes and unresolved states remain unknown; all-off refinement
retains the baseline. The retired in-process Z3/inline protocols are not fallbacks.

## Request reference

Use [request examples](references/requests.md) for concrete submission/paging
shapes. They are templates, not a script to run unchanged. In a repository
checkout, `docs/flow-installation.md`, `docs/flow-operator.md` and
`docs/flow-compatibility.md` provide installation and exact support boundaries.
