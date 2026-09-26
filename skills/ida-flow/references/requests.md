# Flow request examples

These JSON objects are MCP `tools/call` **params** (`name` and `arguments`);
the client supplies the transport envelope. Replace angle-bracket placeholders
with actual returned IDs. All examples use the supervisor's `database` argument.
They show v1 requests; do not strip tags from v2 artifacts to imitate them.

## Open, extract, inspect

First copy the input into a disposable directory. This explicit profile/ABI
example applies to the repository's x64 ELF fixture, not arbitrary binaries.

```json
{"name":"idb_open","arguments":{"input_path":"/absolute/disposable/typed_fixture.elf","mode":"force_headless"}}
```

```json
{"name":"flow_get_capabilities","arguments":{"database":"<session.session_id>"}}
```

```json
{"name":"flow_create_snapshot","arguments":{"database":"<session.session_id>","function":"sum_point","profile":"X64-LE","abi":"sysv-amd64","routing_mode":"analyst_selected","request_key":"snapshot-1"}}
```

```json
{"name":"flow_get_job","arguments":{"database":"<session.session_id>","job_id":"<submitted.job_id>"}}
```

Poll to terminal `complete`. On any other terminal state, stop this branch and
report the diagnostic; do not use example IDs as if they were results.

```json
{"name":"flow_get_function_ssa","arguments":{"database":"<session.session_id>","artifact_id":"<snapshot.result.ssa_artifact>","limit":50}}
```

```json
{"name":"flow_get_cfg","arguments":{"database":"<session.session_id>","artifact_id":"<snapshot.result.ssa_artifact>","limit":50}}
```

## Seed a value, or explicitly seed pointee bytes

Choose one based on the analyst's source evidence. A Load value is not the
pointer's entire pointee. Names and numeric offsets alone do not prove input status.

```json
{"name":"flow_create_implicit_analysis","arguments":{"database":"<session.session_id>","ssa_artifact":"<snapshot.result.ssa_artifact>","seeds":[{"node_id":"<selected Load node_id>","labels":{"explicit":["INPUT"],"control":[],"unknown_provenance":false,"any_explicit_source":false,"any_control_source":false}}],"request_key":"value-source-1"}}
```

This alternative explicitly assumes a valid non-null singleton view without
assuming disjointness. Use it only when that assumption is justified, or choose
`require_program_derived_exact` and accept failure if the relation is unavailable.

```json
{"name":"flow_create_implicit_analysis","arguments":{"database":"<session.session_id>","ssa_artifact":"<snapshot.result.ssa_artifact>","seeds":[{"kind":"pointee_range","schema_version":1,"pointer_node_id":"<selected pointer node_id>","interval":{"start":0,"end":8},"labels":{"explicit":["INPUT"],"control":[],"unknown_provenance":false,"any_explicit_source":false,"any_control_source":false},"binding_mode":"analyst_assumed_exact","point":"after_pointer_definition"}],"request_key":"pointee-source-1"}}
```

After polling that job to completion, use its returned bound SSA/graph for
further analysis. Page both the certificate and the implicit facts completely.

```json
{"name":"flow_get_pointee_evidence","arguments":{"database":"<session.session_id>","artifact_id":"<implicit.result.pointee_certificate_artifact>"}}
```

```json
{"name":"flow_get_implicit_analysis","arguments":{"database":"<session.session_id>","artifact_id":"<implicit.result.implicit_artifact>"}}
```

```json
{"name":"flow_explain_implicit_analysis","arguments":{"database":"<session.session_id>","artifact_id":"<implicit.result.implicit_artifact>","observation_node_id":"<observed Store or Return node_id>"}}
```

## Trace continuation

Start from IDs belonging to one selected analysis. For a bound pointee graph,
use that graph and its own snapshot identity, not nodes from the original graph.

```json
{"name":"flow_trace_backward","arguments":{"database":"<session.session_id>","snapshot_artifact":"<snapshot.result.snapshot_artifact>","graph_artifact":"<selected graph_artifact>","source":{"kind":"value","node_id":"<selected graph node_id>"},"request_key":"trace-1","limit":50}}
```

Replace `1` with the returned revision, including its tagged form for v2. Do not
increment it yourself or reuse a request key for a different continuation.

```json
{"name":"flow_continue_trace","arguments":{"database":"<session.session_id>","trace_id":"<trace.trace_id>","expected_revision":1,"cursor":"<trace.cursor>","request_key":"trace-next-1","limit":50}}
```

## Conditional Store proof

Select a Store and base node from one SSA artifact. The offset below is an
illustration, not an inferred type layout or platform-specific callback rule.

```json
{"name":"flow_check_store","arguments":{"database":"<session.session_id>","ssa_artifact":"<selected ssa_artifact>","store_node_id":"<Store node_id>","base_node_id":"<base node_id>","byte_offset":16,"target_function":"<exact target function name or address>","request_key":"store-1"}}
```

Poll the submitted job, then use **only paging arguments**:

```json
{"name":"flow_check_store","arguments":{"database":"<session.session_id>","artifact_id":"<store.result.store_evidence_artifact>","limit":50}}
```

`proven_in_scope` is conditional on the Store being reached and on the recorded
assumptions. It does not prove later non-overwrite or callback execution.

## Path/refinement

Construct an entry-rooted successor sequence from the actual CFG. Replace the
illustrative `[0,1]`; copy bindings from metadata exactly. `ruleset_digest`
comes from metadata's `rule_digest`. The final block is reached, not executed.

```json
{"name":"flow_check_path","arguments":{"database":"<session.session_id>","graph_artifact":"<selected graph_artifact>","path":{"schema_version":1,"blocks":[0,1],"bindings":{"snapshot_id":"<metadata.snapshot_id>","graph_digest":"<metadata.graph_digest>","profile_digest":"<metadata.profile_digest>","ruleset_digest":"<metadata.rule_digest>","summary_digests":["<metadata.summary_digest>"]}},"request_key":"path-1"}}
```

If explicitly requested, use that **same v1 graph and selector** for angr
refinement after the operator configures the sidecar. Do not copy a selector
from another graph, database or source overlay.

```json
{"name":"flow_refine_path_proof","arguments":{"database":"<session.session_id>","graph_artifact":"<selected graph_artifact>","path":{"schema_version":1,"blocks":[0,1],"bindings":{"snapshot_id":"<metadata.snapshot_id>","graph_digest":"<metadata.graph_digest>","profile_digest":"<metadata.profile_digest>","ruleset_digest":"<metadata.rule_digest>","summary_digests":["<metadata.summary_digest>"]}},"refinement":{"schema_version":1,"symbolic_angr":true,"solver_timeout_ms":5000,"loop_bound":8},"request_key":"refine-path-1"}}
```

Poll the job and page `refined_path_proof_artifact` using the same tool's
`artifact_id` mode. Preserve baseline/refined agreement and unresolved reasons.
Memory refinement separately replays matching SSA/plan/result Load/Store facts;
it does not call an alias-narrowing solver.

All three artifacts and the selected nodes below must come from the same
analysis lineage. Reuse metadata from its graph to construct the selector.

```json
{"name":"flow_refine_memory_proof","arguments":{"database":"<session.session_id>","ssa_artifact":"<selected result.ssa_artifact>","memory_plan_artifact":"<selected result.memory_plan_artifact>","memory_result_artifact":"<selected result.memory_result_artifact>","path":{"schema_version":1,"blocks":[0,1],"bindings":{"snapshot_id":"<metadata.snapshot_id>","graph_digest":"<metadata.graph_digest>","profile_digest":"<metadata.profile_digest>","ruleset_digest":"<metadata.rule_digest>","summary_digests":["<metadata.summary_digest>"]}},"load_id":"<Load node_id>","store_id":"<Store node_id>","refinement":{"schema_version":1,"symbolic_angr":false,"solver_timeout_ms":5000,"loop_bound":8},"request_key":"refine-memory-1"}}
```

Poll and page its `refined_memory_proof_artifact` with this tool's `artifact_id`
mode; `evidence_only` is intentional, not a failed alias proof to retry with
larger solver budgets.

## Graph identity and cleanup

```json
{"name":"flow_get_graph_digest_bytes","arguments":{"database":"<session.session_id>","artifact_id":"<selected completed graph_artifact>"}}
```

Decode each base64url chunk and follow `next_cursor`; verify offsets, total
length and digest before parsing. Hash the v2 wrapper too. Ordinary graph
pages or a prefix of the export cannot substitute for the complete preimage.

Close only after every required job/page is finished:

```json
{"name":"idb_close","arguments":{"database":"<session.session_id>","save":false}}
```
