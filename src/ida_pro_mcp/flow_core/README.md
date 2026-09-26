# SDK-independent flow contracts and analysis

This package implements bounded scalar SSA/provenance, byte-memory, synthetic
heap-lifetime, implicit-flow and path analysis, with public tool integration in
`ida_mcp/api_flow.py` and its adapters. The experimental runtime also exposes
reviewed-call compositions, explicit pointee sources and bounded Store evidence.
Opt-in angr path refinement is X64-only; memory refinement is evidence-only,
not an additional symbolic memory engine. Unknown effects remain explicit.

Importing this package does not make a public capability available. Support is
conditional on the exact reviewed profile, ABI, format, IDA/Hex-Rays build and
evidence route—not blanket ISA, allocator, library or vulnerability support.
See the canonical [operator guide](../../../docs/flow-operator.md),
[compatibility matrix](../../../docs/flow-compatibility.md) and
[installation guide](../../../docs/flow-installation.md) for current usage and
limits. G002 extraction receipts and G003 fixtures alone are not engine proofs.

- `serialization.py`: exact typed decoding, strict fields, canonical JSON and
  domain-separated IDs. JSON objects sort keys; arrays retain their order.
  Label/candidate sets are represented as sorted unique tuples in Python and
  arrays on the wire. Ordered operand/input/program tuples retain semantic order. A digest is
  of the complete representation, not an ISA-equivalence claim.
- `contracts.py`: ID-free structured microcode input, snapshot configuration,
  structural node keys, evidence, graph relationships, source selection and
  independent result axes. Native instructions are not re-lifted here.
- `states.py`: fixed-width Const/Top, explicit/control/unknown provenance,
  candidate/Top pointers, byte intervals, disjoint memory cells, and independent
  possible-liveness/escape components. Only specified joins are provided;
  no transfer, alias decision, strong update or widening algorithm is implied.

`SnapshotIdentity.input_digest` hashes `FunctionInput` **before** derived IDs
exist. Snapshot IDs hash namespace, binary/semantic fingerprints, function,
selected maturity, profile/rule/summary/policy digests and extraction environment.
Nodes use that snapshot plus a structural site or synthetic discriminator. EAs
are evidence and cannot identify nodes by themselves. Graph digests include the
whole validated graph and do not participate in snapshot/node identity.

Namespace strings represent an owner identity but are not authentication.
The storage/runtime boundary verifies ownership and pre/post extraction
semantic fingerprints; these data models alone do not. Config digests are
syntax-validated references; their actual profile/rule content must be verified
by the consuming registry. These
models cannot authenticate supplied hashes or prove the IDA CFG is complete.

`Graph` rejects duplicate identities and dangling nodes/evidence/phi/memory
references. Memory ranges are nonempty, nonnegative object-relative byte ranges;
pointer displacements may be signed. Unknown bounds are explicit (`None`).
`MemoryState` only represents disjoint materialized cells; overlapping writes
must be partitioned by the memory engine, not silently overwritten here.
`Graph.validate_source` checks snapshot ownership identity and target references
before value/memory seeds may be used. It is not an access-control mechanism.

Internal snapshot/graph contracts use schema version 1; this is distinct from
the public wire encoding. The runtime supports `flow-wire/1` and opt-in
`flow-wire/2` for lossless wide integers, as described in the operator guide.
Unknown versions and unknown fields fail closed. Nested state records obtain
their version from the model envelope. Standalone state serialization is intended
for internal unit tests. Changing record fields requires an explicit
schema/migration decision.

Run `uv run pytest tests/flow_core -q`. The unprivileged `flow-core-tests` workflow
runs these tests and wheel import isolation without IDA imports or secrets.

## Canonical collection order (required, not silently normalized)

Frozen constructors and JSON decoders reject unsorted or duplicate semantic sets.
Graph nodes/evidence/edges/objects/versions sort lexically by their respective
stable IDs. Evidence sites sort by `(block_index, instruction_index, operand_path)`;
origins, assumptions, evidence-ID references and reaching-definition IDs sort
lexically. Assumptions are a conjunction/set, not an ordered proof program.
Phi inputs sort by predecessor index. Memory cells sort by
`(object_id, version_id, address_space, interval.start, interval.end)` and remain
disjoint per object/version/address-space. Labels, pointer candidates and
liveness sets retain their explicitly checked canonical ordering.

Operands, nested expression children and `Node.inputs` are ordered operands,
not sets: swapping subtraction operands changes meaning and the digest. Block
and instruction arrays retain consecutive program/index order. Producers must
sort set-like collections before constructing a model. Thus reversed semantic
sets cannot be accepted as a second differently hashed representation.

## Pointer nullness and node shape

`PointerValue.may_be_null` is independent of the non-null location component.
Empty candidates with `may_be_null=True` and `any_compatible_location=False`
represent exact null. Candidates plus null represent their union. Top ranges
over compatible **non-null** locations, and may independently include null.
An empty, non-top, non-null value is rejected (no implicit bottom state). Join
unions candidates, propagates Top, and ORs nullness. Pointer arithmetic and null
dereference behavior remain transfer-analysis responsibilities.

Arity is validated without executing semantics: Constant/InputValue/InputMemory
have no value inputs; Copy/Unary have one; Binary/Compare two; Select three;
Free one pointer input; Return/Branch zero or one. InputMemory/Load/Store require
a memory reference and a width equal to its byte interval. Store's first input
is the stored value; any further inputs carry ordered address/effect operands.
Load may have no value input when its memory reference directly identifies the
location; otherwise inputs carry address-selection dependencies. Other kinds
cannot carry a memory payload. Call and Allocation have variable arity;
call/ABI semantics are checked by the consuming analysis contracts. UnknownValue/OpaqueEffect may retain known
inputs so partial understanding does not discard provenance. Type/width meaning
of pointer/value input nodes beyond these structural checks is a later gate.

Phi mappings intentionally exist in both nodes (predecessor-tagged operand
selection) and edges (uniform dependency traversal). Every mapping must have
exactly one matching `phi_input` edge, including predecessor, and vice versa;
distinct evidence or axes do not justify duplicate mappings.

Direct `from_data` and JSON decoding both reject cyclic/excessively deep input
with `ContractError` rather than exposing a Python recursion failure.

## Historical milestone notes (G005–G009)

The following sections preserve design decisions and evidence boundaries at
those milestones. Statements about deferred integration or later stages describe
that milestone, not the current public feature set summarized above.

## G005 unreleased v1 extraction extension

Before release, the v1 input schema was consistently extended for real SDK
extraction: operand roles/native kinds, widthless void/unknown forms, global
locations, nested EA/synthetic evidence, typed CallInfo/LocationSet/Diagnostic,
and CFG successors with symmetry validation. This is not a compatibility claim
for earlier serialized v1 documents. Call location sets use SDK byte locations,
not guessed native-register names; full call type/argloc and memory effects may
remain explicitly unresolved. Callinfo structural child paths enumerate ordered
arguments followed by return operands. No transfer rules or public tool become
available merely because these input forms can be represented.

G005 format-guard correction: Environment requires a finite `format_id`
(ELF/PE/Mach-O/raw) and nonempty `platform_tag`, both included in snapshot
identity. The adapter validates IDA's structured loader filetype against the
selected measured profile and records the profile's build provenance. These
metadata do not independently authenticate arbitrary binary calling conventions.

## Scalar SSA and explicit analysis (G006)

`cfg.py` computes reachability, dominators, immediate dominators and dominance
frontiers over the recovered CFG. `ssa.py` partitions storage ranges at observed
bit boundaries, places phi nodes using iterated dominance frontiers, and renames
via a deterministic dominator-tree traversal. Entry storage atoms are explicit
InputValue nodes. Partial writes affect only matching atoms; `extract:N` and
`concat_low` express bit slices without CPU-native rewrite rules. A definition
certificate validates dominance, ordering and phi-edge availability. Unreachable
blocks are diagnosed. Entry backedges without a preheader and resource limits
are explicit ContractError refusals, not successful no-flow graphs.

The only opcode tables are structured **microcode** operations shared by every
profile. Integer arithmetic is modular; explicit extension/truncation is applied
once. Scalar, branch, phi/select and overwrite fixtures have independent tests.
Calls, global operands, loads/stores and unknown effects remain partial. Loads
and stores carry deliberately unresolved memory objects, not alias/content
analysis results. Calls conservatively havoc tracked storage; unknown stores
havoc potentially exposed non-register storage. Unsupported operations preserve
known inputs and conservatively havoc locations instead of inventing clean data.

`analysis.py` keeps seeds out of node identity. Its result/cache identity includes
graph, canonical source and policy digests. Explicit/control labels are distinct;
a select's condition uses a control edge and does not become explicit payload
provenance. This is not implicit-flow analysis. The fixed point uses an internal
absent-fact bottom, then Const/Top joins; unresolved published facts are never
represented as clean bottom. On evaluation exhaustion the unfinished frontier
and descendants receive Unknown/AnySource and the result remains partial.

There is no ABI argument-number inference or synthetic function-return inference
for G005 anchors. `entry_storage` names concrete snapshot-local storage atoms.
The anchor receipts select one documented entry-storage site and the explicit
zext output only. Their memory/call-boundary status stays partial. They are pure
replay/integration receipts, not new IDA runs or independent memory proof.

UnknownValue may carry `width_bits=None` when extraction supplies no width.
It retains a diagnostic rule and Unknown provenance; the builder never invents
one-bit data to stand in for an unknown-width global/address value. Sized uses
must obtain their own validated width or remain an explicit unknown boundary.
The versioned scalar-transfer ruleset is part of ScalarPolicy and its digest;
future semantic changes require a ruleset version change before cache reuse.

The scalar-transfer-v2 policy validates shift-count support before inspecting
the payload. Counts outside `[0,width)` or Top counts retain labels but produce
Unknown/partial for shl/lshr/ashr; a symbolic payload with a valid constant count
remains supported Top. The policy revision prevents reuse of v1 cached results.

## Byte-range memory analysis (G007)

`memory.py` constructs a seed-independent logical memory plan: one static token
chain per CFG path, Store/unknown-effect definitions and predecessor-tagged
MemoryPhi joins (including loop backedges). These memory-order relationships
are not data provenance. `memory_analysis.py` separately computes byte contents,
pointer candidates and memory-data dependencies; each dependency has its own
rule, source/target evidence, object/range and precision. Unknown ranges use
`None` plus opaque precision, not a fabricated interval.

Objects have explicit stack/global/argument/unknown kinds, optional extents,
and separate singleton and disjoint-identity evidence. Different argument names
alone do **not** prove non-aliasing. Initial source labels and later effects are
conservatively visible through possible alias objects. Only exact singleton
locations/ranges without unresolved address conditions allow strong updates.
All other stores preserve previous possibilities. Memory labels and address
selection labels remain separate; a memory-order token never labels an entire
object or all later reads. Pointer values can be stored/reloaded without tainting
their pointees. Partial/incompatible pointer overwrites become unknown pointers.

Value/node seeds, pointer seeds, initial memory seeds and object proofs are
explicit, canonical inputs. The result cache key includes the immutable plan,
all source/object inputs and the memory policy. Proof strings are analyst/model
assumptions, not authenticated claims or vulnerability verdicts. Optional flat
segment assumptions must be named. Unresolved segments otherwise widen accesses.
Exact-null, nullable candidates and unknown addresses remain explicit boundaries.

`build_ssa(..., storage_model="memory")` additionally lowers direct structured
stack/global operands to memory operations using object-relative stack offsets
and extracted global addresses. This is independent of CPU family. It does not
reinterpret native instructions. Call target global addresses are **not** global
data reads. Scalar mode remains the G006 contract. Storage model appears in the
SSA envelope and memory-mode node keys are distinct. Indirect microcode roles
are explicit: ldx left=segment/right=address; stx left=data/right=segment/
destination=address. Missing/ambiguous roles are errors, not positional guesses.

Iteration, byte, label and pointer-candidate limits widen with diagnostics.
Unfinished results preserve an Unknown/AnySource frontier. Widened stores do not
advertise strong-update precision. Loads after unknown writes/calls see actual
havoc in byte/default state, not merely a warning. Allocation/free remain opaque
lifetime boundaries for G008; no heap lifecycle claim is made here.

Native fixture receipts and their explicit query assumptions are documented in
`tests/flow_fixtures/MEMORY_EVIDENCE.md`. They preserve G005 extraction limitations
and do not advertise public tools or complete architecture support.

MemorySeed explicitly names the `entry` program point: it initializes the plan's
unique entry token, not all versions of an object. Unknown candidate offset
`None` denotes a location still identified with that object; unreviewed pointer
arithmetic instead widens to any compatible object. A concrete negative/out-of-
extent address cannot reuse the original object's disjoint proof: affected
memory widens across compatible registered objects and remains partial.

`range-memory-v2` treats pointer add/sub by zero as identity in the binary
address domain (not a claim that C null-pointer arithmetic is defined).
A nullable pointer with a nonzero displacement widens to compatible nullable
Top, never unchanged exact null. Full-width displacements use their signed
modular representative. Unresolved stores with no candidate still havoc every
compatible registered object and retain data labels and write evidence.

Memory value seeds accept sized Constant/InputValue/Copy/Unary/Binary/Compare/
Select/Phi/Load/UnknownValue/Call/Return nodes. Store, Branch, OpaqueEffect and
void returns are rejected: use MemorySeed for contents, or select the Store's
explicit data input node. Seeds are never silently discarded. The v2 policy
revision invalidates v1 cache identities for these changed semantics.

## Explicit synthetic heap/lifetime lane (G008)

`heap.py` builds a seed-independent HeapPlan over a validated SSAProgram.
Only explicit `Allocation` and `Free` node kinds are lifetime operations:
allocator-looking Call names are not recognized. Allocation has a pointer-width
result and zero/one positive-or-unknown scalar size operand; Free has one
pointer input and no result. Load/Store create readonly lifetime-access
observations using their explicit address role. OpaqueEffect `heap_use` and
`heap_escape` each require one pointer and no result. `heap_opaque_reachable`
records explicit pointer roots but conservatively affects all compatible heap
objects and escaped objects: it does not yet prove transitive reachability. Ordinary opaque operations and Calls remain unmodeled global
heap effects.

Objects have `kind="heap"`; identity is a digest of snapshot-local allocation
node plus ordered explicit context (maximum eight components). There are no
per-iteration objects or implicit call-context inference. A site defaults to
`singleton=False`: allocation/free are weak joins, retaining older possible
instances. Singleton requires a OneShotProof assumption record in the plan, and CFG-cyclic
sites reject it. The evidence string is not a mathematical proof; the acyclic
check alone does not establish single execution across calls. Changing only a
MemoryObject flag cannot bypass that declared assumption. These are explicit
synthetic model assumptions, not evidence that a binary malloc site executes once. A singleton seed cannot claim it was already allocated
before that one-shot modeled execution.

The liveness set and escape axis remain independent. A successful one-shot
allocation moves not_allocated→live; exact live singleton free moves live→freed.
Nullable/multiple-candidate/summary free preserves possible live and freed.
Nonlive or unknown frees stay unresolved and conservatively widen. Escape
changes only escape, so live+escaped remains representable. Opaque effects widen
liveness/escape instead of inventing a definitive ownership outcome. Read/use
observations retain the lifetime at that program point without changing it.
No memory bytes are cleared, resurrected or otherwise mutated by this lane.

`heap_analysis.py` computes a finite CFG/HeapPhi fixed point. Results record
before/after transitions, pointer candidates, evidence, precision and unresolved
boundaries—not automatic findings, CWE categories or severity. Branch may-free
joins retain live/freed alternatives with the escape axis intact. Loop/recursive
site summaries do not turn previously freed instances definitely live again.
Address disjointness does not establish unreachability: a root object may store
a pointer to another disjoint local object. Without an independently validated
transitive points-to/reachability model, reachable opaque effects include all
compatible heap objects and escaped objects. Allocator names grant no exclusion.

HeapPointer seeds apply only to explicit InputValue/UnknownValue nodes and
HeapSeed states apply at entry. Cache identity includes plan, seeds and nullable/
budget policy. Context/event/phi-input build limits refuse explicitly; iteration,
event-visit, object-state evaluation and candidate limits produce partial
Unknown frontiers without creating runtime-count identities. Final states join
reachable exit states (or reachable block outputs when no exit is recovered);
this does not prove execution termination. Pointer facts are widened when the
analysis frontier is incomplete. Real allocator recognition, real-binary heap
validation, function summaries and combined byte/lifetime execution remain later
integration gates; G008 makes no public capability available.

The synthetic-heap-v2 policy, explicit-heap-events-v2 plan rules and
synthetic-lifetime-transfer-v2 observations invalidate earlier cached semantics.
UnknownValue is an opaque all-heap effect only for the builder's current
`unsupported_opcode:` prefix or exact `unknown_memory_width` code, matching the
byte-memory effect classifier. Ordinary unknown inputs, operand/value-width
limitations and synthetic `unmodeled_memory_or_call_effect` value placeholders
are not extra heap mutations: their originating Call/unknown-write event already
carries the effect. New effect encodings require explicit classifier review.

## Private persistence and worker reference runtime (G009)

`runtime_contracts.py`, `persistence.py` and `runtime.py` provide internal durable
jobs/traces; public flow job/query integration followed in G010. The filesystem
backend supports the verified POSIX permission/locking model. Other platforms fail with
`unsupported_permission_model` before filesystem mutation; Windows ACL/locking
support remains unverified. Pure core imports remain SDK-independent.

The host supplies a persistent owner namespace and unpredictable owner key from
trusted configuration. Neither a binary hash, IDB path nor session label grants
ownership. Owner keys must be retained by that host for restart; the store keeps
only their digest. A dedicated private root has a fixed format marker, 0700
directories and 0600 regular single-link files. Nonempty foreign roots, symlinks,
replaced directories and insecure modes are rejected. This guards the private
cache boundary, not a malicious same-UID process with arbitrary filesystem access.

SQLite is the metadata authority: initial empty version 0→1 bootstrap only,
unknown schema versions refused, WAL, foreign keys, FULL synchronization and
integrity checks. Namespaces, artifacts, jobs, traces, requests and pages carry
owner/scope bindings or reference scope-bound rows. Scope includes fingerprint,
binary/profile/rule/summary/policy digests. Changed context explicitly invalidates
old rows; terminal job state stays immutable with a separate stale flag. Old
views/replays fail rather than silently reattaching to another interpretation.

Immutable JSON is canonicalized, written to a same-directory exclusive temp,
flushed/fsynced, re-read, atomically renamed and directory-synced before SQLite
references it. Store writers and recovery share the SQLite writer transaction.
The low-level BlobStore helper is not a separate metadata publication authority.
Cleanup checks references across **all namespaces** and removes only owned
unreferenced temp/orphan files. Referenced history is never collected. A crash
between orphan unlink and metadata cleanup remains recoverable; missing/corrupt
referenced data fails closed. The upstream RPC output cache is never consulted.

Jobs use queued→extracting→analyzing→committing→complete, separate
cancel_requested→cancelled, and failed/stale/interrupted terminals. Atomic
state/owner checks prevent late completion from rewriting a terminal decision.
A process-held owner lease gates startup recovery and execution; extra metadata
views cannot become executors. Reopen marks nonterminal jobs interrupted. Safe
retry creates a **new** job ID, with the same handler/input and an explicit
retry_of link—never arbitrary computation resumption or terminal state reset.
Progress, budgets, errors and the last safe checkpoint are persisted. JSON null
is a valid committed job result, distinct from not supplying a result.

The executor accepts an immutable host registry of callables. Requests choose a
registered name and JSON input, not a command or module path. Host handlers must
validate their own DTOs/model context; SDK extraction handlers must be wrapped
for the IDA main-thread pump. `ctx.check()` cooperates with cancel/deadline and
`ctx.report()` records progress/checkpoints. Threads are daemon-owned by the
worker, not external subprocesses. Shutdown signals cancellation before trying
nonblocking metadata writes, waits a bounded grace period, and retires unfinished
leases. If a contended database prevents the terminal write, next-owner recovery
records interruption. Native/uncooperative code and kernel I/O cannot be forcibly
preempted by this reference thread executor.

A trace pins a validated snapshot+graph, tagged source, policy/scope/direction/
edge filter and immutable state with frontier/visited/emitted/pending/unresolved
IDs. Membership and snapshot bindings are checked. Traversal computation remains
G010; this layer commits the trusted traversal result atomically. The transaction
stores the complete response and new frontier before transmission. Same key and
canonical request replays the original committed page without advancing; changed
input or competing revisions conflict. Before-commit failure rolls back page and
frontier together; after-commit disconnect replays the committed response. This
is not exactly-once network delivery.

Page sizing matches `len(json.dumps(response))`, including default Unicode
escaping, not UTF-8 bytes. Multi-item pages target 16,000 serialized characters;
the hard maximum is 39,999, below the current RPC 50,000 threshold. Oversized
pages/items are rejected without advancing. Evidence uses explicit offset/length
chunks; no preview truncation substitutes for persisted content.

`ida_mcp/flow/runtime.py` is an internal worker factory. Busy state is pump busy
OR active leased flow jobs. Signals/finally invoke bounded cleanup, and database
switching is refused while active flow jobs exist. Adopted-worker detach and
supervisor shutdown still do not terminate persistent worker jobs; owned close
retains its existing worker-termination path. No unrelated worker/process is
stopped. The source diff is confined to these hooks and one equivalent lint fix.

Tests cover transaction/race/recovery/ownership/size/security cases, faked owned
close versus adopted detach, and SDK-blocked wheel imports. A fresh IDA 9.3
process passed the private factory/busy/job/replay/integrity smoke recorded in
`tests/flow_fixtures/manifests/runtime_smoke.json`. That is not a live HTTP flow
job-tool smoke: that integration was deferred to G010 at this milestone.

### G009 synchronization and admission fence

A Store now has an immutable per-handle scope binding. `invalidate_context`
changes the authoritative SQLite namespace context and stales existing rows; it
**does not rebind that Store**. Retire the old owner and explicitly open a new
Store for the new context. This prevents old in-flight inputs from being tagged
with a newly assigned context. All public validation, request construction and
publication run under the Store RLock; SQLite `BEGIN IMMEDIATE` revalidates the
binding, including when another Store instance performs invalidation. Close
signals immediately; an in-flight transaction rolls back before commit, then
releases its lease. Flock acquisition, recovery and integrity are all inside the
constructor cleanup guard, including exceptional recovery transactions.

The worker factory provides one fail-fast admission lock shared by configured
Runtime.submit, runtime configuration and `database_switch()`. The latter covers
open, activation, warmup and discovery/return in idb_open—not just a count check.
Submissions during a switch fail before job persistence. Switching is denied
while callbacks are unfinished, even if their keepalive lease expired. Idle-TTL
busy state still uses valid leases so an expired callback cannot keep a worker
alive indefinitely. Closing is signaled by an Event without waiting for the
admission lock; error paths release the fence.

Lock order is admission → short registry/runtime locks → Store RLock → SQLite.
Runtime.submit does not hold its runtime mutex during SQLite publication. Store
operations never call back into admission/runtime locks. Nonblocking shutdown
metadata attempts also use nonblocking Store-lock acquisition. Repeated barrier
tests exercise both same-handle serialization and peer-handle database fencing
for artifacts, graphs, jobs, traces, pages and idempotent request replay.

Runtime mutexes now protect only in-memory tuples/events and thread publication.
`cancel()` signals its event first, releases the mutex, then returns the actual
Store cancellation outcome (or propagates its failure). Expiry collection and
retirement occur under the mutex; durable finishing happens after release.
Submit publication and the closing decision share a short mutex, with Store
creation/state reads and abandoned-admission finishing outside it. Durable wait
lookups also occur outside that mutex. Factory initialization may hold admission
to prevent a DB switch, but never the registry mutex; shutdown does not wait for
admission. Late/failed initialization cleans up its Store outside registry locks.
Repeated barrier tests cover Store-contended cancel, submit, expiration and
factory initialization while shutdown(0) runs, plus idempotent submit retries.

## Experimental public surface (G010 and subsequent integration)

`query.py` supplies deterministic forward/backward **graph reachability**, not
seeded taint or feasible paths. Separate public APIs now expose memory analysis,
implicit analysis, path proofs, reviewed-call compositions, pointee-source
certificates, bounded Store evidence and opt-in refinement. Memory results and
their evidence are pageable; source selections must match the returned graph
and snapshot identities. Consult the operator guide for the current tool set
rather than the initial G010 inventory.

`flow_get_capabilities` reports route-specific availability and uncertainty;
`supported_profiles` is not universally empty and is not a blanket architecture
claim. Exact fixture routes and explicit analyst-selected routes have different
evidence boundaries, documented in the compatibility matrix.

The lazy worker adapter reads host IDB metadata through `idasync` and submits
registered analysis handlers to the job runtime. No MCP parameter chooses imports,
commands, a root, owner key, or a namespace. A private POSIX registry owns random database namespace IDs and a
random secret independently of binary hashes and paths. Paths index that private
registry but are not namespace IDs. The optional **host environment** override is
`IDA_MCP_FLOW_STATE_ROOT`; use a real absolute, non-symlink directory with mode
0700. Non-POSIX runtimes report unavailable. The registry is not a multi-user
access-control service.

RuntimeScope.fingerprint is now a **database-level** coarse invalidation fence
(binary digest, DB path, IDA change count/version, and product build digest), not
the function-specific Snapshot.semantic_digest. Snapshot and Graph artifacts
validate their own model identity and match namespace/binary/profile/rules/
summary/policy before their rows bind to the current DB scope. Multiple function
artifacts can coexist. Changed context requires explicit owner-lease invalidation
and reopen; existing artifacts/jobs/traces become stale, including after restart.
Paging and tracing load immutable stored artifacts after runtime context and
fingerprint checks; they do not re-extract the selected function on every query.
This coarse fence is not a cryptographic full-IDB fingerprint or a guarantee
that every semantic mutation is detected. Create fresh snapshots after relevant
database changes rather than treating another page read as renewed extraction
evidence. Optimizer-removed origins are not reconstructed.

Artifact cursors bind content, section/filter, and position. Trace cursors bind
trace ID and revision, with atomic request replay provided by G009. Entire trace
responses, including cursor/schema, are persisted before transmission. Evidence
larger than a page is exposed as reconstructible canonical-JSON text chunks with
offset/length/total_length, never a preview. All wire pages are measured using
`json.dumps` character count: target 16,000 and hard 39,999. Unknown boundaries
and analysis incompleteness are separate from frontier exhaustion. Cancellation
is cooperative; native generation cannot be forcibly preempted.

The flow-readonly profile excludes `idb_save`, Python, debugger, and mutation
tools. MCP trace netnodes may change the **working** IDB; close ephemeral sessions
with `save=false`. Static supervisor E2E is recorded by
`tests/flow_core/native_api_smoke.py`: two owned Mach-O copies, explicit external
`database` routing, job/artifact/trace/replay/conflict/cancellation, and adoption
then detach while the owning supervisor retains cleanup authority. Targets are
never executed. Standard `ida-mcp-test --mcp-mode --category api_flow` verifies
registration and capability discovery through the actual MCP transport.
