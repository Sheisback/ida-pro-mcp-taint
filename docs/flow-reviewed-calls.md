# Reviewed owned-fixture calls

The public `flow_create_snapshot` job selects a source-packaged immutable summary
catalog for the exact two repository-owned G011/G022 `call_heap` binaries (x86_64 and
AArch64 Mach-O). `flow_get_call_compositions` pages the resulting compositions.
The capability result advertises reviewed interprocedural semantics only when
that catalog matches the active runtime scope. Other binaries still expose
conservative call observations, not reviewed library support.

Selection uses binary SHA-256, the exact extraction-profile digest, IDA/Hex-Rays
builds, extractor rules and policy. At each direct call, bounded static callee
extraction must reproduce the reviewed baseline snapshot identity. Binding then
also checks callee RVA, calling convention and structural signature. Function
names are display metadata only; no name-based matching or user-supplied catalog
loading exists. Baseline namespaces are review identity salts, not authorization
to read another database's artifacts. Runtime artifacts retain the current
persistent database namespace and its scope checks.

The closure has a depth limit of 8 and a 64-function extraction budget, including
the root. Its visited RVAs and boundaries are returned in the snapshot job result.
Indirect, external/unreviewed, recursive, stale/missing and budget-limited targets
remain explicit Unknown/partial boundaries. A reviewed wrapper's declared effects
can compose even when its separately reported implementation closure contains an
external call; this does not model arbitrary allocator or library implementations.
The catalog digest fences runtime state and snapshots, each baseline snapshot
fences reviewed callee semantics, and the packaged runtime build digest covers
the catalog data and closure implementation.

## Scope and limits

- Identity, output, copy/fill/global and allocation/free **reviewed branches** are
  separate call-composition artifacts. They do not imply whole-program inlining
  or a complete interprocedural memory-SSA graph.
- Acyclic CFG blocks compose an explicit shared `CallState` in topological order;
  predecessor states are joined, not serialized in arbitrary block-number order.
  Exact SSA instruction evidence maps call arguments and results. Copy,
  bit-extraction/concatenation and exact non-overlapping stack spill/reload chains
  preserve allocation-result object identity into later calls.
- Entry-pointee objects are symbolic, nullable and not assumed disjoint from other
  observed objects. Output effects materialize byte ranges and SSA-entry
  provenance without asserting a concrete address or a definite write.
- Branches remain overapproximations; no null-test refinement is claimed. Free
  transitions preserve allocation object identity but stay weak when nullable or
  non-live possibilities remain. Loop/order gaps join and widen reachable-prefix
  state without inventing an order among unresolved calls. Unreachable calls are
  marked without evaluating summaries or importing unrelated state. Unknown pointer transforms,
  overlapping spills, aliasing writes and canonical unknown-memory effects
  lose precision/havoc. Pointer-width arguments with lost identity widen to
  nullable any-compatible pointers at unknown calls; narrower proven scalar
  arguments do not alone expose local heap. Non-stack pointer publication marks
  compatible heap escape unknown before subsequent opaque-call widening.
  No result is an automatic UAF, double-free or vulnerability verdict.
- Pinned native fixtures contain identity, output and allocation/free callers.
  The owned `call_output_user` wrapper provides an actual extracted output call;
  its public composition exposes an output memory effect without inventing a
  concrete pointee or definite write when the pointer remains unresolved.
- Target binaries are never executed. IDA loads disposable working copies; its
  caches and working-IDB metadata are not promised byte-immutable.

## Reproducible validation

```sh
uv run --group dev python -m pytest tests/test_flow_reviewed_runtime.py -q
uv run --group dev python tests/flow_core/native_reviewed_runtime_smoke.py /tmp/reviewed-public.json
```

The licensed smoke builds each architecture twice using
`scripts/build_flow_call_anchors.py`, checks the pinned binary/source/dSYM hashes,
and statically opens private copies. It exercises actual public snapshot jobs,
reviewed identity/output/alloc/free effects, unresolved recursive/indirect calls, job
replay, terminal cancellation and complete paginated/chunked call results.
The receipt records the actual output target/four provenance-carrying bytes and
the allocation/free object identity plus nonempty weak lifetime transition.
The actual H03 case additionally records global-publication escape uncertainty
and nonempty opaque-call heap widening on both architectures.
A
changed toolchain/hash fails closed; it does not silently repin a catalog.

The packaged review data comes from
`tests/flow_fixtures/manifests/calls/extraction_{x86_64,arm64}.json`. Updating it
requires a new reviewed full-identity catalog and static extraction evidence,
not runtime learning or a name-based compatibility fallback.
