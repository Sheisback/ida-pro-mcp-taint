# AGENTS.md

Repository-specific guidance for coding agents. This ports the applicable
development rules from `CLAUDE.md` and adds this fork's flow-analysis and
upstream-sync contracts. `CLAUDE.md` remains as upstream-oriented reference;
use this file for current fork-specific boundaries. Follow higher-priority
host instructions as well.

## Project and important paths

`ida-pro-mcp` exposes IDA Pro and idalib to MCP clients. This fork also adds
experimental static SSA, memory/provenance, and taint-flow tools.

| Area | Path |
| --- | --- |
| MCP server entrypoint | `src/ida_pro_mcp/server.py` |
| Headless supervisor and IDA worker | `src/ida_pro_mcp/idalib_supervisor.py`, `src/ida_pro_mcp/idalib_server.py` |
| IDA/plugin API tools | `src/ida_pro_mcp/ida_mcp/api_*.py` |
| Flow public API and IDA adapters | `src/ida_pro_mcp/ida_mcp/api_flow.py`, `src/ida_pro_mcp/ida_mcp/flow/` |
| SDK-independent flow core | `src/ida_pro_mcp/flow_core/` |
| Flow profile and operator guidance | `profiles/flow-readonly.txt`, `docs/flow-operator.md`, `docs/flow-compatibility.md` |

Base API modules: `api_core.py` handles IDB metadata/functions/strings/imports;
`api_analysis.py` handles decompilation, disassembly, xrefs, paths, and search;
`api_memory.py` handles memory reads and patching; `api_types.py` handles types
and structs; `api_modify.py` handles comments/renaming/patches; `api_stack.py`
handles frames; `api_sigmaker.py` handles signatures; `api_resources.py`
handles `ida://` resources. `api_debug.py` and `api_python.py` expose sensitive
debugger/Python operations and are not part of the read-only flow profile.

## Implementation rules

- IDA SDK calls belong on IDA's main thread. For public IDA tools, use the
  existing decorator order:

  ```python
  from .rpc import tool
  from .sync import idasync

  @tool
  @idasync
  def my_tool(...):
      ...
  ```

- Keep `flow_core` free of IDA imports; extract immutable data in the IDA
  adapter, then analyze it outside the IDA main thread where possible.
- Prefer batch-first APIs, full type hints, and `Annotated[...]` parameter
  descriptions. The docstring becomes the MCP tool description. Existing APIs
  may accept comma-separated strings or lists; preserve their documented
  normalization contract. For example,
  `addrs: Annotated[str, "Addresses (0x401000, main) or list"]` documents a
  batch-aware tool argument.
- Reuse `parse_address()`, `normalize_list_input()`, `normalize_dict_list()`,
  and shared pagination/filter helpers in `utils.py` rather than inventing
  parallel parsers.
- Mark destructive or debugger operations unsafe using the established
  `@unsafe` / `@tool` / `@idasync` pattern; do not add them to
  `profiles/flow-readonly.txt`.

## Flow safety and evidence boundary

- Analyze binaries **statically in IDA**; never execute a target binary as a
  test of `flow_*`. Use disposable binary/IDB copies when IDA or MCP tracing
  may change a working database. Close owned headless test sessions with
  `save=False`.
- Do not produce an automatic vulnerability verdict, dynamic proof of concept,
  or dedicated GUI as part of flow analysis. Preserve `partial`, `unknown`,
  unresolved memory/call effects, and provenance instead of silently treating
  missing models as safe.
- A tool call's `database` is the session ID returned by `idb_open`, not a file
  path. Keep per-database state and ownership isolated.
- Support claims require the exact reviewed profile, ABI, IDA/Hex-Rays build,
  format, and evidence route. The fork's required licensed release-test
  version is **IDA 9.3**; upstream's broader IDA 8.3+ statement does not
  promote this fork's experimental flow profiles. See
  `docs/flow-compatibility.md`.
- The original `mrexodia` Codex marketplace installs upstream, not this fork.
  For current tester installation use `docs/flow-installation.md` and a pinned
  GitHub commit plus the matching read-only profile. Do not claim a public
  fork plugin/PyPI release until its separate packaging and release work is
  complete.

## Development and verification

Use Python 3.11+ and `uv`. IDA Free is unsupported. If IDA uses the wrong
Python, use `idapyswitch`; activate idalib as described in `README.md`.

```sh
# Server modes (use only the mode needed for the task)
uv run ida-pro-mcp
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
uv run idalib-mcp --stdio
uv run idalib-mcp --host 127.0.0.1 --port 8745
# A disposable binary path may be supplied at startup when needed.
uv run idalib-mcp --stdio path/to/disposable/binary

# Flow's restricted stdio mode from the checkout
uv run idalib-mcp --stdio --profile profiles/flow-readonly.txt

# MCP inspector / GUI installer when explicitly in scope
uv run mcp dev src/ida_pro_mcp/server.py
uv run ida-pro-mcp --install
uv run ida-pro-mcp --uninstall
# Unsafe mode only for an explicitly authorized task:
uv run ida-pro-mcp --unsafe
```

For IDA-facing tests, copy the fixture to a disposable directory while
preserving its basename (binary-specific tests use `@test(binary="...")`):

```sh
work=$(mktemp -d)
cp tests/typed_fixture.elf "$work/typed_fixture.elf"
uv run ida-mcp-test "$work/typed_fixture.elf" -q
uv run ida-mcp-test "$work/typed_fixture.elf" -c api_analysis -q
uv run ida-mcp-test "$work/typed_fixture.elf" -p '*stack*' -q
```

`tests/crackme03.elf` is the compact general fixture;
`tests/typed_fixture.elf` covers typed globals, structs, locals, and stack
behavior. For coverage across both maintained fixtures:

```sh
cp tests/crackme03.elf "$work/crackme03.elf"
uv run coverage erase
uv run coverage run -m ida_pro_mcp.test "$work/crackme03.elf" -q
uv run coverage run --append -m ida_pro_mcp.test "$work/typed_fixture.elf" -q
uv run coverage report --show-missing
```

For generic IDA tests, also try a non-fixture binary when available to catch
ELF-only assumptions.

SDK-free checks should run before expensive IDA checks:

```sh
PYTHONPATH=src:. uv run pytest -q tests/flow_core tests/test_upstream_sync.py
uvx ruff@0.15.7 check src/ida_pro_mcp/flow_core tests/flow_core \
  src/ida_pro_mcp/ida_mcp/flow/runtime.py src/ida_pro_mcp/idalib_server.py \
  scripts/check_upstream_sync.py tests/test_upstream_sync.py
uv run python scripts/audit_flow_support.py --root . \
  --check tests/flow_fixtures/manifests/support_receipts.json
```

Prefer semantic assertions over field-presence checks and round-trip tests for
mutating APIs. Fix incorrect API behavior rather than weakening a test. Guard
legitimate IDA/Hex-Rays variance explicitly. IDA-dependent tests under
`src/ida_pro_mcp/ida_mcp/tests/` run through `ida-mcp-test`, not ordinary
SDK-free `pytest`. Keep test binaries unexecuted, original inputs preserved,
and receipt provenance genuine; regenerate native receipts with IDA when
implementation hashes change instead of editing hashes by hand.

For scoped feature work, prioritize `flow_core`, `api_flow.py`, and the IDA
flow adapters. For general upstream MCP work, prioritize the IDA-facing
`api_analysis.py`, `api_types.py`, `api_modify.py`, `api_stack.py`,
`api_memory.py`, `api_core.py`, `api_resources.py`, `utils.py`, and
`framework.py`. Debugger APIs, transport/hosting, and installer changes are
lower priority unless the task specifically concerns them.

## Upstream history: reviewed cursor, not GitHub's behind count

This fork squash-integrated upstream through `fab3505` in fork commit
`e349bc0`. GitHub still shows those 13 upstream commits as “behind” because
the commits are not ancestry parents; that badge does **not** mean 13 pending
fixes. The tracked cursor is `docs/upstream-sync-state.json`, with the audit
at `docs/upstream-sync-2026-09-23.md`.

Before any upstream sync, run:

```sh
python scripts/check_upstream_sync.py
python scripts/check_upstream_sync.py --json  # optional structured report
```

The checker fetches the official upstream `main`, verifies ancestry, and lists
only commits after the recorded reviewed SHA. It does not merge, mutate the
cursor, or automatically mark new code as safe. If new commits appear:

1. Inspect each upstream patch and its tests; decide what this fork actually
   needs. Preserve flow-specific behavior and protected read-only defaults.
2. Apply reviewed changes in small logical commits, run targeted/full tests,
   IDA 9.3 smoke where relevant, static support audit, and any affected native
   receipts. Do not replace genuine evidence with copied digest labels.
3. **Only after** the code is integrated and verified, update
   `docs/upstream-sync-state.json` with the new full upstream SHA and the fork
   integration commit; document decisions in a dated audit note.
4. Do not click GitHub's **Sync fork** just to clear the behind badge, and do
   not auto-merge, force-push, or rewrite history without explicit authority.

Keep commits focused and human-readable; avoid automated checkpoint/worker
noise in published history. A clean upstream cursor is a review record, not a
claim of complete taint correctness or release readiness.
