# Experimental flow tools: Codex development installation

This fork is currently distributed to testers from a **pinned GitHub commit**.
It is not a separately released PyPI package or a fork-specific Codex
marketplace plugin. The `mrexodia/codex-marketplace` commands in the upstream
README install the original project, not these `flow_*` tools. Codex's
`mcp add --url` expects a running HTTP MCP endpoint, **not** a GitHub repository
URL; the Git source belongs in the local stdio command run by `uvx`.
See the [official Codex MCP connection guide](https://developers.openai.com/learn/docs-mcp)
for the CLI configuration model.

## Prerequisites

- A licensed local IDA Pro **9.3** with idalib activated for the Python used by
  `uvx`. IDA Free and a remote/cloud-only Codex environment are not substitutes
  for a local licensed IDA installation.
- Python 3.11+, `uv`/`uvx`, Git, and the Codex CLI on `PATH`.
- A trusted, disposable working copy of the input binary or IDB. Analysis does
  not execute the target, but upstream MCP tracing and IDA save/close behavior
  can modify a working IDB.

See the [README prerequisites](../README.md#prerequisites) for the IDA 9.3
activation command on each host OS. Check `uvx --version` and
`codex mcp add --help` before registering the server.

## Install from a reviewed Git revision (macOS/Linux shell)

Use one immutable revision for the package **and** its read-only profile. The
revision below is the latest reviewed developer-install pin, not a moving
`main` alias. The profile is downloaded separately because it is not currently
included in the Python wheel.

```sh
FLOW_REF=7b9c5d383fff79d60e473dec82aaafd73eacac35
PROFILE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/ida-pro-mcp-taint"
mkdir -p "$PROFILE_DIR"
curl -fsSL \
  "https://raw.githubusercontent.com/Sheisback/ida-pro-mcp-taint/$FLOW_REF/profiles/flow-readonly.txt" \
  -o "$PROFILE_DIR/flow-readonly.txt"
printf '02187a3b23e3d0297278f56cab07633b6006474c551a4630c7eaa10793f4873a  %s\n' \
  "$PROFILE_DIR/flow-readonly.txt" | shasum -a 256 -c -

codex mcp add ida-pro-mcp-taint -- \
  uvx --from "git+https://github.com/Sheisback/ida-pro-mcp-taint.git@$FLOW_REF" \
  --with "z3-solver>=5.1,<6" \
  idalib-mcp --stdio --profile "$PROFILE_DIR/flow-readonly.txt"
codex mcp list
```

The `--with` flag provides the z3 solver that the opt-in symbolic
refinement tiers (`flow_refine_path_proof`, `flow_refine_memory_proof`)
need; the version pin mirrors the package's `solver` extra. Without z3,
requested tiers return unknown with `solver_unavailable` while the v1
baseline stays intact.

If `ida-pro-mcp-taint` is already configured, inspect it with
`codex mcp get ida-pro-mcp-taint --json`; remove that exact entry with
`codex mcp remove ida-pro-mcp-taint` only when intentionally replacing it.
A local-checkout configuration remains a valid development alternative.
Start a **new** Codex session after changing MCP configuration. On the first
use, `uvx` fetches/builds the pinned source and may take longer. The local IDA
license and decompiler must still be available on that machine.

For a smoke check, ask Codex to list `flow_get_capabilities`, `idb_open`, and
`flow_create_snapshot`, then open a disposable binary with `idb_open`. Pass the
returned session ID as `database` to subsequent `flow_*` calls. A restricted
connection exposes only the tools listed in `profiles/flow-readonly.txt` plus
supervisor database-management tools. Close an owned test session with
`idb_close(database=<session_id>, save=False)`.

## Distribution boundary

GitHub-source installation is the **developer/tester lane**, not a support or
vulnerability-detection claim. An earlier 137-binary selected-function smoke
scan ran before the information-diagnostic correction, so its all-`partial`
count is **not** a post-fix completeness statistic; one very large Go graph
also exceeded the full-page scan timeout. After the correction, an IDA 9.3
`memcpy_small_dest_ssa` sample returned `complete_in_scope`, while a
`recv`/`system` sample retained named unknown effects and `partial`. These are
bounded smoke observations, not a full-corpus or vulnerability verdict. See
the [compatibility matrix](flow-compatibility.md).

The planned next lane is a **distinctly named fork plugin in a Git-backed
Codex marketplace**; public distribution is later and requires its own release
decision. Before enabling that lane, change the inherited upstream publisher,
repository, package/version and plugin metadata; bundle the read-only profile;
verify a clean-machine install; and finish the separate release checks. The
current wheel still uses the upstream `ida-pro-mcp` package name/version and
does not contain `profiles/flow-readonly.txt`, so publishing it as a distinct
fork now would be misleading. A marketplace can itself use a Git repository as
a source; no PyPI publication is required for that next step. See the
[official plugin marketplace guide](https://developers.openai.com/plugins/build/plugins).
