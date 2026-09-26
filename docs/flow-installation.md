# Experimental flow tools: Codex development installation

This fork is currently distributed to testers from a **pinned GitHub commit**.
It is not a separately released PyPI package or a fork-specific Codex
marketplace plugin. The `mrexodia/codex-marketplace` commands in the upstream
README install the original project, not these `flow_*` tools. Codex's
`mcp add --url` expects a running HTTP MCP endpoint, **not** a GitHub repository
URL; the Git source belongs in the local stdio command run by `uvx`.
See the [official Codex MCP connection guide](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
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
set -eu
FLOW_REF=e0202f6469d382a5798f136429a991da9d946c01
PROFILE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/ida-pro-mcp-taint"
mkdir -p "$PROFILE_DIR"
curl -fsSL \
  "https://raw.githubusercontent.com/Sheisback/ida-pro-mcp-taint/$FLOW_REF/profiles/flow-readonly.txt" \
  -o "$PROFILE_DIR/flow-readonly.txt"
printf 'e742a5dfb343be1cd3fc2aa52ea111c08738ea120a82827ed7766b59a66e86f3  %s\n' \
  "$PROFILE_DIR/flow-readonly.txt" | shasum -a 256 -c -

codex mcp add ida-pro-mcp-taint -- \
  uvx --from "git+https://github.com/Sheisback/ida-pro-mcp-taint.git@$FLOW_REF" \
  idalib-mcp --stdio --profile "$PROFILE_DIR/flow-readonly.txt"
codex mcp list
```

This pin includes pointee/Store evidence, lossless graph export, the angr
sidecar, and the reviewed refinement/wire fixes. The matching profile exposes
these tools; an older profile can hide tools even when the package is newer.
The local verification record is [the review-fix report](flow-review-fixes-2026-09-26.ko.txt),
not a public release certification.

The opt-in angr path tier (`flow_refine_path_proof` with `symbolic_angr`)
runs in a sidecar under a separately configured interpreter
(`IDA_MCP_ANGR_PYTHON`); nothing in the host environment provides it.
Without that interpreter, requested tiers return unknown with
an explicit unavailability reason while the v1 baseline stays intact.

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

## Local-checkout alternative

Use absolute paths so the client's working directory does not select a different
project or profile. For a new entry, or an intentional replacement of the exact
entry inspected above:

```sh
# Run from the root of this checkout.
REPO_ROOT="$(pwd -P)"
codex mcp add ida-pro-mcp-taint -- \
  uv run --project "$REPO_ROOT" idalib-mcp --stdio \
  --profile "$REPO_ROOT/profiles/flow-readonly.txt"
```

This runs the checkout rather than the pinned GitHub package. Restart the MCP
server/client session after changing source or configuration. Do not keep an
old upstream server entry and mistake its tools for this connection's tools.

## Optional angr sidecar

Basic extraction, taint, graph tracing, bounded v1 path checks, and memory
evidence do **not** require angr. Do not install a `solver` extra or Z3 into
IDA's environment: the former in-process engine was retired.

The local review used Python 3.11, angr/claripy 9.2.213 and Z3 4.13.0. To prepare
a separate environment on a macOS/Linux host, without altering this project's
dependencies:

```sh
ANGR_ENV="${XDG_DATA_HOME:-$HOME/.local/share}/ida-pro-mcp-taint/angr"
test -x "$ANGR_ENV/bin/python" || uv venv --python 3.11 "$ANGR_ENV"
uv pip install --python "$ANGR_ENV/bin/python" "angr==9.2.213"
"$ANGR_ENV/bin/python" -c 'import angr, claripy, z3; print(angr.__version__, claripy.__version__, z3.get_version_string())'
```

Pass the interpreter to the MCP **server process**, not just to an unrelated
terminal. Using `FLOW_REF` and `PROFILE_DIR` from the pinned-install example,
register or intentionally replace that one entry with:

```sh
codex mcp add ida-pro-mcp-taint \
  --env "IDA_MCP_ANGR_PYTHON=$ANGR_ENV/bin/python" -- \
  uvx --from "git+https://github.com/Sheisback/ida-pro-mcp-taint.git@$FLOW_REF" \
  idalib-mcp --stdio --profile "$PROFILE_DIR/flow-readonly.txt"
```

For the checkout alternative, retain the same `--env` option and use its
`uv run --project ...` command after `--`. The CLI environment syntax is
documented in the [official MCP guide](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

`configured_unverified` means the interpreter and runner paths exist; capability
discovery does not import or launch angr. Only an explicit
`symbolic_angr: true` request attempts it, and failures remain `unknown` with
the original baseline preserved. This tier currently accepts only representable
x64 prefixes over **v1** artifacts. Memory refinement is `evidence_only`, not
an alias-narrowing solver. See the [operator contract](flow-operator.md#opt-in-symbolic-refinement-experimental).

## Optional client skill

MCP registration makes tools available; skill installation supplies the agent's
workflow instructions. From a checkout containing `skills/ida-flow/`, install
that **whole directory**, including its request reference:

```sh
# Review an existing customized skill before replacing its files.
SKILL_DIR="$HOME/.agents/skills/ida-flow"
mkdir -p "$SKILL_DIR"
cp -R skills/ida-flow/. "$SKILL_DIR/"
```

Codex documents `~/.agents/skills/` for user skills and `.agents/skills/` for
repository-scoped skills in its [skill guide](https://learn.chatgpt.com/docs/build-skills).
Invoke `$ida-flow` or ask for static flow analysis; restart the client if the
new skill is not discovered. Other clients should use their own skill-loading
mechanism or load `skills/ida-flow/SKILL.md` as instructions.

The skill does not install IDA, register an MCP server, enable unsafe tools, or
turn this repository into a published fork plugin. Keep `idapython` for explicit
IDAPython scripting, not as a way around the restricted flow profile.

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
