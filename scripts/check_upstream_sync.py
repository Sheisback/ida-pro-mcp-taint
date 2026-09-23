"""Report upstream commits not yet reviewed by this squash-synced fork.

This command never merges code or advances the reviewed marker. Its fetch uses
the repository URL recorded in docs/upstream-sync-state.json, not a local remote
name that might point somewhere else.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "docs/upstream-sync-state.json"
_SHA = re.compile(r"[0-9a-f]{40}\Z")


class UpstreamSyncError(RuntimeError):
    """The recorded upstream history cannot be checked safely."""


def _git(
    repo: Path, *args: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode:
        raise UpstreamSyncError(result.stderr.strip() or "git command failed")
    return result


def load_state(path: Path = STATE) -> dict[str, str | int]:
    state = json.loads(path.read_text(encoding="utf-8"))
    expected = {
        "schema_version",
        "upstream_url",
        "upstream_branch",
        "last_reviewed_upstream_commit",
        "fork_integration_commit",
        "integration_method",
        "reviewed_date",
    }
    if not isinstance(state, dict) or set(state) != expected:
        raise UpstreamSyncError("invalid upstream sync state fields")
    if state["schema_version"] != 1 or state["integration_method"] != "squash":
        raise UpstreamSyncError("unsupported upstream sync state")
    if state["upstream_url"] != "https://github.com/mrexodia/ida-pro-mcp.git":
        raise UpstreamSyncError("unexpected upstream repository URL")
    if state["upstream_branch"] != "main":
        raise UpstreamSyncError("unexpected upstream branch")
    for key in ("last_reviewed_upstream_commit", "fork_integration_commit"):
        if not isinstance(state[key], str) or not _SHA.fullmatch(state[key]):
            raise UpstreamSyncError(f"invalid {key}")
    return state


def pending_commits(repo: Path, reviewed: str, current: str) -> list[dict[str, str]]:
    if _git(
        repo, "merge-base", "--is-ancestor", reviewed, current, check=False
    ).returncode:
        raise UpstreamSyncError(
            "reviewed commit is not an ancestor of upstream main; "
            "history may have been rewritten, so do not auto-sync"
        )
    output = _git(
        repo,
        "log",
        "--reverse",
        "--format=%H%x09%s",
        f"{reviewed}..{current}",
    ).stdout
    return [
        {"sha": sha, "subject": subject}
        for sha, subject in (line.split("\t", 1) for line in output.splitlines())
    ]


def check(repo: Path = ROOT, state_path: Path = STATE) -> dict[str, object]:
    state = load_state(state_path)
    integration = str(state["fork_integration_commit"])
    if _git(
        repo, "merge-base", "--is-ancestor", integration, "HEAD", check=False
    ).returncode:
        raise UpstreamSyncError(
            "checkout does not contain the recorded fork integration commit"
        )
    _git(
        repo,
        "fetch",
        "--no-tags",
        "--quiet",
        str(state["upstream_url"]),
        str(state["upstream_branch"]),
    )
    current = _git(repo, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip()
    reviewed = str(state["last_reviewed_upstream_commit"])
    pending = pending_commits(repo, reviewed, current)
    return {
        "schema_version": 1,
        "reviewed_upstream_sha": reviewed,
        "current_upstream_sha": current,
        "fork_integration_commit": integration,
        "pending_count": len(pending),
        "pending_commits": pending,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="Print a machine-readable report"
    )
    parser.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Return exit code 2 when upstream has new commits",
    )
    args = parser.parse_args()
    try:
        report = check()
    except (OSError, ValueError, UpstreamSyncError) as exc:
        parser.exit(1, f"upstream check failed: {exc}\n")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Last reviewed upstream: {report['reviewed_upstream_sha']}")
        print(f"Current upstream main: {report['current_upstream_sha']}")
        print(f"New commits requiring review: {report['pending_count']}")
        for commit in report["pending_commits"]:
            print(f"  {commit['sha'][:12]} {commit['subject']}")
        if report["pending_count"]:
            print("Review and test these changes before advancing the recorded SHA.")
    return 2 if args.fail_on_new and report["pending_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
