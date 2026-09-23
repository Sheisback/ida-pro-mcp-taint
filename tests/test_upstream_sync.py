"""Offline regression tests for the separately tracked upstream review marker."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import check_upstream_sync as sync
from scripts.check_upstream_sync import (
    STATE,
    UpstreamSyncError,
    load_state,
    pending_commits,
)


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True, stderr=subprocess.DEVNULL
    ).strip()


def commit(repo: Path, name: str, message: str) -> str:
    (repo / name).write_text(message)
    git(repo, "add", name)
    git(repo, "commit", "-qm", message)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "Flow Test")
    git(tmp_path, "config", "user.email", "flow@example.invalid")
    return tmp_path


def test_pending_commits_counts_only_changes_after_reviewed_sha(repo):
    reviewed = commit(repo, "base", "reviewed")
    assert pending_commits(repo, reviewed, reviewed) == []

    first = commit(repo, "first", "first new fix")
    second = commit(repo, "second", "second new fix")
    assert pending_commits(repo, reviewed, second) == [
        {"sha": first, "subject": "first new fix"},
        {"sha": second, "subject": "second new fix"},
    ]


def test_rewritten_upstream_history_fails_closed(repo):
    reviewed = commit(repo, "base", "reviewed")
    git(repo, "checkout", "--orphan", "replacement")
    current = commit(repo, "replacement", "unrelated replacement")
    with pytest.raises(UpstreamSyncError, match="history may have been rewritten"):
        pending_commits(repo, reviewed, current)


def test_recorded_state_has_an_exact_official_upstream_and_integration(tmp_path):
    state = load_state()
    assert state["last_reviewed_upstream_commit"] == (
        "fab3505ee2405ef4e87dcd370418ea7d661f5bdf"
    )
    assert state["fork_integration_commit"] == (
        "e349bc0196aae48caec61c30a74784ce316d04d6"
    )

    bad = dict(state, upstream_url="https://example.invalid/other.git")
    path = tmp_path / "state.json"
    path.write_text(json.dumps(bad))
    with pytest.raises(UpstreamSyncError, match="unexpected upstream"):
        load_state(path)
    assert STATE.exists()


@pytest.mark.parametrize("fail_on_new,expected", [(False, 0), (True, 2)])
def test_cli_reports_new_commits_without_automatic_failure(
    monkeypatch, capsys, fail_on_new, expected
):
    monkeypatch.setattr(
        sync,
        "check",
        lambda: {
            "reviewed_upstream_sha": "a" * 40,
            "current_upstream_sha": "b" * 40,
            "pending_count": 1,
            "pending_commits": [{"sha": "b" * 40, "subject": "new fix"}],
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["check_upstream_sync.py", *(["--fail-on-new"] if fail_on_new else [])],
    )
    assert sync.main() == expected
    assert "new fix" in capsys.readouterr().out
