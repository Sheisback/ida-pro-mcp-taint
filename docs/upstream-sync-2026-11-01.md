# Upstream IDA Pro MCP audit — 2026-11-01

Compared this fork with `mrexodia/ida-pro-mcp` from the previously reviewed
[`fab3505`](https://github.com/mrexodia/ida-pro-mcp/commit/fab3505) cursor to
[`c133c38`](https://github.com/mrexodia/ida-pro-mcp/commit/c133c38).

## Reviewed change

Upstream added a README banner recommending the official Hex-Rays IDA MCP
Server for general IDA Pro MCP use. This fork adopted the recommendation in
[`README.md`](../README.md) as fork integration commit `9cdf29a`.

The wording was adapted because applying the upstream patch literally does not
apply after this fork's existing installation banner. The adapted notice:

- preserves the upstream recommendation and announcement links;
- identifies `flow_*` and `driver_*` as fork-specific experimental tools; and
- refers readers back to this fork's existing support boundaries.

No implementation file, tool schema, read-only profile, test fixture, or native
receipt changed. The upstream change does not expand the reviewed profile
matrix, turn an unknown or partial result into a complete one, or add a
vulnerability-detection claim.

## Validation

- `PYTHONPATH=src:. uv run pytest -q tests/test_upstream_sync.py` passed 5/5.
- `git diff --check` passed.
- Licensed IDA receipt regeneration was not required because no implementation
  hash or generated receipt input changed.

## GitHub ancestry badge

GitHub may continue to show this fork as behind upstream after this review
because the earlier upstream integration was squashed and `c133c38` was
adapted rather than added as a parent commit. The 14-commit GitHub behind count
consists of the 13 upstream commits already reviewed through `fab3505` plus
`c133c38`; it is not a count of unreviewed work.

Use `python scripts/check_upstream_sync.py` against the reviewed cursor. Do not
click **Sync fork** merely to clear the ancestry-based badge.
