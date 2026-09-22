# Flow operator guide

## Safety boundary

Use the flow pipeline for static analysis only. **Never execute the target**,
attach a debugger, or use a dynamic proof-of-concept while producing or
validating these receipts. Every committed receipt must retain
`target_executed: false`. Run licensed IDA capture only in the protected CI or
release environment; untrusted pull requests must not receive license secrets
or a licensed runner.

## Install and activate IDA

1. Install Python 3.11 or newer, `uv`, and a supported IDA Pro installation.
2. Activate idalib with IDA's `py-activate-idalib.py` script for the host OS.
3. Install from the wheel used for release, or create a development environment
   with `uv sync --dev`.
4. Confirm the source, wheel, headless process, and (when actually available)
   GUI process report the same build ID. A GUI acceptance gate is a blocker,
   not evidence of GUI success; do not accept an EULA as part of automation.

## Audit committed support evidence

The audit reads JSON only. It neither imports IDA nor opens a target:

```bash
uv run python scripts/audit_flow_support.py \
  --root . \
  --check tests/flow_fixtures/manifests/support_receipts.json
```

To regenerate the derived summary after independently reviewed receipt changes:

```bash
uv run python scripts/audit_flow_support.py \
  --root . \
  --output tests/flow_fixtures/manifests/support_receipts.json
```

Review the diff. The audit validates the P0 result bodies, recomputes the
normal, format, and RV32 semantic receipt graph, and then compares the derived
support manifest. It does not trust copied digest labels. A successful audit
means the committed receipt graph is internally consistent and reproducible;
it is not a support promotion or a P6 release-readiness verdict.

## Interpret results conservatively

- `normal` identifies the native Hex-Rays observation path for the exact
  recorded configuration.
- `fallback` is a separate evidence path. RV32 remains partial and unverified;
  never merge it into normal evidence or label it fully supported.
- `partial` and `unknown` are soundness states. Preserve unresolved calls,
  memory effects, paths, and unsupported operations in downstream reports.
- A processor/decompiler file inventory or license declaration is not proof
  that extraction succeeds. Only an actual static receipt can prove the exact
  observed configuration.

## Packaging and release expectations

- Run focused support-audit tests before the full suite.
- Require Ruff, scoped Pyright, compileall, sdist/wheel builds, and isolated
  wheel imports.
- Verify build-ID parity across every process mode actually exercised.
- Aggregate protected licensed-IDA results into release CI without exposing
  credentials to untrusted jobs.
- Retain receipt inputs, source digests, named limitations, and
  `target_executed: false`; do not delete or weaken evidence to make a gate pass.
- Require a current, normal receipt for every mandatory profile. A fallback,
  skip, empty profile list, stale/unbound receipt, missing benchmark, or absent
  permitted GUI-process observation must leave strict release readiness blocked.

If IDA, a processor/decompiler module, license entitlement, or GUI acceptance
is unavailable, report that exact blocker and leave the corresponding claim
unverified.
