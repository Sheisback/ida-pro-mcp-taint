# Flow compatibility and evidence boundary

The pinned [Codex GitHub-source installation](flow-installation.md) is a
developer/tester route, not a distribution or runtime-support promotion.

The flow-analysis profile matrix records **static observations**, not blanket
architecture support. The committed audit in
`tests/flow_fixtures/manifests/support_receipts.json` covers all 17 inventoried
profiles and deliberately does not promote runtime support. All registry rows
remain `unverified` until a separately reviewed product decision changes that
contract.

The required licensed release test version is **IDA 9.3 only**. Versions
9.0–9.2 are no longer release gates. This does not change the required ISA
profiles or turn archival receipts into current-run evidence.

## Required release profiles (16)

| Profile | P0 observation | Semantic evidence | Runtime support claim |
| --- | --- | --- | --- |
| `X86-LE` | normal success | normal, partial with named limits | unverified |
| `X64-LE` | normal success | normal, partial with named limits | unverified |
| `ARM32-LE` | normal success | normal, partial with named limits | unverified |
| `ARM32-BE` | normal success | normal, partial with named limits | unverified |
| `THUMB-LE` | normal success | normal, partial with named limits | unverified |
| `THUMB-BE` | normal success | normal, partial with named limits | unverified |
| `A64-LE` | normal success | normal, partial with named limits | unverified |
| `MIPS32-LE` | normal success | normal, partial with named limits | unverified |
| `MIPS32-BE` | normal success | normal, partial with named limits | unverified |
| `MIPS64-LE` | normal success | normal, partial with named limits | unverified |
| `MIPS64-BE` | normal success | normal, partial with named limits | unverified |
| `PPC32-LE` | normal success | normal, partial with named limits | unverified |
| `PPC32-BE` | normal success | normal, partial with named limits | unverified |
| `PPC64-LE` | normal success | normal, partial with named limits | unverified |
| `PPC64-BE` | normal success | normal, partial with named limits | unverified |
| `RV64-LE` | normal success | normal, partial with named limits | unverified |

`RV32-LE` remains an **optional, unverified** inventory row: its normal
microcode probe returned `MERR_LICENSE` (`-23`), and its separate fallback is
partial. The user explicitly removed RV32 from the required goal on
2026-09-23. Neither that fallback nor this scope change promotes RV32 support.
The reviewed release partition is pinned in
`profiles/flow-release-scope.json`. This later approval supersedes only RV32's
mandatory-release classification in the original design contract; the other
profile, format, safety, and final verification requirements remain in force.

The matrix also contains four format-specific observations: X64 PE, X64
Mach-O, A64 Mach-O, and ARM32 raw. They are exact fixture/configuration
receipts, not general claims about every PE, Mach-O, or raw input.

## What the evidence proves

- The 17 inventory identities are present in canonical order; 16 remain
  required for release and RV32 is optional.
- Sixteen profiles have normal P0 and semantic observations.
- RV32 has a recorded normal-backend failure and a separate partial fallback.
- Inputs were preserved and every receipt states that the target was not
  executed.
- Unknown call effects, unresolved memory boundaries, and unsupported
  operations remain explicit partial/unknown results rather than false-clean
  results.
- The eight G007 memory-analysis receipts now have six
  `complete_in_scope` modeled computations and two indexed-stack `partial`
  results with actual opaque effects. Information-only extraction notes no
  longer force partiality; `may_alias` edge precision remains separate from
  analysis completion. This is not a support or vulnerability verdict.

## What the evidence does not prove

- Availability of a processor or decompiler module on another IDA install.
- License entitlement, GUI EULA acceptance, or GUI-process end-to-end success.
- Compatibility outside the recorded IDA, processor, ABI, format, maturity,
  fixture digest, and build-ID configuration.
- A vulnerability verdict. The flow API reports evidence and limitations; the
  operator owns interpretation.

The source of truth for exact rows and artifact identities remains the JSON
receipt set. This document is an operator-readable summary only.

## Runtime routing modes

`flow_create_snapshot` exposes two distinct routing contracts:

- `exact_fixture` is the default conformance mode. The open input digest and
  observed processor, bitness, data endianness, format, IDA build, and Hex-Rays
  build must match one frozen normal semantic receipt.
- `analyst_selected` accepts a different input digest only when the caller
  supplies both `profile` and `abi`. The same observed environment fields must
  match reviewed normal evidence for that exact selection. ARM and Thumb are
  therefore distinguished by the explicit profile, not guessed from IDA's
  coarse processor metadata.

Analyst selection records the current binary digest separately from the
configuration fixture digest. The former scopes runtime state and stale-context
checks; the latter remains the reviewed extraction-configuration evidence. This
mode is not fixture conformance, ABI inference, or a support promotion. An input
change invalidates the retained selection, and RV32 is rejected because no
normal route exists.

## Audit and release boundary

The support audit recomputes every referenced receipt body. It validates the
P0 result receipts with the recording contract and rebuilds the complete
normal, format, and RV32 semantic matrix with the receipt-specific validators.
Copied digest labels are not accepted as proof that the referenced bodies are
intact.

Passing that audit proves only that the committed static observation graph is
internally consistent. It does not establish distribution release readiness.
The user-approved implementation-completion scope does **not** require a
protected Linux runner or an official licensed 5×30 benchmark receipt.
The separate strict distribution gate requires current, checkout-bound normal
evidence for every mandatory profile and exact bindings for the build, fixture
SHA-256, processor, ABI,
format, maturity, and observed IDA and Hex-Rays builds. RV32 fallback evidence
remains separate and is not a mandatory normal row. For that separate gate,
licensed benchmark and permitted GUI-process evidence must also be present;
absence remains an explicit distribution blocker rather than a successful or
skipped gate.

Release row counts and availability are derived from the canonical semantic
matrix, profile build manifest, and hash-pinned release-scope policy. A fallback
row for a **required** profile remains in `unavailable_normal_rows` and blocks
release; the optional RV32 fallback stays in the audited inventory but outside
the mandatory row set. Its recorded failure is never counted as a normal pass.
