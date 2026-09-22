# Flow compatibility and evidence boundary

The flow-analysis profile matrix records **static observations**, not blanket
architecture support. The committed audit in
`tests/flow_fixtures/manifests/support_receipts.json` covers every required
profile and deliberately does not promote runtime support. All registry rows
remain `unverified` until a separately reviewed product decision changes that
contract.

## Required profiles

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
| `RV32-LE` | normal microcode failed | explicit fallback, partial | unverified |
| `RV64-LE` | normal success | normal, partial with named limits | unverified |

The matrix also contains four format-specific observations: X64 PE, X64
Mach-O, A64 Mach-O, and ARM32 raw. They are exact fixture/configuration
receipts, not general claims about every PE, Mach-O, or raw input.

## What the evidence proves

- The 17 required profile identities are present in canonical order.
- Sixteen profiles have normal P0 and semantic observations.
- RV32 has a recorded normal-backend failure and a separate partial fallback.
- Inputs were preserved and every receipt states that the target was not
  executed.
- Unknown call effects, unresolved memory boundaries, and unsupported
  operations remain explicit partial/unknown results rather than false-clean
  results.

## What the evidence does not prove

- Availability of a processor or decompiler module on another IDA install.
- License entitlement, GUI EULA acceptance, or GUI-process end-to-end success.
- Compatibility outside the recorded IDA, processor, ABI, format, maturity,
  fixture digest, and build-ID configuration.
- A vulnerability verdict. The flow API reports evidence and limitations; the
  operator owns interpretation.

The source of truth for exact rows and artifact identities remains the JSON
receipt set. This document is an operator-readable summary only.
