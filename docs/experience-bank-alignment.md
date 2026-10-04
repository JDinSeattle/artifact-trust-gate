# Experience Bank implementation map

Result provenance: owner-confirmed separate cloud-hosted test results. The README reproduces the current selected bullets. Commands below exercise this checkout; new outcomes must be recorded separately from those supplied results.

| Result | Implementation and regression evidence | Reproduce | Scope / source difference |
|---|---|---|---|
| 1 | [gate.py](../gate.py) · [scripts/validate.py](../scripts/validate.py) | `make verify` | Integrity, valid signature and authorization have separate decision checks. |
| 2 | [gate.py](../gate.py) · [scripts/validate.py](../scripts/validate.py) | `make verify` | Foreign-key self-verification is a positive control before policy rejection. |
| 3 | [gate.py](../gate.py) · [tests/test_gate.py](../tests/test_gate.py) | `make test` | Consumption rehashes and executes the opened inode; no concurrent in-place writer guarantee. |
| 4 | [gate.py](../gate.py) · [tests/test_gate.py](../tests/test_gate.py) | `make test` | Strict JSON and nonblocking regular-file checks prevent FIFO blocking. |
| 5 | [scripts/setup.py](../scripts/setup.py) · [scripts/validate.py](../scripts/validate.py) | `make verify evidence-check` | Pinned Cosign maintenance preserves detached-signature compatibility. |

## Measurement boundaries

- Offline pinned-key fixture only: no transparency log (Rekor), keyless identity, Kubernetes admission, vulnerability scanning, SLSA level, or production release.
- Same-FD execution removes path retargeting but relies on an owner-exclusive store with no concurrent in-place writer; a pwrite inside the trusted CAS is outside the guarantee.
- A valid signature is not authorization, and a signed provenance claim is not proof of truth without an independent build witness; builder, predicate, and subject still need checking.
- The Cosign 2.6.5 move is compatibility maintenance; do not claim the detached workflow was vulnerable to the legacy-bundle issue or that a specific security fix was validated.
- The 17 decisions and 7 regressions test decision and consumption identity, not deployment speedup.

## Local verification

See `docs/alignment-verification.json` for commands and outcomes from this checkout. Supplied cloud numbers, historical checked-in artifacts and new local checks are separate evidence sets. A skipped dependency test is not a pass.
