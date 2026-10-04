# Artifact Trust Gate

## Experience Bank results

The results below are the owner-confirmed results from a separate cloud-hosted test environment, synchronized from the Experience Bank. The experiments retain the local, synthetic, simulator, CPU, Docker and single-host boundaries stated in each result; cloud hosting does not imply production deployment. This repository refresh does not represent a rerun of those measurements. Earlier dated evidence below remains tied to its own source, configuration and denominator.

1. Separated digest integrity, signature validity, and release authorization in an offline pinned-key gate on Ubuntu 24.04 x86_64 (Python 3.12.13, Cosign 2.6.5) that evaluated 17 real-signature decisions: 4 allow controls, 3 corrupted signature bytes, 2 foreign keys, 3 provenance-policy errors, 3 subject/content errors, and 2 non-regular files.

2. Proved authorization is not the same as cryptographic validity: each foreign-key case first verified successfully under its own public key and was then rejected by the fixed release policy (builder.id local-builder/v1, fixed predicateType, subject digest equal to the artifact digest), so the rejection came from authorization rather than a broken signature.

3. Consumed digest-identified bytes rather than paths: across 20 path-replacement rounds, the verified descriptor executed the original 128 KiB static CPU ELF after its path was renamed to another ELF and kept returning the deterministic matrix checksum, 6 for fixed input [2]x[3] instead of the replacement's 123.

4. Hardened parsing and deployment: duplicate JSON keys and non-finite numbers rejected, inputs opened with NOFOLLOW/NONBLOCK then fstat-required to be regular files, and a FIFO input returned non_regular within 50 ms without waiting for read/write ends, with 7 local regressions passing.

5. Maintained verifier currency without expanding trust: Cosign 2.6.5 verified two historical detached signatures produced by 2.6.1, and the detached workflow is not asserted to have been affected by the legacy-bundle issue that the maintenance release addresses.

See the [implementation and reproduction map](docs/experience-bank-alignment.md) for per-result source/tests, reproduction commands and limitations.

[![verify](https://github.com/JDinSeattle/artifact-trust-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/JDinSeattle/artifact-trust-gate/actions/workflows/ci.yml)

An offline release gate for the CPU GEMM executable. It uses real **Cosign 2.6.5** signatures and separates valid signature mathematics from signer authorization and provenance policy. The gate snapshots inputs once, verifies both executable and provenance, promotes content-addressed bytes, and records the exact deployment digest.

The allow/reject matrix contains 17 cases, including valid release, idempotence, byte tampering, stale-signature tag retargeting (local path analogue), a mathematically valid unauthorized signer, wrong signature, unknown algorithm/format, wrong builder/predicate, verifier crash/timeout, symlink input, and post-promotion tampering. The consumer rehashes and executes the same opened inode via `/proc/self/fd`.

Private test keys are generated in a temporary directory and removed; only public keys, signatures, test-owned executables and verification evidence are archived. This is local-key authorization, not keyless CI identity, admission control, vulnerability scanning, compliance certification or a SLSA level claim.

## September 2026 maintenance

The verifier moves from Cosign 2.6.1 to the maintained 2.6.5 patch. The campaign additionally verifies the checked-in historical executable and provenance signatures with the new binary. JSON parsing rejects nonfinite constants; policy identity fields require bounded strings. Consumption validates the deployment record, rejects symlinked object directories and opens the executable with O_NOFOLLOW and O_NONBLOCK before checking regular-file type and size. A FIFO regression proves rejection without blocking.

[Design, acceptance tests and limits](docs/refresh-20260907.md) · [Current measured results](docs/refresh-results-20260907.md). CI repeats validation on Python 3.12 and 3.14.7.

## Reproduce

```bash
git clone https://github.com/JDinSeattle/artifact-trust-gate.git
cd artifact-trust-gate
make verify
python3 evidence.py .runs/latest
```

`make test` runs focused contract regressions. `make verify` also builds and executes real integration/fault experiments. A prior `.runs/latest` is moved to a timestamped archive before a fresh run; nonempty output directories outside `.runs` are never overwritten. GitHub Actions executes the same entry point and uploads evidence even on failure.

The checked-in [local evidence](evidence/local/) has raw records, a source/environment manifest and SHA-256 artifact hashes. Verify it with `make evidence-check`. [Measured results](docs/results.md), [engineering notes](docs/engineering.md), and [interview guide](docs/interview.md) explain what can be claimed.

## System

```mermaid
flowchart LR
  B[Build executable] --> D[SHA-256 provenance]
  D --> S[Cosign sign blob + manifest]
  S --> P[Pinned signer / policy]
  P --> V[Snapshot + verify both signatures]
  V --> O[Content-addressed object]
  O --> R[Atomic deployment record]
  R --> X[Rehash opened inode + execute]
```

The signed provenance binds the artifact digest, declared source digest, builder and predicate. The trusted policy pins the public-key bytes and permitted builder/predicate/format/hash algorithm. A builder claim is a statement by the authorized local signer, not independently authenticated CI metadata. Policy and tool administration are outside the artifact submitter's authority.

## Support and evidence limits

Linux x86_64, Python ≥3.10, g++, and checksum-pinned Cosign downloaded on first run (~149 MiB). Only our own local blobs and ephemeral local keys are used. Offline verification deliberately excludes the transparency log (`--offline --insecure-ignore-tlog`) for this test-key model. The gate assumes trusted policy/tool/deployment directories and a trusted authorized builder. Same-UID concurrent host writers, compromised builder, malicious toolchain and root are outside the boundary. Atomic file replacement is tested, but no power-loss durability claim. No freshness/rollback policy, registry API, SBOM vulnerability verdict, KMS or algorithm migration qualification; upgrading Cosign requires rerunning the matrix before changing the pin.


**Role evidence:** Platform security · software supply chain. This is an author-operated engineering lab. AI-assisted implementation is disclosed; ownership means understanding, reproducing and explaining the code and measurements. No external customer, production operation, upstream contribution or independent reviewer is implied.

MIT licensed. Operator source vendoring, where present, is recorded in `vendor/lock.json`; upstream workload attribution, where present, is in `upstream/`.
