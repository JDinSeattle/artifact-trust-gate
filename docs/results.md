# Historical local baseline results

Preserved baseline; current maintenance results are in [refresh-results-20260907.md](refresh-results-20260907.md).

Execution date: 2026-09-07T21:44:04Z. 4 focused unit/regression tests passed, followed by the real integration campaign. See [validation log](../evidence/local/validation.log) and [manifest](../evidence/local/manifest.json).

CPU: 13th Gen Intel(R) Core(TM) i9-13900K. Kernel: 7.0.0-29-generic. All results are author-operated local measurements; cloud CI is a separate reproducibility check.

| Case | Expected | Actual |
|---|---|---|
| valid | allow | allow |
| idempotent | allow | allow |
| byte_tamper | reject | reject |
| tag_retarget_old_signature | reject | reject |
| unauthorized_key | reject | reject |
| valid_math_unauthorized_signer | reject | reject |
| wrong_signature | reject | reject |
| provenance_mismatch | reject | reject |
| wrong_builder | reject | reject |
| unknown_algorithm | reject | reject |
| unknown_format | reject | reject |
| wrong_predicate | reject | reject |
| corrupt_signature | reject | reject |
| verifier_crash | reject | reject |
| verifier_timeout | reject | reject |
| symlink_input | reject | reject |
| post_promotion_tamper | reject | reject |

All 17 expected decisions matched. The deployed executable produced the independently known result `[1.546875]` for the generated 1×1×1 input. [Foreign signature mathematical validity](../evidence/local/foreign-math-valid.json) is recorded separately from its authorization rejection. [Full matrix](../evidence/local/matrix.json) includes exact reasons and successful deployment digest records. No private test key is retained.
