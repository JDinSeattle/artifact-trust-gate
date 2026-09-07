# Interview preparation / 面试准备

Target: Platform security · software supply chain.

Explain the code path and one retained failure before citing any metric. All numbers must link to the checked-in evidence and its hardware/software manifest. A GitHub CI pass demonstrates reproducibility, not production use.

可陈述：独立实现、真实本地测试、故障定位、可复现证据。不可陈述：企业客户、生产规模、未测硬件成绩、上游已合并贡献、独立用户验收。先按 README 完整复现，再练习解释每个边界和失败。

## Evidence-led talking points

- Open `foreign-math-valid.json`, then the denied foreign signer case. The same artifact can be mathematically signed correctly and unauthorized by release policy.
- Show that provenance is signed too, and that artifact digest, builder, predicate and signature policy are checked before publication.
- Explain the verify-then-copy race and how snapshots plus a content-addressed deployment avoid path re-resolution. The consumer verifies an opened inode; same-UID hostile mutation of trusted objects remains outside scope.
- Explain why offline test keys use no transparency log, why this is not keyless identity validation, and which additional issuer/subject/bundle checks keyless would require.
- Explain the fail-closed timeout and post-promotion tamper cases, including which file is absent on rejection.

Resume wording, after reproducing: “Implemented an offline Cosign release gate with pinned signer/provenance policy, snapshot-based verification and digest-bound promotion; executed 17 allow/deny cases and verified the exact deployed executable before use.” Never imply SLSA certification, production admission, vulnerability scanning or proprietary cryptographic design.
