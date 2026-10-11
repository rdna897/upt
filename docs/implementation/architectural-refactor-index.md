# Public UPT architectural refactoring — working index

**Status:** programme in progress. This index is newly authored from the public UPT repository and public PR/issue evidence; it is not a copy of private planning documents.
**Current canonical source:** `rdna897/upt` on public `main`.
**Freeze:** no production UPT deployment until all agreed stages are closed and the operator explicitly approves a separate final release/deployment. See [development policy](../development-policy.md).

## Completed

| Stage | Scope | Public evidence |
| --- | --- | --- |
| 1 | Full-scan worker separation (`scan_worker.py`); facade retains bounded scheduling and RPC | Included in the public baseline |
| 2 | Exact-container targeted verification method with real-worker regression tests | [PR #2](https://github.com/rdna897/upt/pull/2), merged |
| 3 | Runtime health/snapshot coordination: Option A, tests only; extraction recorded as not warranted (`RuntimeMonitorLifecycleTests`, no `src/` change) | [Specification](phase3-runtime-health-snapshot.md) ([PR #4](https://github.com/rdna897/upt/pull/4)); tests [PR #7](https://github.com/rdna897/upt/pull/7), merged at `f50eb5e`. Deferred defects: [#5](https://github.com/rdna897/upt/issues/5), [#6](https://github.com/rdna897/upt/issues/6) |

The repository-policy safeguards are tracked separately in [PR #1](https://github.com/rdna897/upt/pull/1); they are not a refactoring stage.

## Proposed stages (not blanket implementation authority)

| Stage | Candidate boundary | Gate |
| --- | --- | --- |
| 6a | SQLite state and transaction ownership **assessment** (brought forward from Stage 6 as a prerequisite for Stages 4/5) | [Assessment](stage6-sqlite-state-ownership-review.md); owner decisions G1–G5 recorded (Option A; corrective work tracked in [#9](https://github.com/rdna897/upt/issues/9), [#10](https://github.com/rdna897/upt/issues/10), [#11](https://github.com/rdna897/upt/issues/11), [#12](https://github.com/rdna897/upt/issues/12)). Assessment only; not Stage 6 implementation |
| 4 | Compose observation/eligibility versus mutating/trust authority | Needs separate public-safe specification and owner-approved boundary; must cite the accepted (G1) Stage 6a transaction contract; may proceed in parallel with separately approved corrective work |
| 5 | Update, rollback and Compose mutation coordination | Needs separate design/implementation reviews; depends on Stage 6a decisions G2–G4 (durable completion policy [#9](https://github.com/rdna897/upt/issues/9), CLI intent [#10](https://github.com/rdna897/upt/issues/10), rollback-point ownership) **and the G5 resolution of R10** ([#11](https://github.com/rdna897/upt/issues/11)); R12 ([#12](https://github.com/rdna897/upt/issues/12)) must be resolved before final release readiness. Not every Stage 5 change is pre-authorised |
| 6 | SQLite state boundaries without fragmenting transactions | Assessment performed early as 6a; any implementation needs separate approval and includes runtime-snapshot ordering debt ([#6](https://github.com/rdna897/upt/issues/6)) |
| 7 | Web request adapters and presentation boundaries | Preserve auth, CSRF, sessions, SSE and wire contracts |
| 8 | Combined integration, security, compatibility and release-readiness closure | Full clean-tree CI, isolated rehearsal, rollback evidence and separate deployment approval |

**Current next gate — G2:** R10 is merged ([PR #14](https://github.com/rdna897/upt/pull/14)); its tracking issue #11 is closed. G2 [issue #9](https://github.com/rdna897/upt/issues/9) is next: [completion-policy design brief](g2-mutation-completion-policy.md), **design only**, with the already merged [characterisation tests (PR #13)](https://github.com/rdna897/upt/pull/13) as the baseline. Approve the completion policy before authorising any source correction or Stage 5 work. **Revised S0 proposal (pending owner decisions D3/D10):** a [durable, operation-scoped recovery fence](g2-s0-recovery-fence-design.md), independent of `protected_images`, protects both the image and backup and blocks conflicting mutations. S0 brings forward a **minimal G3 intent foundation** (including a CLI operation row); full G3 reconciliation remains separate. The P11 upsert proposal was withdrawn after safety review. Approval of S0 ownership, compatibility and status decisions is required before implementation. G3 [issue #10](https://github.com/rdna897/upt/issues/10) and R12 [issue #12](https://github.com/rdna897/upt/issues/12) remain separate. Production deployment remains frozen.

Each stage may be accepted as **not warranted** when an independently reviewed cost/benefit analysis shows the extraction is worse than the status quo. A stage is not complete until review evidence and the owner's closeout are recorded. Do not expand programme scope or deploy intermediate phases implicitly.

## Change discipline

- Create a public-safe Draft architecture PR first; independently review it and seek explicit approval before implementation.
- Code on an isolated branch; use synthetic fixtures and fail-closed runner guards; retain existing privilege, state, cache, history and rollback semantics.
- Run exact-head full Python 3.10/3.13 and Chromium CI. A passing `merge-gate` is required for code merges but does not replace manual review.
- Do not include private issue bodies, operational topology, internal CI runners, host paths or credentials in public commits, release assets or CI logs.
- All merges are code-only. Production UPT web/agent, Docker workloads, SQLite state and host service configuration stay untouched until separately authorised.
