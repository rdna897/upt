# Public UPT architectural refactoring — working index

**Status:** programme in progress. This index is newly authored from the public UPT repository and public PR/issue evidence; it is not a copy of private planning documents.
**Current canonical source:** `rdna897/upt` on public `main`.
**Freeze:** no production UPT deployment until all agreed stages are closed and the operator explicitly approves a separate final release/deployment. See [development policy](../development-policy.md).

## Completed

| Stage | Scope | Public evidence |
| --- | --- | --- |
| 1 | Full-scan worker separation (`scan_worker.py`); facade retains bounded scheduling and RPC | Included in the public baseline |
| 2 | Exact-container targeted verification method with real-worker regression tests | [PR #2](https://github.com/rdna897/upt/pull/2), merged |

The repository-policy safeguards are tracked separately in [PR #1](https://github.com/rdna897/upt/pull/1); they are not a refactoring stage.

## Proposed stages (not blanket implementation authority)

| Stage | Candidate boundary | Gate |
| --- | --- | --- |
| 3 | Runtime health/snapshot coordination; evaluate extraction versus tests-only | [Draft Phase 3 specification](phase3-runtime-health-snapshot.md), [issue #3](https://github.com/rdna897/upt/issues/3); owner approved Option A (tests only; extraction not warranted); tests-only implementation PR pending owner acceptance. Deferred defects: [#5](https://github.com/rdna897/upt/issues/5), [#6](https://github.com/rdna897/upt/issues/6) |
| 4 | Compose observation/eligibility versus mutating/trust authority | Needs separate public-safe specification and owner-approved boundary |
| 5 | Update, rollback and Compose mutation coordination | Needs separate design/implementation reviews |
| 6 | SQLite state boundaries without fragmenting transactions | Evaluate transaction ownership **before** accepting detailed Stage 4/5 designs; include runtime-snapshot ordering debt ([#6](https://github.com/rdna897/upt/issues/6)) |
| 7 | Web request adapters and presentation boundaries | Preserve auth, CSRF, sessions, SSE and wire contracts |
| 8 | Combined integration, security, compatibility and release-readiness closure | Full clean-tree CI, isolated rehearsal, rollback evidence and separate deployment approval |

Each stage may be accepted as **not warranted** when an independently reviewed cost/benefit analysis shows the extraction is worse than the status quo. A stage is not complete until review evidence and the owner's closeout are recorded. Do not expand programme scope or deploy intermediate phases implicitly.

## Change discipline

- Create a public-safe Draft architecture PR first; independently review it and seek explicit approval before implementation.
- Code on an isolated branch; use synthetic fixtures and fail-closed runner guards; retain existing privilege, state, cache, history and rollback semantics.
- Run exact-head full Python 3.10/3.13 and Chromium CI. A passing `merge-gate` is required for code merges but does not replace manual review.
- Do not include private issue bodies, operational topology, internal CI runners, host paths or credentials in public commits, release assets or CI logs.
- All merges are code-only. Production UPT web/agent, Docker workloads, SQLite state and host service configuration stay untouched until separately authorised.
