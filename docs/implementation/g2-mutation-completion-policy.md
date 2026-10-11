# G2 — mutation completion and SQLite publication (design brief)

**Status:** Design draft only; **not approved for implementation or merge**. The completion policy must receive independent review and explicit owner approval before source changes.
**Tracking:** [issue #9](https://github.com/rdna897/upt/issues/9) (S6-R1, R1b, R2, R3).
**Prerequisites:** [Stage 6a transaction-ownership decision](stage6-sqlite-state-ownership-review.md); merged [G2 characterisation PR #13](https://github.com/rdna897/upt/pull/13); merged [R10 PR #14](https://github.com/rdna897/upt/pull/14).
**Deployment:** Production freeze remains in force. No Docker changes or live databases in development/tests.

## Problem and required contract

An image update, pinned update or rollback can finish successfully in Docker while a subsequent SQLite history or terminal-operation write fails. Existing paths can then produce a contradictory FAILED record, reverse a healthy pinned update, abandon a web operation, or produce no durable record at all. The G2 policy must cover all of these without redefining the actual workload outcome.

The proposal must specify, per mutation path:

1. **Two distinct facts:** observed Docker/Compose workload outcome versus persistence/publication outcome. Do not claim a successful Docker mutation failed solely because SQLite publication failed.
2. **No database-only compensation:** never restore a pin or recreate the previous container solely in response to history or audit persistence failure. Recovery after a genuine workload failure remains separately guarded.
3. **Idempotent publication:** bounded attempts, stable deduplication/reconciliation for errors before commit and ambiguous errors *after* commit, and no duplicate/contradictory history or terminal state.
4. **Recovery safety:** rollback eligibility, active image protection and source/backup evidence stay safe when history or terminal status is missing/ambiguous. Do not silently expire the sole usable recovery point.
5. **Persistent unavailability:** distinguish observed success from unknown persistence; do not claim durable success if writes cannot be verified. Define explicit CLI exit/error output, agent logs and web operation visibility, including what a later operator must reconcile.
6. **Transaction ownership:** preserve single-transaction atomic publication where required; do not hold SQLite transactions across Docker or Compose effects. Maintain core/web separation, existing locks and schema compatibility.

## Required design decisions before coding

- Define an explicit outcome/state matrix: workload `not started / failed / succeeded / uncertain` × publication `not attempted / committed / ambiguous / unavailable`, including operator-facing labels.
- Specify the durable correlation/idempotency key for each CLI/web operation, how an ambiguous commit is queried, and whether the existing `operation_runs` mechanism suffices. Any new persistence mechanism or schema change requires separate review.
- Define retry limits and bounded delays; the rule when every write fails; how a terminal `finish_operation` failure is handled without fabricating a FAILED workload.
- Define rollback eligibility and protection across updates, pinned updates, CLI/web rollback and Compose apply; clarify whether a pre-mutation intent or fence is needed before the Docker boundary. Cross-reference G3 [issue #10](https://github.com/rdna897/upt/issues/10), without silently implementing it.
- Define compatibility and staged rollout/rollback requirements for existing schema 9 and deployed binaries.

## Evidence and proposed implementation slicing

The baseline is `tests/test_sqlite_completion_characterisation.py`, which intentionally asserts **current defective behaviour**. It uses guarded, synthetic SQLite faults for pre-commit failure, ambiguous post-commit acknowledgement and persistent unavailability. Update these assertions **only** in a subsequent, separately approved implementation PR with explicit replacement tests.

Plan separately reviewed, bounded implementation slices: R1 ordinary update, R2 pinned update, R1b CLI/web rollback, then R3 cross-path consistency/Compose apply and final policy integration. A slice must not weaken previously approved safety invariants or break the namespace-update publication contract.

## Design acceptance gate

Before implementation: document each affected call path; a complete state/outcome matrix; no-database and ambiguous-commit behaviour; rollback-protection invariants; retry/reconciliation semantics; synthetic test plan; migration/compatibility impact; risks and open decisions. Obtain an independent ChatGPT review and explicit owner decision.

**This draft authorises documentation and analysis only.** No `src/`, database/schema, CI-policy, live Docker or production changes. Do not merge the design PR without owner approval.
