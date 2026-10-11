# G2 — mutation completion and SQLite publication (design brief)

**Status:** Design proposal for independent review; **not approved for implementation or merge**. Owner approval of this policy and of the open decisions below is required before any source change.
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

## 1. Current behaviour by call path

Each row names the mutation path, the completion write that makes its outcome durable, the current behaviour when that write fails, and the evidence that fixes the behaviour.

| Path | Completion write | What happens when it fails | Evidence |
| --- | --- | --- | --- |
| Ordinary update (`do_update`, `src/docker_update_manager/operations.py:358`) | `state.record(... result="SUCCESS" ...)` inside the workload try | Failure enters the handler at `operations.py:363-376`, which writes FAILED with no new image identity (unguarded, `operations.py:374`) and re-raises; under persistent unavailability the handler write also fails, replaces the original error, and nothing is durable | `tests/test_sqlite_completion_characterisation.py` class `OrdinaryUpdateHistoryFailureCurrentBehaviour` (4 tests) |
| Pinned update (`_do_pinned_update`, `operations.py:156`) | Same window | The handler (`operations.py:160-224`) restores the old pin and, because recreation had started, recreates the previous digest — a compensating Docker mutation caused only by the database failure | `PinnedUpdateHistoryFailureCurrentBehaviour` (5 tests) |
| CLI rollback (`do_rollback`, `operations.py:425`) | Single `record(ROLLED BACK)` after the effect, with no handler | Failure raises after Compose sources were restored and the service recreated; no history row; the superseded update row remains the selected rollback point | `CliRollbackHistoryFailureCurrentBehaviour` |
| Web rollback (`do_web_rollback`, `operations.py:564`; adapter `src/docker_update_manager/webservice.py:2115-2177`) | `record(ROLLED BACK)` then `finish_operation(succeeded)` (`webservice.py:2134`) inside the same try | `sqlite3.Error` is not in the handler tuple (`operations.py:574`), so the adapter fallback (`webservice.py:2147-2165`) can write `FAILED / NO CHANGES MADE` with "review became stale before mutation" although the service was rolled back; a `finish_operation(succeeded)` failure is converted into a failure audit plus `finish_operation(failed)` | No characterisation test yet (Stage 6 synthetic probe only) |
| Web update adapter (`webservice.py:1931-1980`) | `finish_operation(succeeded)` (`webservice.py:1956`) inside the try | A terminal-write failure is reported as failed (`webservice.py:1977`); any exception from `do_update`, including a SQLite completion failure, becomes `failed` | Synthetic plan in section 6 |
| Compose apply (`webservice.py:2622-2671`) | Reference behaviour | `write_history` deduplicates by `operation_id` before inserting; bounded `COMPOSE_HISTORY_ATTEMPTS = 3` (`webservice.py:61`) with 0.2 s × attempt back-off; on exhaustion it keeps the factual outcome and adds a warning, but surfacing that warning needs `finish_operation` (`webservice.py:2669`), itself unguarded | Implemented reference path in `webservice.py` |
| Namespace update / Namespace Apply | Publish history and terminal operation state atomically in one transaction | `state.py:442-474` for namespace update; Namespace Apply reconciles ambiguous commits via `namespace_apply_published`, `state.py:1448` | Out of scope for change; reference pattern |

**Related surfaces.** These are not replaced by the policy, but the policy must not make them worse.

- (a) CLI `main` catches only `ValueError, RuntimeError, CommandError, yaml.YAMLError` (`src/docker_update_manager/cli.py:540`), so a raw `sqlite3.OperationalError` escapes as a traceback with exit status 1 rather than an `EXIT_*` code (`cli.py:26`: 0/10/20/30).
- (b) `upt cleanup` removes dangling images not in `protected_images` (`cli.py:418-425`); after a mutable-tag update whose history row was never committed, the previous image is dangling and unprotected, so the sole rollback image can be removed.
- (c) `State.record` writes the history row, `protected_images` and `rollback_refs` in one transaction (`state.py:442-458`), so protection exists only if the completion row commits.
- (d) `recover_abandoned_operations` (`state.py:777`) marks old active operations interrupted without consulting committed history.

## 2. Definitions

- **Workload outcome W** (factual, from Docker/Compose observation only). Values:
  - `not_started` — refused or blocked before any source write or Docker mutation.
  - `failed` — the mutation was attempted and the post-condition was not met; includes automatically recovered and manual-recovery-required outcomes.
  - `succeeded` — post-mutation verification passed: exact service identity, running, not unhealthy/starting as currently checked.
  - `uncertain` — a mutation command was issued but its result could not be observed, for example a recreate timed out or discovery failed afterwards.

- **Workload completion point** — the line at which W becomes `succeeded`: immediately after the existing verification and before the completion write (ordinary update `operations.py:355-357`, pinned update `:152-155`, CLI rollback `:423`, web rollback `:561-563`).
  Nothing after this point may change W.

- **Publication outcome P** — one of:
  - `not_attempted`;
  - `committed` — the row returned by the insert or found by the reconciliation read;
  - `ambiguous` — an attempt raised and the last reconciliation read also failed, so whether a row committed is unknown;
  - `unavailable` — all bounded attempts failed and the last successful reconciliation read proved no row exists, or the database could not be opened at all.

- **Completion key** — see section 4 (P3).

- **Recovery evidence** — the previous image (protected by `protected_images`/`rollback_refs`), the Compose backup directory (`state root/backups/<stamp>` created by `backup_files`, `src/docker_update_manager/compose.py:125`), and for web rollback the pre-rollback recovery backup.

## 3. Outcome and publication matrix

Rows are the factual workload outcome W; columns are the publication outcome P. Each cell gives the operator label and the required behaviour.

| Workload outcome W | P = committed | P = ambiguous | P = unavailable |
| --- | --- | --- | --- |
| `not_started` | "Blocked — no changes made" (BLOCKED row) | "Blocked — no changes made; record not verified" | "Blocked — no changes made; record not verified" |
| `failed` | "Failed", plus "automatic recovery succeeded" or "manual recovery required" as today | "Failed — record not verified; manual reconciliation required" | "Failed — record not verified; manual reconciliation required" |
| `succeeded` | "Succeeded" | "Succeeded in Docker — History record unverified (may exist)" | "Succeeded in Docker — not recorded; rollback protection missing" |
| `uncertain` | Existing failure label for the path, plus "outcome uncertain" | Same, plus "record not verified; manual reconciliation required" | Same, plus "record not verified; manual reconciliation required" |

For `not_started`, no Docker action is possible and the refusal is reported as today.
For `failed`, the original workload error stays primary; the publication failure is attached to it and never substituted for it.
For `succeeded`, the label is never FAILED, never "no changes made", and no compensation runs.
For `uncertain`, the row keeps each path's existing failure semantics (`result` and `rollback_result` exactly as written today) and adds details `workload_outcome="uncertain"`; G2 does not change recovery or labelling for genuine workload uncertainty beyond that key, and the existing guarded recovery rules apply unchanged.

`not_attempted` occurs only for interruption (process killed), which is owned by G3 ([issue #10](https://github.com/rdna897/upt/issues/10)).

History `result` and `rollback_result` vocabularies are unchanged (schema 9 compatible).
New facts go into additive `details` JSON keys `completion_id`, `workload_outcome`, and, in the adapter result only, `publication`.

## 4. Policy rules

### P1 — Factual outcome

The completion write happens after the workload completion point and outside the workload failure handler.
Structurally this is a separate try, or a handler that distinguishes a completion-publication exception.
A publication failure never enters the workload failure/recovery path, never writes FAILED or BLOCKED for a succeeded workload, and never triggers source restoration or recreation (this removes the R2 compensation).
Genuine workload-failure recovery at the pre-completion-point stage stays exactly as today, including `pre_recovery_check` guards.

### P2 — Shared publisher

One core helper (proposed module `src/docker_update_manager/completion.py`; the name is not binding) serves update, pinned update, CLI rollback, web rollback, failure/BLOCKED rows and Compose apply.
Signature concept: `publish(state, key, row fields) -> (P, history_id or None)`.
Each attempt is one `State.record` transaction; no transaction is held across Docker or Compose effects or sleeps.
The update lock already held by the caller remains held throughout.

### P3 — Completion key

A 32-hex `completion_id` is generated in core before the first source write or Docker mutation.
Web operations use their existing `operation_id` (already written into history `details.operation_id`); CLI operations generate a uuid4 hex.
The key is stored in history `details` JSON as `completion_id` (web rows: equal to `operation_id`).
Lookup is a bounded `history_for_service(stack, service)` scan filtered by `action` and parsed `details.completion_id`, the same pattern Compose apply uses today (`webservice.py:2625-2628`).
There is no `json_extract` dependency, no new table and no unique index (that would be a schema change); uniqueness is guaranteed by a single writer per key under the existing lock.
The CLI key exists only in process memory until the completion row commits; it deduplicates retries within one process but is not a durable pre-mutation intent (that is G3, [issue #10](https://github.com/rdna897/upt/issues/10)).

### P4 — Bounded attempts

Maximum 3 attempts (the same as `COMPOSE_HISTORY_ATTEMPTS`), with back-off 0.2 s then 0.4 s.
Retry only `sqlite3.OperationalError` (busy, locked, I/O, or cannot open).
Do not retry `sqlite3.IntegrityError`, `ValueError` (for example namespace publication authorisation), `TypeError` or programming errors; these stop further attempts immediately and the error class is logged; P is then classified by the P5 reconciliation read (normally `unavailable`, because the failed transaction rolled back).
Worst-case wall time is approximately 3 × 30 s SQLite busy timeout (`state.py:184`, `:195`) + 0.6 s, about 91 s; implementations must not exceed this bound.

### P5 — Ambiguous-commit reconciliation

After any failed attempt, perform a read-only reconciliation (`State.read`) by completion key before the next attempt and after the last one.
Found means committed (use that id; never insert again).
Read succeeded and absent means it is safe to retry.
Read failed means, if attempts remain, retry with read-before-insert; otherwise P is `ambiguous`.
Rationale: with one connection per transaction, once `commit()` returns or raises there is no later in-flight commit, so a successful read is definitive.
If reconciliation finds a row for the key with a different `result` (a contradiction), do not write another row: P is `committed` for idempotency purposes, and the contradiction is reported in the P7 log record and adapter result (`contradiction: true`) for operator review.

### P6 — Persistent unavailability

After the bound, stop: no further writes for this completion (no FAILED fallback) and no compensating Docker action.
Core raises a typed `CompletionPublicationIncomplete` (proposed name; subclass of `RuntimeError`, so existing CLI handling maps it) carrying W, P, completion key, action, stack and service, old and new image ids and the backup path.
For W other than `succeeded`, the original workload exception remains the raised/primary error and the publication outcome is attached (exception chaining or attribute), never replacing it.

### P7 — Operator visibility independent of SQLite

(a) Process log: one structured ERROR record on a dedicated logger (proposed `docker_update_manager.completion`) with completion key, action, service, W, P, old and new image ids, backup path, error class and a bounded (up to 200 chars) SQLite message; never environment content, credentials or registry auth.
(b) CLI: a stderr message naming the service, W, P, the completion id, the running image id, the previous image id, and the instruction "do not run `upt cleanup` or retention for this service until reconciled"; exit status per open decision D1 (recommended `EXIT_FATAL` = 30).
CLI completion paths must not leak raw `sqlite3` tracebacks.
The automatic post-command retention and snapshot steps in `cli.py:531-532` must remain skipped when publication is incomplete (today they are skipped only because the exception propagates; S1 must preserve this deliberately).
G2 adds no reconciliation command: "reconcile" means the operator verifies the running image against the reported identities and keeps the reported previous image and backup until a durable record exists. Whether a bounded reconciliation tool is in scope is open decision D8.
(c) Web: the operation result carries `workload`, `publication`, `completion_id`, `manual_reconciliation_required: true` and a warning; terminal status per open decision D2 (recommended `succeeded` plus warning, matching the Compose apply precedent).
If SQLite is wholly unavailable the web surface cannot read anything; the log record is then the authoritative evidence.

### P8 — Terminal operation state (web)

Publish History first, then `finish_operation`, as today.
`finish_operation` gets the same bounded attempts; it is already idempotent (`UPDATE … WHERE status IN active`, `state.py:949-985`): on rowcount 0, read the status back; if it equals the intended status it is committed, otherwise log a contradiction.
A failed success-terminal write must never fall through to `finish_operation(failed)` or a failure audit.
If the terminal write cannot be completed the operation remains active, and `recover_abandoned_operations` must, before marking it interrupted, look up a committed history row by `operation_id`/`completion_id` and derive the terminal state from it (succeeded plus warning for a committed success).
The web rollback fallback that writes `NO CHANGES MADE` may run only when the adapter can prove the mutation boundary was not crossed.

### P9 — Rollback eligibility versus protection

Protection is unchanged: every non-BLOCKED row with `old_image_id` protects it (`state.py:454-457`).
Eligibility is unchanged (latest SUCCESS `update`, unexpired ref, backup present, `operations.py:387-393`) plus a new guard: rollback refuses when the selected row `new_image_id` is known and differs from the running service `image_id` ("History does not match the running image; reconcile first").
This stops the R1 case where rollback silently targets an earlier point (characterisation test `test_current_behaviour_failed_success_write_makes_rollback_select_an_earlier_point`) and the R1b case where an unrecorded completed rollback leaves the superseded update selectable (`CliRollbackHistoryFailureCurrentBehaviour`).
Never silently expire the sole usable rollback point; an operator-visible unreconciled completion must not be resolved by retention.
Residual gap: when P is `unavailable` there is no `protected_images` row, so the previous image is protected only by operator action until G3 provides pre-mutation intent/protection; see D3.

### P10 — Transaction ownership and compatibility

No SQLite transaction spans Docker or Compose effects or back-off sleeps; History and protection stay one transaction (`State.record`).
Core/web separation and existing locks are unchanged; schema 9 is unchanged.
Namespace update and Apply contracts are unchanged; do not route namespace publication through the new helper without separate approval.

## 5. Per-path application

| Path | Completion point | Key | Success publication | Failure-path publication | Removed behaviour |
| --- | --- | --- | --- | --- | --- |
| Ordinary update | `operations.py:357` | CLI uuid or web operation_id | SUCCESS with full new identity via the publisher; output "Updated …" only after committed | FAILED/BLOCKED via the publisher, original error primary | FAILED row after a successful workload |
| Pinned update | `operations.py:152-155` | CLI uuid or web operation_id | SUCCESS with the new pin/digest via the publisher | FAILED/BLOCKED via the publisher; guarded genuine-failure recovery unchanged | Pin restore and recreate triggered by publication failure |
| `--pin` follow-on (`operations.py:361`) | Reuses the update completion | The update key | Runs only if the update publication is committed; otherwise skipped and reported | — | Pin attempted after an unrecorded update |
| CLI rollback | `operations.py:423` | CLI uuid | ROLLED BACK via the publisher | No handler today; nothing added beyond P6 | Raw sqlite error escaping after a completed rollback |
| Web rollback | `operations.py:561-563` | operation_id | ROLLED BACK via the publisher; adapter terminal per P8 | FAILED via the publisher; NO CHANGES MADE only with pre-boundary proof | Misreport as NO CHANGES MADE; success converted to failed on terminal-write failure |
| Web update adapter | Reuses the update completion | operation_id | Maps `CompletionPublicationIncomplete` per P7/P8 instead of `failed` | Same mapping, original workload error primary | Web reports a successful update as failed |
| Compose apply | `webservice.py:2622-2671` | operation_id | Moves onto the shared publisher (key = operation_id, behaviour preserved) | Same factual-outcome-plus-warning behaviour | Ad-hoc retry loop replaced; terminal write per P8 |

## 6. Synthetic test plan

All tests use the `tests/sqlite_faults.py` harness (fault modes `before_commit`, `after_commit`, `unavailable`; matchers `history_insert`, `terminal_operation_update`), temporary databases, every Docker/Compose/registry boundary mocked, and `time.sleep` patched.
For each of ordinary update, pinned update, CLI rollback, web rollback and the web update adapter:

1. `before_commit` ×1 — the retry commits exactly one success row; no FAILED row; the Docker call sequence is identical to a no-fault run.
2. `after_commit` ×1 — reconciliation finds the row; exactly one row; no FAILED row; no retry insert.
3. `before_commit` ×3 — P is `unavailable`; no history row; `CompletionPublicationIncomplete`; one ERROR log on the completion logger; no compensating Docker call; the pinned source keeps the new pin.
4. `unavailable` — as case 3, plus the CLI exit status and stderr contract (no traceback).
5. Reconciliation read failure after an `after_commit` fault — P is `ambiguous` and reported as such.
6. Failure-path row under unavailability — the original workload error is preserved as primary.
7. Web: a `terminal_operation_update("succeeded")` fault is never converted to failed; abandoned-operation recovery derives the terminal state from committed history.
8. Rollback eligibility guard — a mismatched `new_image_id` refuses; a matching row still rolls back.
9. Bound — the attempt count and total sleep are asserted.

Each implementation slice replaces the matching characterisation tests in `tests/test_sqlite_completion_characterisation.py` with explicit replacement tests in the same PR.
Tests for genuine workload-failure recovery (including `pre_recovery_check` refusal and operator-edit protection) must remain and pass.

## 7. Implementation slices

Separately reviewed PRs, each independently revertible, none merged without owner approval:

- **G2-S1 (R1):** shared publisher, typed exception, completion logger, ordinary update, web update adapter mapping (required in the same slice, otherwise web reports a successful update as failed), CLI surface.
- **G2-S2 (R2):** pinned update; remove database-triggered compensation; `--pin` follow-on gating.
- **G2-S3 (R1b):** CLI and web rollback; web fallback gating; rollback eligibility guard (P9).
- **G2-S4 (R3):** Compose apply onto the publisher; terminal-state policy P8 including `recover_abandoned_operations`; characterise (tests only, no behaviour change without approval) the namespace-update ambiguous-commit path; final cross-path consistency review.

## 8. Compatibility and rollout

No schema migration; `CORE_SCHEMA_VERSION` stays 9 (`state.py:119`).
Additive `details` keys only, which older binaries ignore.
CLI success rows gain JSON `details` (previously none): S1 must verify every History reader tolerates JSON details on CLI rows (web rows already carry JSON).
Rows written by new binaries remain readable by deployed binaries, so per-slice rollback is a binary revert.
Production freeze stays in force; no deployment is implied by any slice.

## 9. Open decisions for owner

- **D1 — CLI exit status** for W = `succeeded` with P not `committed`.
  Recommended 30 (`EXIT_FATAL`, non-zero because durable success is unverified); alternatives 20 (`EXIT_PARTIAL`, but that currently means something else) or a new code (a contract change).
- **D2 — Web terminal status** for the same case.
  Recommended `succeeded` plus warning and `manual_reconciliation_required` (Compose apply precedent; no new status); alternative `failed` (misreports the workload) or a new status (a wire/UI contract change).
- **D3 — Residual protection gap** when no SQLite write succeeds.
  Recommended accept for G2 with P7 operator guidance and close it in G3 ([issue #10](https://github.com/rdna897/upt/issues/10)) via pre-mutation intent that also protects the previous image before the Docker boundary; alternative require a pre-Docker protection write inside G2 (the semantics of `protected_images` rows without a history id need separate design review) or a non-SQLite journal (a new persistence mechanism, separate review).
- **D4 — Accept the rollback running-image match guard** (P9) as a behaviour change.
  Side effects: a second rollback after a completed rollback is refused (the latest SUCCESS update no longer matches the running image), and so is rollback after an out-of-band image change; both now require operator reconciliation instead of proceeding.
- **D5 — Retry bound** (3 attempts, up to about 91 s worst case under lock) acceptable, or lower the per-attempt busy timeout for completion writes.
- **D6 — Namespace-update ambiguous commit:** characterise only in S4, or fix within G2.
- **D7 — `do_pin`** (`operations.py:70`) and other single-write mutation records (pin, removal): include in G2-S4 or defer to Stage 5.
- **D8 — Reconciliation tool:** recommended none in G2 (without durable intent there is nothing reliable to reconcile from once the process exits); provide one with G3. Alternative: a bounded, read-mostly `upt` reconciliation command in G2-S4 (separate design).

## 10. Risks

- Longer lock hold under SQLite contention, bounded by P4.
- App-level deduplication relies on a single writer per key, which holds under the update lock and per-operation worker.
- JSON details on CLI rows (compatibility check in S1).
- Operators ignoring the CLI warning, mitigated by the non-zero exit and the structured log.
- The D3 protection gap remains until G3.

## 11. Design acceptance gate

Before implementation: document each affected call path; a complete state/outcome matrix; no-database and ambiguous-commit behaviour; rollback-protection invariants; retry/reconciliation semantics; synthetic test plan; migration/compatibility impact; risks and open decisions. Obtain an independent ChatGPT review and explicit owner decision.

Independent ChatGPT review of this PR must be recorded, owner decisions D1–D8 must be recorded in this file, and only then may G2-S1 start in a separate PR.

**This draft authorises documentation and analysis only.** No `src/`, database/schema, CI-policy, live Docker or production changes. Do not merge the design PR without owner approval.
