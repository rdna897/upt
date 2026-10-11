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

| Path | Completion write | What happens when it fails | Evidence |
| --- | --- | --- | --- |
| Ordinary update (`do_update`, `src/docker_update_manager/operations.py:358`) | `state.record(... result="SUCCESS" ...)` inside the workload try | The handler (`operations.py:363-376`) writes FAILED with no new image identity (unguarded, `operations.py:374`) and re-raises; under persistent unavailability the handler write also fails, replaces the original error, and nothing is durable | `tests/test_sqlite_completion_characterisation.py`, `OrdinaryUpdateHistoryFailureCurrentBehaviour` (4 tests) |
| Pinned update (`_do_pinned_update`, `operations.py:156`) | Same window | The handler (`operations.py:160-224`) restores the old pin and, because recreation had started, recreates the previous digest: a compensating Docker mutation caused only by the database failure | `PinnedUpdateHistoryFailureCurrentBehaviour` (5 tests) |
| CLI rollback (`do_rollback`, `operations.py:425`) | Single `record(ROLLED BACK)` after the effect, no handler | Raises after sources were restored and the service recreated; no history row; the superseded update remains the selected rollback point | `CliRollbackHistoryFailureCurrentBehaviour` |
| Web rollback (`do_web_rollback`, `operations.py:564`; adapter `src/docker_update_manager/webservice.py:2115-2177`) | `record(ROLLED BACK)`, then `finish_operation(succeeded)` (`webservice.py:2134`) in the same try | `sqlite3.Error` is not in the handler tuple (`operations.py:574`), so the adapter fallback (`webservice.py:2147-2165`) can write `FAILED / NO CHANGES MADE` ("review became stale before mutation") although the service was rolled back; a terminal-write failure becomes a failure audit plus `finish_operation(failed)` | Stage 6 synthetic probe only |
| Web update adapter (`webservice.py:1931-1980`) | `finish_operation(succeeded)` (`webservice.py:1956`) inside the try | A terminal-write failure is reported as failed (`webservice.py:1977`); any exception from `do_update`, including a completion-write failure, becomes `failed`. The mutation boundary is tracked only in memory (`webservice.py:1874-1877`) | Section 6 plan |
| Compose apply (`webservice.py:2622-2671`) | Deduplicated `write_history` by `operation_id`, `COMPOSE_HISTORY_ATTEMPTS = 3` (`webservice.py:61`) | Keeps the factual outcome and adds a warning on exhaustion, but surfacing it needs `finish_operation` (`webservice.py:2669`), itself unguarded. Persists `mutation_started` before invocation (`state.py:1602-1611`) | Reference path |
| Namespace update / Namespace Apply | History and terminal state in one transaction (`state.py:442-474`); ambiguous Apply commits re-read via `namespace_apply_published` (`state.py:1448`) | Namespace update commits image protection and a fence **before** Compose (`mark_namespace_update`, `state.py:1075-1095`) | Out of scope for change; reference patterns |

**Related surfaces** (the policy must not make them worse):

- (a) CLI `main` catches only `ValueError, RuntimeError, CommandError, yaml.YAMLError` (`src/docker_update_manager/cli.py:540`); a raw `sqlite3.OperationalError` escapes as a traceback with exit status 1 instead of an `EXIT_*` code (`cli.py:26`: 0/10/20/30).
- (b) `upt cleanup` removes dangling images not in `protected_images` (`cli.py:418-425`). After a mutable-tag update whose history row never committed, the previous image is dangling and unprotected, so the sole rollback image can be removed.
- (c) `State.record` writes the history row, `protected_images` and `rollback_refs` in one transaction (`state.py:442-458`); today protection exists only if the completion row commits.
- (d) Retention treats a `protected_images` row with no matching rollback ref (including a NULL `history_id`) as **unresolved** and refuses removal, even under `--override-protection` (`src/docker_update_manager/retention.py:19-31`, `:137-144`, merged in R10 #14). Retention deletes only resolved protection rows (`retention.py:312`, `:325`).
- (e) `recover_abandoned_operations` (`state.py:777-866`) marks every stale active web update/rollback `failed` with "Agent stopped while this update was active" (`state.py:810-811`) without consulting History or any durable boundary marker. Only namespace update and Compose apply have durable markers.
- (f) Compose backups (`backups/<stamp>`, `compose.py:125`) expire by age only (`retention.py:49-61`, default 7 days), whether or not a history row references them. This is pre-existing and applies equally to committed rollback points.
- (g) `State.connect` (`state.py:263-274`) does not tell its caller whether an exception arose before `commit()` (rolled back, definitely not committed) or from `commit()` (outcome unknown). Every connection uses a fixed 30 s timeout and busy timeout (`state.py:184`, `:195`).
- (h) The operation status vocabulary is `queued / running / finalizing / succeeded / failed / blocked` (`state.py:136`, `:802-805`). It has no status for "outcome not established". The `status` column has no CHECK constraint (`state.py:72-78`), but `webapp.py`, `operation_presentation.py` and `static/operation.js` interpret the vocabulary.

## 2. Definitions

- **Workload outcome W** (factual, from Docker/Compose observation only):
  - `not_started`: refused or blocked before the mutation boundary;
  - `failed`: mutation attempted and the post-condition not met (including automatically recovered and manual-recovery-required outcomes);
  - `succeeded`: post-mutation verification passed (exact service identity, running, not unhealthy/starting as currently checked);
  - `uncertain`: a mutation may have occurred but its result was not observed (recreate timed out, discovery failed afterwards, or the process stopped after the boundary).
- **Mutation boundary**: the first action that can change the image store, a Compose source or a container. For the update paths this is the first `side_effect_started=True` before the pull (`operations.py:124`, `:308`, `:323`). For rollback it is the first source write (`operations.py:410`, `:535`).
- **Workload completion point**: where W becomes `succeeded`, immediately after the existing verification and before the completion write: ordinary update `operations.py:355-357`, pinned update `:152-155`, CLI rollback `:423`, web rollback `:561-563`. Nothing after this point may change W.
- **Publication outcome P** for one completion row:
  - `committed`: exactly one row with the completion key exists and its factual fields match (P5);
  - `not_committed`: absence of the key has been **established** (a successful read found no row, or the failed transaction is known to have rolled back);
  - `ambiguous`: a commit may have happened and absence could not be established before the deadline;
  - `contradictory`: a row with the key exists but its factual fields differ, or more than one row has the key. This is **never** successful publication.
- **Terminal publication**: the web `finish_operation` write, kept distinct from history publication.
- **Recovery evidence**: the previous image (protected by `protected_images`), the Compose backup directory, the web pre-rollback recovery backup, and the completion marker (P11).

## 3. Outcome and publication matrix

Operator labels and required behaviour. "Record not verified" means P is `not_committed`, `ambiguous` or `contradictory` after the deadline.

| W | P = committed | Record not verified |
| --- | --- | --- |
| `not_started` | "Blocked — no changes made" (BLOCKED row) | "Blocked — no changes made; record not verified". Nothing changed. A marker write that failed ambiguously may leave a pending protection row, which only fails closed |
| `failed` | "Failed", plus "automatic recovery succeeded" or "manual recovery required" as today | "Failed — record not verified; manual reconciliation required". The original workload error stays primary |
| `succeeded` | "Succeeded" | "Succeeded in Docker — not durably recorded; manual reconciliation required". Never FAILED, never "no changes made", no compensation; the previous image stays protected by the P11 marker |
| `uncertain` | The path's existing failure label plus "outcome uncertain" | Same, plus "record not verified; manual reconciliation required" |

`contradictory` is additionally reported as "History contradiction" with both identities. For `uncertain`, each path keeps its existing `result`/`rollback_result` and adds `details.workload_outcome="uncertain"`; G2 does not change recovery for genuine workload uncertainty. History `result`/`rollback_result` vocabularies are unchanged. New facts go in additive `details` keys (`completion_id`, `workload_outcome`) and in the operation result (`workload`, `publication`, `outcome_verified`).

## 4. Policy rules

### P1 — Factual outcome

The completion write runs after the workload completion point and outside the workload failure handler (a separate try, or a handler that distinguishes completion-publication exceptions). A publication failure never enters the failure/recovery path, never writes FAILED/BLOCKED for a succeeded workload, and never triggers source restoration or recreation (this removes the R2 compensation). Genuine pre-completion-point recovery, including `pre_recovery_check` guards, is unchanged.

### P2 — Shared publisher

One core helper (proposed `src/docker_update_manager/completion.py`; the name is not binding) serves update, pinned update, CLI rollback, web rollback, failure rows and Compose apply. Each write is one `State` transaction. No transaction spans Docker/Compose effects or back-off sleeps. The caller's update lock stays held.

### P3 — Completion key

A 32-hex `completion_id` is fixed before the mutation boundary: web operations use their `operation_id` and CLI operations generate a uuid4 hex. It is stored in history `details.completion_id` and in the P11 marker. Lookup is a bounded `history_for_service(stack, service)` scan filtered by `action` and parsed `details.completion_id`, the pattern Compose apply already uses (`webservice.py:2625-2628`). There is no `json_extract` dependency. A unique index is **not** added in G2 (schema change): duplicate prevention relies on the P5 invariant, not on database uniqueness.

### P4 — One monotonic completion deadline

- One deadline per mutation, measured with `time.monotonic()` from the workload completion point (or from the failure point for failure rows). It covers **every** completion-side SQLite step: connection open, busy waits, history writes, reconciliation reads, back-off sleeps, the web terminal write and its read-back.
- Recommended budget: **60 s** (D5). This replaces the earlier "3 × 30 s + back-off ≈ 91 s" estimate, which bounded writes only.
- Each step receives `min(remaining, 30 s)` as its connection and busy timeout. This requires a `State`-level per-call timeout (an API addition with no schema change), because `_new_connection` currently fixes 30 s.
- Writes are retried only for `sqlite3.OperationalError`, and only as P5 permits. `IntegrityError`, `ValueError` (for example namespace publication authorisation), `TypeError` and programming errors stop further writes immediately; P5 reads may still classify the outcome.
- Back-off is 0.2 s, then 0.4 s, then 0.8 s (capped at 1 s), never past the deadline.
- **Exhaustion:** no new SQLite step starts after the deadline. A statement already executing is not interrupted (an in-progress commit cannot be safely abandoned); its outcome is classified by P5 with no further reads. The final classification stands: `not_committed`, `ambiguous` or `contradictory` all mean "record not verified". No insert ever happens after the deadline, so exhaustion cannot create a duplicate, and W is reported unchanged.

### P5 — Ambiguous commits and retry safety

**Invariant:** an insert for a completion key is never retried unless the key's absence has been established in the same publisher run, either by a successful read finding no row or because the failed transaction is known to have rolled back before `commit()`. G2 adds no database uniqueness, so no other condition permits a retry.

`State` must let the publisher distinguish "failed before `commit()`" (rolled back, `not_committed`) from "failed in or after `commit()`" (unknown). Until it can, every write failure is treated as unknown.

Before the first insert the publisher reads by key: an existing matching row is `committed` (no insert), a contradictory row is `contradictory` (no insert), and a failed read means no insert until a later read succeeds. Decision tree after each write attempt:

1. Write returned → re-read is not required → `committed`.
2. Write failed before `commit()` → `not_committed` established → retry permitted within the deadline (still read-before-insert).
3. Write failed in/after `commit()` → reconciliation read by key:
   - 3a. Read succeeds, no row → `not_committed` established → retry permitted.
   - 3b. Read succeeds, exactly one row whose factual fields match → `committed`; never insert again.
   - 3c. Read succeeds, a row with different factual fields or more than one row → `contradictory`; stop writing; report both identities; **not** success.
   - 3d. Read fails → **no insert**. Only reads are repeated, within the deadline. If none succeeds → `ambiguous`.
4. Persistent unavailability (connections cannot open) → reads and writes both fail. Classification is `not_committed` only if every write failed before `commit()`; otherwise `ambiguous`.

Factual fields compared: `action`, `result`, `stack`, `service`, `old_image_id`, `new_image_id` (when known), `details.completion_id` and `details.workload_outcome`. The same tree governs the P11 marker write and the terminal write. `finish_operation` is idempotent by its `WHERE status IN (active)` guard (`state.py:949-985`): rowcount 0 requires a read-back, and a different terminal status is `contradictory`.

### P6 — Unverified publication

When P is not `committed` after the deadline, the publisher stops. There is no FAILED fallback row and no compensating Docker action. Core raises a typed `CompletionPublicationIncomplete` (proposed name, a `RuntimeError` subclass) carrying W, P, the completion key, action, stack/service, old/new image ids and the backup path. For W ≠ `succeeded` the original workload exception stays primary, with the publication outcome attached and never substituted.

### P7 — Operator visibility independent of SQLite

- (a) **Log.** One structured ERROR record on a dedicated logger (proposed `docker_update_manager.completion`) with key, action, service, W, P, old/new image ids, backup path, error class and a SQLite message bounded to 200 characters. It never contains environment content, credentials or registry auth. When nothing is durable, this record is the authoritative evidence.
- (b) **CLI.** A stderr message stating the factual workload outcome and, separately, that publication was not verified, with the completion id, running and previous image ids, backup path, and a pointer to the manual procedure (section 5). Exit status **30** (D1). No raw `sqlite3` traceback. The automatic post-command snapshot and retention (`cli.py:531-532`) stay skipped; today that happens only because the exception propagates, and S1 must preserve it deliberately.
- (c) **Web.** See P8. A warning alone is never the protection mechanism; protection is P11.

### P8 — Web terminal publication and post-restart recovery (fail-closed)

Three cases are distinct:

1. **Terminal publication succeeds.** If history is `committed`, the terminal status follows W (`succeeded`, `failed`, `blocked`) with warnings as today. If history is not verified:
   - W = `not_started` or `failed`: these workload outcomes were observed, so the terminal status follows W, adding `publication`, `completion_id` and `manual_reconciliation_required: true`;
   - W = `succeeded`: the terminal status is **unresolved** (D9), with result `{workload: "succeeded", publication, completion_id, outcome_verified: false, manual_reconciliation_required: true}`. `succeeded` is used **only** when the history row is durably committed (D2);
   - W = `uncertain`: today's terminal mapping (`failed` with manual recovery required) is kept unless the D9 decision extends `unresolved` to in-process uncertain outcomes.
2. **Terminal publication fails** (deadline exhausted). The adapter never falls through to `finish_operation(failed)` or a failure audit. The operation stays active in the database, the P7 log record is written, and the worker exits normally, releasing the lock.
3. **Post-restart / post-worker reconciliation** (`recover_abandoned_operations`, which already requires the update lock as its liveness proof). For a stale update/rollback operation:
   - **No marker** and the operation was created by a P11-aware binary (`summary.completion_protocol >= 1`) → the boundary was provably not crossed → `blocked`, "no changes were made".
   - **No marker** on a legacy operation → today's behaviour is retained (`failed`, "check the container and History"), because absence proves nothing.
   - **Marker present** and exactly one matching committed history row (same completion key and `old_image_id` as the marker) → the terminal status the in-process adapter would have published for that row under case 1, with the warning "terminal state recovered after interruption".
   - **Marker present** and no row, a contradictory row, or reads that fail → **unresolved**. `mutation_performed: null`, `outcome_verified: false`, `manual_reconciliation_required: true`. Never `succeeded` or `failed`.
   - **Never replay.** Recovery issues no Docker or Compose command and does not restore sources. The marker, the pending protection row and the backups are retained.
   - If the database is unavailable at restart, recovery cannot run and the operation stays active; the API reports the database error rather than a status. The contract applies once the database is readable again.

The web rollback `NO CHANGES MADE` fallback (`webservice.py:2147-2165`) may run only when the adapter can prove the boundary was not crossed: no marker committed, and the in-memory boundary flag false.

**Status vocabulary (D9).** The current vocabulary cannot express "unresolved" without misusing `failed`. The recommended option is a new terminal status `unresolved` (an API/UI contract change, no schema change); see D9 for the alternatives and the required compatibility review. Until D9 is decided, no G2 slice may write an unverified outcome as `succeeded` or `failed`; slices that need it (S1, S3, S4) are blocked on D9.

### P9 — Rollback eligibility versus protection

Protection rules are unchanged except for P11. Eligibility (`operations.py:387-393`) gains one fail-closed guard: refuse when the selected SUCCESS row's `new_image_id` is known and differs from the running `image_id` ("History does not match the running image; reconcile first"). This stops the R1 case (`test_current_behaviour_failed_success_write_makes_rollback_select_an_earlier_point`) and the R1b case (`CliRollbackHistoryFailureCurrentBehaviour`) where an unrecorded outcome leaves a stale point selectable.

### P10 — Transaction ownership and compatibility

No SQLite transaction spans Docker/Compose effects or sleeps. History and its protection stay one transaction (`State.record`). Core/web separation, locks, schema 9 and the namespace update/Apply contracts are unchanged; namespace publication is not routed through the new helper without separate approval.

### P11 — Pre-mutation completion marker and enforceable protection (resolves D3)

Immediately before the mutation boundary, in one short `State` transaction:

1. Upsert `protected_images(image_id=<image to be replaced>, reason='pending completion <completion_id>', history_id=NULL)`. For updates this is the current `old_image_id`; for rollback it is the currently running image.
2. Web operations only: set `summary.completion_marker = {completion_id, old_image_id, backup}` and `summary.completion_protocol = 1` on the active `operation_runs` row. This mirrors `mark_compose_mutation_started` (`state.py:1602-1611`).

Rules:

- **Fail closed.** If the marker cannot be committed (P5 tree, with its own budget under the P4 mechanism; recommended 30 s), the mutation is refused before the boundary: W = `not_started`, nothing changed.
- **Upsert, not insert-or-ignore.** An existing history-linked row for the same image could later be resolved and deleted by retention while this completion is unverified. Replacing it with the pending, history-less row keeps the image unresolved-protected. On a committed completion row, `State.record` replaces the pending row with the normal history-linked protection (`state.py:454-457`), exactly as today. The only lifecycle change is the interval between the marker and the completion.
- **Enforcement.** `upt cleanup` excludes every `protected_images` image (`cli.py:420`). Retention refuses removal of any image with an unresolved (NULL-history) protection, even under `--override-protection` (`retention.py:28-31`, `:142-143`). So a failed or ambiguous completion leaves the previous image protected by existing, already-reviewed mechanisms rather than by a warning.
- **Release.** No G2 path deletes a pending row except its replacement by the completion's own committed row. Clearing an orphaned pending row is the manual procedure (section 5), until G3 provides a reviewed tool (D8). The cost of failing closed is retained disk space, never lost recovery evidence.
- **Precedent.** `mark_namespace_update` already commits `INSERT OR IGNORE INTO protected_images(image_id,reason)` with a NULL history id before Compose (`state.py:1094-1095`). P11 differs in using an upsert, for the reason above.
- **Compatibility limit.** Pre-R10 binaries deleted protection rows by image when removing expired images (removed in `9aca400`). The guarantee therefore holds only for binaries that include R10 (#14). Rolling back below R10 while pending rows exist is unsupported (D3b).
- **Backups.** Compose backup expiry by age (Related surface f) is pre-existing and not caused by publication failure. Retaining the backup of an unverified completion is optional decision D3c.

### P12 — Sequencing with G3

G3's durable CLI intent journal and interruption recovery (#10) is **not** a prerequisite for G2. P11 (slice G2-S0) is the smallest independently reviewable fail-closed safeguard: it reuses schema-9 constructs that existing retention and cleanup already enforce, and it is a **prerequisite for S1–S3**. G3 later supplies the durable CLI intent record, interruption recovery for CLI operations, and the reviewed reconciliation tool. P11 markers are designed to be read by G3 without migration.

## 5. Per-path application and manual reconciliation

| Path | Marker (P11) | Completion point | Key | Success publication | Failure-path publication | Removed behaviour |
| --- | --- | --- | --- | --- | --- | --- |
| Ordinary update | Before pull (`operations.py:308`/`:323`) | `operations.py:355-357` | CLI uuid / web `operation_id` | SUCCESS via publisher; "Updated …" printed only after `committed` | FAILED via publisher, original error primary | FAILED row after a successful workload |
| Pinned update | Before pull (`operations.py:124`) | `operations.py:152-155` | Same | SUCCESS with new pin via publisher | FAILED via publisher; guarded genuine-failure recovery unchanged | Pin restore and recreate triggered by publication failure |
| `--pin` follow-on (`operations.py:361`) | Uses `do_pin` (D7) | — | — | Runs only if the update is `committed`; otherwise skipped and reported | — | Pin after an unrecorded update |
| CLI rollback | Before first source write (`operations.py:410`) | `operations.py:423` | CLI uuid | ROLLED BACK via publisher | P6 only | Raw sqlite error after a completed rollback |
| Web rollback | Before first source write (`operations.py:535`) | `operations.py:561-563` | `operation_id` | ROLLED BACK via publisher; terminal per P8 | FAILED via publisher; NO CHANGES MADE only with pre-boundary proof | NO CHANGES MADE misreport; success→failed on terminal-write failure |
| Web update adapter | Via core | Via core | `operation_id` | Terminal per P8 | Terminal per P8 | Successful update reported as failed |
| Compose apply | Existing `mutation_started` | Existing | `operation_id` | Moves onto publisher; terminal per P8 | Unchanged factual outcome plus warning | Ad-hoc retry loop |

**Manual reconciliation procedure (documented interim; D8).** It is read-only apart from the final, explicitly approved step:

1. Take the completion id, service and image ids from the CLI message, the web result or the `docker_update_manager.completion` log.
2. Inspect the running container's image id (`docker inspect`) and compare it with the reported old and new ids.
3. Check History for a row with that `completion_id` (`upt history`).
4. Do not run `upt cleanup`, forced retention or manual image removal for the previous image until reconciled. P11 already blocks UPT's own removal paths.
5. Do not re-run the update or rollback to "repair" the record; P9 refuses an inconsistent rollback.
6. Release of the pending protection row or creation of a corrective History record needs a reviewed tool (G3). Until then, leave the row in place. Direct database edits are outside the supported procedure.

## 6. Synthetic test plan

All tests use `tests/sqlite_faults.py` (modes `before_commit`, `after_commit`, `unavailable`; matchers `history_insert`, `terminal_operation_update`), temporary databases, every Docker/Compose/registry boundary mocked, and a fake monotonic clock and sleep. Extending the harness with a read-failure fault and a marker-write matcher is part of S0/S1 (tests only).

For each of ordinary update, pinned update, CLI rollback, web rollback and the web update adapter:

1. `before_commit` ×1 → retry commits exactly one row; no FAILED row; Docker calls identical to a no-fault run.
2. `after_commit` ×1, read succeeds → `committed`; exactly one row; no second insert.
3. `after_commit` ×1 then the reconciliation read fails until the deadline → `ambiguous`; **no second insert attempted** (assert insert count = 1); exactly one row afterwards (the committed one).
4. `after_commit` ×1, read fails once then succeeds → `committed`; insert count = 1.
5. Pre-existing row with the same key and a different `result` or `new_image_id` → `contradictory`; no insert; reported as a contradiction, not success.
6. `before_commit` until the deadline → `not_committed`; no row; `CompletionPublicationIncomplete`; one ERROR completion log; no compensating Docker call; the pinned source keeps the new pin.
7. `unavailable` → as 6, plus CLI exit 30 with the stderr contract and no traceback.
8. Deadline: fake clock asserts total elapsed time ≤ budget across writes, reads and back-off, and no SQLite step starts after the deadline.
9. Failure-path row under unavailability → the original workload error stays primary.
10. P11: a marker-write failure refuses before any Docker call (W = `not_started`). After an unverified completion the previous image is in `state.protected()`, `upt cleanup` candidate filtering excludes it, and retention reports "SKIPPED - UNRESOLVED PROTECTION" even with override. A committed completion replaces the pending row with the history-linked row.
11. P11 upsert: an existing history-linked protection for the same image is replaced by the pending row, so expiring the older ref does not make the image removable.
12. Web P8: a `terminal_operation_update("succeeded")` fault is never converted to failed. Recovery with marker plus committed row → terminal from the row; marker and no row → unresolved; no marker with `completion_protocol=1` → blocked; legacy operation without marker → today's behaviour; no Docker call in any recovery case.
13. P9: a mismatched `new_image_id` refuses; a matching row still rolls back.

Each slice replaces the matching characterisation tests in `tests/test_sqlite_completion_characterisation.py` with explicit replacement tests in the same PR. Genuine workload-failure recovery tests (including `pre_recovery_check` refusal and operator-edit protection) must remain and pass.

## 7. Implementation slices

Separately reviewed PRs, each independently revertible, none merged without owner approval:

- **G2-S0 (prerequisite):** P11 marker and pending protection for ordinary update, pinned update and both rollbacks; `State` before/after-commit classification and per-call timeout (P4/P5 primitives); harness extensions. No change to completion behaviour yet.
- **G2-S1 (R1):** shared publisher, deadline, typed exception, completion logger, ordinary update, web update adapter (P8 cases 1–2), CLI surface. Needs S0 and D9.
- **G2-S2 (R2):** pinned update; remove database-triggered compensation; `--pin` gating. Needs S0 and S1.
- **G2-S3 (R1b):** CLI and web rollback; web fallback gating; P9 guard. Needs S0, S1 and D9.
- **G2-S4 (R3):** Compose apply onto the publisher; P8 case 3 in `recover_abandoned_operations`; namespace-update ambiguous-commit characterisation (tests only, D6); cross-path consistency review.

## 8. Compatibility and rollout

- No schema migration; `CORE_SCHEMA_VERSION` stays 9 (`state.py:119`).
- Additive `details` and operation `summary`/`result` keys only. CLI success rows gain JSON `details` (previously none); S1 must verify that every History reader tolerates this.
- Pending protection rows (P11) are honoured by deployed R10+ retention and by every version of `upt cleanup`. Downgrading below R10 while pending rows exist is unsupported (D3b).
- The `unresolved` operation status (if D9 is approved) requires `webapp.py`, `operation_presentation.py`, `static/operation.js`, SSE terminal detection and API clients to be updated together. Older web binaries' handling of an unknown status must be assessed before adoption.
- Per-slice rollback is a binary revert, within the R10 floor. The production freeze stays in force; no slice implies deployment.

## 9. Decision register

Provisional direction is as recorded from the owner's review instructions (2026-10-11). **None of these is final approval**; each needs explicit owner confirmation after the independent ChatGPT review.

| ID | Decision | Provisional direction | Still requires |
| --- | --- | --- | --- |
| D1 | CLI exit status for factual success with unverified publication | 30 (`EXIT_FATAL`), with separate factual-success and publication-failure messages | Confirmation |
| D2 | Web terminal status | `succeeded` with warning **only** when History is durably committed; otherwise unresolved | Confirmation; depends on D9 |
| D3 | Enforceable rollback protection and G2/G3 sequencing | Require enforceable protection: P11 in G2-S0 as a prerequisite for S1–S3; G3 not a prerequisite (P12) | Confirmation of P11 and the S0 sequencing |
| D3b | Binary rollback floor | Do not support downgrade below R10 (#14) while pending protection rows exist | Separate decision |
| D3c | Retain the Compose backup of an unverified completion beyond age expiry | Recommended: defer to G3; age expiry is pre-existing and equal for committed points | Separate decision |
| D4 | Rollback running-image identity guard (P9) | Accept, fail closed. Side effects: a second rollback after a completed rollback, and rollback after an out-of-band image change, are refused pending reconciliation | Confirmation |
| D5 | Retry bound | One monotonic completion deadline (P4); recommended 60 s | Confirmation of the budget value |
| D6 | Namespace-update ambiguous commit | Characterise first (tests only, S4); any fix is a separate decision | Confirmation |
| D7 | Unrelated single-write mutation records (`do_pin` at `operations.py:70`, removal, others) | Defer with explicit tracking; open a tracking issue before S1 merges | Tracking issue creation |
| D8 | Reconciliation tool | Defer the automated tool to G3; the section 5 manual procedure is the interim | Confirmation |
| D9 | Status vocabulary for unverified outcomes | Recommended: new terminal operation status `unresolved` (no schema change; API/UI contract change), used for an unverified succeeded publication and for marker-present interrupted operations. Sub-decision: whether also to use it for in-process `uncertain` outcomes, which today are `failed` with manual recovery. Alternatives: (b) `failed` with `outcome_verified:false`, which misuses a definitive status and conflicts with P8; (c) leave the operation non-terminal, which falsely shows it as in progress and keeps streams open | **Separate compatibility decision**, after assessing UI/API consumers and older web binaries; blocks S1, S3 and S4 |

## 10. Risks

- Lock hold under contention is bounded by the P4 deadline (recommended 60 s) plus at most one non-interruptible in-flight statement.
- Without a unique index, duplicate prevention depends on the P5 invariant and on single-writer-per-key under the update lock and per-operation worker.
- P11 retains images whose completion stays unverified until manual or G3 reconciliation: disk cost by design.
- The P11 upsert re-links protection for a shared image id earlier than today (at the marker rather than at completion); the end state after a committed completion is unchanged.
- D9 touches the web wire contract.
- Backup age expiry for unverified completions (D3c).

## 11. Review history

- **Opus review of the first draft** (commit `eb3bd3b`): corrected citations, the scope of the uncertain outcome, and the reconciliation gaps.
- **Independent ChatGPT architecture review of `eb3bd3b`:** two High and two Medium findings, all accepted after checking against the code:
  - (H1) P8 could not reconstruct an outcome from absent History → P8 rewritten as a fail-closed three-case contract with durable markers and an unresolved status (D9);
  - (H2) no durable protection when nothing commits → P11 pre-mutation marker with pending protection, enforced by existing cleanup/retention, sequenced as G2-S0 (P12);
  - (M3) retry after an ambiguous commit with a failed read could duplicate → P5 invariant and decision tree, `contradictory` outcome, tests 3–5;
  - (M4) the deadline bounded writes only → P4 single monotonic deadline covering every completion-side step.

## 12. Design acceptance gate

Before implementation: document each affected call path; a complete state/outcome matrix; no-database and ambiguous-commit behaviour; rollback-protection invariants; retry/reconciliation semantics; synthetic test plan; migration/compatibility impact; risks and open decisions. Obtain an independent ChatGPT review and explicit owner decision.

The independent ChatGPT review of this revision must be recorded, and owner decisions D1–D9 (including D3b and D3c) must be recorded in this file. Only then may G2-S0 start in a separate PR. S1–S4 additionally depend on the prerequisites listed in section 7.

**This draft authorises documentation and analysis only.** No `src/`, database/schema, CI-policy, live Docker or production changes. Do not merge the design PR without owner approval.
