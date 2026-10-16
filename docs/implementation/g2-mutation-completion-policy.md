# G2 — mutation completion and SQLite publication (design brief)

**Status:** G2 policy decisions D1–D10 (including D3b and D3c) accepted as the author-approved design direction on 2026-10-16. PR #15 remains documentation-only and awaits final author review; this policy acceptance is not authorisation to implement S0b, migrate schema, merge or deploy.
**Tracking:** [issue #9](https://github.com/rdna897/upt/issues/9) (S6-R1, R1b, R2, R3).
**Prerequisites and merged groundwork:** [Stage 6a ownership assessment](stage6-sqlite-state-ownership-review.md); [characterisation PR #13](https://github.com/rdna897/upt/pull/13), [R10 PR #14](https://github.com/rdna897/upt/pull/14), [S0a SQLite primitives PR #16](https://github.com/rdna897/upt/pull/16), and [cleanup protection PR #19](https://github.com/rdna897/upt/pull/19).
**Deployment:** Production freeze remains in force. No Docker changes or live databases in development/tests.
**S0 foundation:** [dedicated schema-10 recovery-fence design](g2-s0-recovery-fence-design.md), Option B selected as policy; exact DDL, offline migration, downgrade safety, operator release and web compatibility still need separate implementation approval. The `protected_images` upsert, summary-only CLI journal and shared bootstrap-fence designs are withdrawn.

## Problem and required contract

An image update, pinned update or rollback can finish successfully in Docker while a subsequent SQLite history or terminal-operation write fails. Existing paths can then produce a contradictory FAILED record, reverse a healthy pinned update, abandon a web operation, or produce no durable record at all. The G2 policy must cover all of these without redefining the actual workload outcome.

The proposal must specify, per mutation path:

1. **Two distinct facts:** observed Docker/Compose workload outcome versus persistence/publication outcome. Do not claim a successful Docker mutation failed solely because SQLite publication failed.
2. **No database-only compensation:** never restore a pin or recreate the previous container solely in response to history or audit persistence failure. Recovery after a genuine workload failure remains separately guarded.
3. **Idempotent publication:** bounded attempts, stable deduplication/reconciliation for errors before commit and ambiguous errors *after* commit, and no duplicate/contradictory history or terminal state.
4. **Recovery safety:** rollback eligibility, active image protection and source/backup evidence stay safe when history or terminal status is missing/ambiguous. Do not silently expire the sole usable recovery point.
5. **Persistent unavailability:** distinguish observed success from unknown persistence; do not claim durable success if writes cannot be verified. Define explicit CLI exit/error output, agent logs and web operation visibility, including what a later operator must reconcile.
6. **Transaction ownership:** preserve single-transaction atomic publication where required; do not hold SQLite transactions across Docker or Compose effects. Maintain core/web separation, existing locks and explicit schema migration/compatibility gates.

## 1. Mutation-path behaviour and historical defect baseline

The mutation-publication faults remain G2 work. The dangling-image cleanup fault described in the historical baseline was separately fixed by merged PR #19; current cleanup validates full identities and rollback ownership.

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
- (b) **Historical defect resolved by PR #19:** cleanup used to compare abbreviated IDs and omit important protection. Current cleanup validates canonical IDs and existing rollback references. G2 still needs a distinct durable fence armed before a mutation because a successful workload without matching History can otherwise lack independent recovery ownership.
- (c) `State.record` writes the history row, `protected_images` and `rollback_refs` in one transaction (`state.py:442-458`); today protection exists only if the completion row commits.
- (d) Retention treats a `protected_images` row with no matching rollback ref (including a NULL `history_id`) as **unresolved** and refuses removal, even under `--override-protection` (`src/docker_update_manager/retention.py:19-31`, `:137-144`, merged in R10 #14). Retention deletes only resolved protection rows (`retention.py:312`, `:325`).
- (e) `recover_abandoned_operations` (`state.py:777-866`) marks every stale active web update/rollback `failed` with "Agent stopped while this update was active" (`state.py:810-811`) without consulting History or any durable boundary marker. Only namespace update and Compose apply have durable markers.
- (f) Compose backups (`backups/<stamp>`, `compose.py:125`) currently expire by age only (`retention.py:49-61`, default 7 days), even if History references them. S0 must explicitly exempt every backup claimed by a pending/unresolved completion guard, including forced cleanup, instead of treating this as acceptable for unverified completions.
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
- **Recovery evidence**: the previous image and all distinct owners of its protection (legacy `protected_images` / `rollback_refs` plus the independent operation guard in P11), the exact Compose recovery backup, web pre-rollback backup, and durable operation identity.

## 3. Outcome and publication matrix

Operator labels and required behaviour. "Record not verified" means P is `not_committed`, `ambiguous` or `contradictory` after the deadline.

| W | P = committed | Record not verified |
| --- | --- | --- |
| `not_started` | "Blocked — no changes made" (BLOCKED row) | "Blocked — no changes made; record not verified". Nothing changed. An ambiguous guard write may leave a durable operation guard, which must remain protected until reconciled |
| `failed` | "Failed", plus "automatic recovery succeeded" or "manual recovery required" as today | "Failed — record not verified; manual reconciliation required". The original workload error stays primary |
| `succeeded` | "Succeeded" | "Succeeded in Docker — not durably recorded; manual reconciliation required". Never FAILED, never "no changes made", no compensation; the previous image and recovery backup remain protected by the P11 operation-scoped guard |
| `uncertain` | The path's existing failure label plus "outcome uncertain" | Same, plus "record not verified; manual reconciliation required" |

`contradictory` is additionally reported as "History contradiction" with both identities. For `uncertain`, each path keeps its existing `result`/`rollback_result` and adds `details.workload_outcome="uncertain"`; G2 does not change recovery for genuine workload uncertainty. History `result`/`rollback_result` vocabularies are unchanged. New facts go in additive `details` keys (`completion_id`, `workload_outcome`) and in the operation result (`workload`, `publication`, `outcome_verified`).

## 4. Policy rules

### P1 — Factual outcome

The completion write runs after the workload completion point and outside the workload failure handler (a separate try, or a handler that distinguishes completion-publication exceptions). A publication failure never enters the failure/recovery path, never writes FAILED/BLOCKED for a succeeded workload, and never triggers source restoration or recreation (this removes the R2 compensation). Genuine pre-completion-point recovery, including `pre_recovery_check` guards, is unchanged.

### P2 — Shared publisher

One core helper (proposed `src/docker_update_manager/completion.py`; the name is not binding) serves update, pinned update, CLI rollback, web rollback, failure rows and Compose apply. Each write is one `State` transaction. No transaction spans Docker/Compose effects or back-off sleeps. The caller's update lock stays held.

### P3 — Completion key

A 32-hex `completion_id` is fixed before the mutation boundary: web operations use their `operation_id` and CLI operations generate a uuid4 hex. It is stored in History `details.completion_id` and the new schema-10 `completion_fences` owner. CLI does **not** create a web `operation_runs` row. Lookup is a bounded `history_for_service(stack, service)` scan filtered by `action` and parsed `details.completion_id`, the pattern Compose apply already uses (`webservice.py:2625-2628`). There is no `json_extract` dependency. No uniqueness index is proposed here; P5 and update-lock single-writer semantics require explicit verification, not assumption.

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

Factual fields compared: `action`, `result`, `stack`, `service`, `old_image_id`, `new_image_id` (when known), `details.completion_id` and `details.workload_outcome`. The same safety tree governs the P11 typed-fence insertion and the terminal write; factual History and the matching fence resolution commit atomically. `finish_operation` is idempotent by its `WHERE status IN (active)` guard (`state.py:949-985`): rowcount 0 requires a read-back, and a different terminal status is `contradictory`.

### P6 — Unverified publication

When P is not `committed` after the deadline, the publisher stops. There is no FAILED fallback row and no compensating Docker action. Core raises a typed `CompletionPublicationIncomplete` (proposed name, a `RuntimeError` subclass) carrying W, P, the completion key, action, stack/service, old/new image ids and the backup path. For W ≠ `succeeded` the original workload exception stays primary, with the publication outcome attached and never substituted.

### P7 — Operator visibility independent of SQLite

- (a) **Log.** One structured ERROR record on a dedicated logger (proposed `docker_update_manager.completion`) with key, action, service, W, P, old/new image ids, backup path, error class and a SQLite message bounded to 200 characters. It never contains environment content, credentials or registry auth. When nothing is durable, this record is the authoritative evidence.
- (b) **CLI.** A stderr message stating the factual workload outcome and, separately, that publication was not verified, with the completion id, running and previous image ids, backup path, and a pointer to the manual procedure (section 5). Exit status **30** (D1). No raw `sqlite3` traceback. The automatic post-command snapshot and retention (`cli.py:531-532`) stay skipped when publication is unverified; S1 must preserve this explicitly. The durable P11 guard separately blocks normal and forced UPT cleanup regardless of the operator warning.
- (c) **Web.** See P8. A warning alone is never the protection mechanism; protection is P11.

### P8 — Web terminal publication and post-restart recovery (fail-closed)

Three cases are distinct:

1. **Terminal publication succeeds.** If history is `committed`, the terminal status follows W (`succeeded`, `failed`, `blocked`) with warnings as today. If history is not verified:
   - W = `not_started` or `failed`: these workload outcomes were observed, so the terminal status follows W, adding `publication`, `completion_id` and `manual_reconciliation_required: true`;
   - W = `succeeded`: the terminal status is **unresolved** (D9), with result `{workload: "succeeded", publication, completion_id, outcome_verified: false, manual_reconciliation_required: true}`. `succeeded` is used **only** when the history row is durably committed (D2);
   - W = `uncertain`: today's terminal mapping (`failed` with manual recovery required) is kept unless the D9 decision extends `unresolved` to in-process uncertain outcomes.
2. **Terminal publication fails** (deadline exhausted). The adapter never falls through to `finish_operation(failed)` or a failure audit. The operation stays active in the database, the P7 log record is written, and the worker exits normally, releasing the lock.
3. **Post-restart / post-worker reconciliation** (`recover_abandoned_operations`, which requires the update lock). This ships alongside **S1 web correctness**, not S4. For a stale update/rollback operation:
   - **No committed guard** and the operation was created by a P11-aware binary (`summary.completion_protocol >= 1` recorded at operation creation, independently of guard insertion) → the boundary was never authorised → `blocked`, "no changes were made", subject to proving no effect path bypasses P11.
   - **No guard** on a legacy operation → today's behaviour is retained (`failed`, "check the container and History"), because absence proves nothing.
   - **Fence row present (active, manual or resolved)** and exactly one matching committed history row (same completion key, exact service owner and original running-image claim as the fence) → the terminal status the in-process adapter would have published for that row under case 1, with the warning "terminal state recovered after interruption".
   - **Unresolved fence present** and no row, a contradictory row, or reads that fail → **unresolved**. `mutation_performed: null`, `outcome_verified: false`, `manual_reconciliation_required: true`. Never `succeeded` or `failed`.
   - **Never replay.** Recovery issues no Docker or Compose command and does not restore sources. The unresolved fence and every independently owned image protection and backup claim are retained. If History was already published with a resolved fence, retain that correlated evidence until terminal recovery completes.
   - If the database is unavailable at restart, recovery cannot run and the operation stays active; the API reports the database error rather than a status. The contract applies once the database is readable again.

The web rollback `NO CHANGES MADE` fallback (`webservice.py:2147-2165`) may run only when the adapter can prove the boundary was not crossed: a new-protocol operation has no committed guard, and the in-memory boundary flag is false.

**Status vocabulary (D9).** The current vocabulary cannot express "unresolved" without misusing `failed`. The recommended option is a new terminal status `unresolved` (an API/UI contract change, no schema change); see D9 for the alternatives and the required compatibility review. Until D9 is decided, no G2 slice may write an unverified outcome as `succeeded` or `failed`; slices that need it (S1, S3, S4) are blocked on D9.

### P9 — Rollback eligibility versus protection

Protection rules are unchanged except for P11. Eligibility (`operations.py:387-393`) gains one fail-closed guard: refuse when the selected SUCCESS row's `new_image_id` is known and differs from the running `image_id` ("History does not match the running image; reconcile first"). This stops the R1 case (`test_current_behaviour_failed_success_write_makes_rollback_select_an_earlier_point`) and the R1b case (`CliRollbackHistoryFailureCurrentBehaviour`) where an unrecorded outcome leaves a stale point selectable.

### P10 — Transaction ownership and compatibility

No SQLite transaction spans Docker/Compose effects or sleeps. History, normal rollback refs, non-destructive existing protections and a matching completion-fence resolution commit in one `State.record` transaction. G2 introduces **schema 10 via separately approved explicit offline migration**; namespace update/Apply retain their existing separate fence and publication contracts. Core/web separation and locks remain.

### P11 — Schema-10 recovery owner and claims (revised D3/D10)

The chosen planning direction is **Option B**, a dedicated `completion_fences` table plus indexed `completion_fence_claims`, with independent image/backup claims and service identity. See [S0 schema-10 design](g2-s0-recovery-fence-design.md). The original `protected_images` replacement, `operation_runs.summary` CLI journal and shared `compose_bootstrap_fences` approaches are withdrawn. This is not approval to implement.

The G2 fence is keyed by durable `completion_id` and an exact `logical_key`, with additional (stack, Compose service) cross-checks so edited file lists or moved projects cannot silently bypass unresolved identity. **Admission is per service, not per shared image**. Separate claim rows protect the currently running and rollback-target images as appropriate, plus every required recovery backup; image claims block destructive cleanup, not unrelated service updates.

S0 requires an explicit offline schema-9→10 transition, reliable older-binary incompatibility and a safe state-preserving rollback gate. **Namespace-consumer updates continue to use their existing namespace fence unchanged**, avoiding dual arming and duplicate ID/key collisions. An internal web revalidation may exempt **only its verified own G2 fence**, never an arbitrary user-supplied ID or any other bootstrap/namespace fence.

Arm G2 in core after backups, before the earliest effect; failed/ambiguous guard creation blocks the mutation until exact presence is proved. A matching truthful History entry, image rollback refs and **conditional fence resolution** commit atomically in one `State` transaction; a wrong rowcount rolls everything back. Preserve existing `NULL history_id` protection rows and do not replace another protection owner. Resolve a post-arm, pre-effect refusal only on proof that no side effect occurred. Retain an active/manual guard for unverified outcomes, crash recovery or missing postconditions.

All UPT deletion paths (`upt cleanup`, forced retention, `remove --images`, backup TTL) and mutation entrypoints (`restart`, `remove`, `convert`, `restore-compose`, CLI/web direct callers) must respect guards. Audit stable identity, redaction, claim enrichment, malformed records, active guards under CLI batch failures, and pruning of **only resolved G2 records**, preserving existing namespace/bootstrap retention.

A minimal audited operator-only release must exist before any G2 writer is active. It verifies image/source/backup evidence, resolves only one proven guard and may publish corrective History solely from independently established facts; otherwise remains fenced. Unsupported operator attestation needs an explicit decision.

### P12 — Limited overlap with G3

G2-S0 advances the minimum durable CLI completion identity, independent image/backup claims and audited release needed for G2 safety. Full G3 interruption journalling and guided reconciliation remain [issue #10](https://github.com/rdna897/upt/issues/10). Storage-independent **S0a** is merged in PR #16; S0b/S0c require separately scoped implementation authorisation and final author review.

## 5. Per-path application and manual reconciliation

| Path | Typed fence (P11) | Completion point | Key | Success publication | Failure-path publication | Removed behaviour |
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
4. Do not run `upt cleanup`, forced retention or manual image removal for the previous image until reconciled. P11 must block UPT's own removal paths for both the image and its backup.
5. Do not re-run the update or rollback to "repair" the record; P9 refuses an inconsistent rollback.
6. A **minimal audited operator-only resolution path** is required before G2 guard writers are activated. Release the named fence only after independent evidence and correlated History are proved, or atomically publish a verified corrective record. Otherwise leave it fenced. Full guided reconciliation remains in G3; direct database edits are unsupported.

## 6. Synthetic test plan

All tests use `tests/sqlite_faults.py` (modes `before_commit`, `after_commit`, `unavailable`; matchers `history_insert`, `terminal_operation_update`), temporary databases, every Docker/Compose/registry boundary mocked, and a fake monotonic clock and sleep. Extending the harness with read-failure, dedicated fence-insert and claim-write matchers is part of S0a/S0b/S0c (synthetic tests only).

For each of ordinary update, pinned update, CLI rollback, web rollback and the web update adapter:

1. `before_commit` ×1 → retry commits exactly one row; no FAILED row; Docker calls identical to a no-fault run.
2. `after_commit` ×1, read succeeds → `committed`; exactly one row; no second insert.
3. `after_commit` ×1 then the reconciliation read fails until the deadline → `ambiguous`; **no second insert attempted** (assert insert count = 1); exactly one row afterwards (the committed one).
4. `after_commit` ×1, read fails once then succeeds → `committed`; insert count = 1.
5. Pre-existing row with the same key and a different `result` or `new_image_id` → `contradictory`; no insert; reported as a contradiction, not success.
6. `before_commit` until the deadline → `not_committed`; no row; `CompletionPublicationIncomplete`; one ERROR completion log; no compensating Docker call; the pinned source keeps the new pin.
7. `unavailable` → as 6, plus CLI exit 30 with the stderr contract and no traceback.
8. Deadline: fake clock asserts no new SQLite step begins past the budget and each timeout is bounded by remaining time; an already-running commit is allowed its documented non-interruptible tail.
9. Failure-path row under unavailability → the original workload error stays primary.
10. P11: pre-boundary fence/claim insert failure refuses before any Docker action; committed schema-10 claims block every UPT image/backup deletion path, including forced overrides. Existing protections and rollback refs remain intact; the matching History transaction resolves exactly one named fence.
11. P11 ownership: two fences may share an image claim; resolving one never releases the other. An existing `NULL history_id` manual/namespace protection remains byte-for-byte intact, while a distinct rollback ref may be inserted. Admission refuses conflicting **service identities** (not unrelated shared-image services), including logical-key drift. Namespace and bootstrap evidence must not be pruned by G2.
12. Web P8: a `terminal_operation_update("succeeded")` fault is never converted to failed. Recovery with guard plus committed row → terminal from the row; guard and no row → unresolved; **protocol capability recorded on creation** plus no guard → blocked; legacy operation without capability → today's behaviour. Guarded image and backup survive recovery; no Docker call occurs in any recovery case. Also test failure after atomic History/fence resolution but before a web terminal write, followed by recovery.
13. P9: a mismatched `new_image_id` refuses; a matching row still rolls back.

Each slice replaces the matching characterisation tests in `tests/test_sqlite_completion_characterisation.py` with explicit replacement tests in the same PR. Genuine workload-failure recovery tests (including `pre_recovery_check` refusal and operator-edit protection) must remain and pass.

## 7. Implementation slices

Each implementation slice needs a separate PR, passing exact-head validation and final author review; this design PR authorises **documentation only**. See the [schema-10 S0 proposal](g2-s0-recovery-fence-design.md).

- **S0a — completed and merged (PR #16):** before-/during-commit classification, per-call timeout and deterministic fault harness. No schema or workload changes. Integrating those primitives into the shared G2 publisher remains work for later implementation slices.
- **S0b — proposed next separate implementation PR, not yet authorised:** explicit, **offline** schema-9→10 transition; `completion_fences` and `completion_fence_claims` indexes; service/backup/image admission/removal predicates, migration/rollback gates, API/SSE redaction, safety tests. **No G2 writers enabled.** Preserve all existing namespace/bootstrap behaviour.
- **S0c — atomic publication and operator recovery:** guarded `State.record` transaction with exact History/fence resolution, non-destructive `protected_images` handling, post-arm/no-effect proof and minimal audited reconciliation. **Activate writers only with their corresponding S1/S2/S3 corrected completion handlers**, never in a half-enabled release.
- **S1 (R1):** shared publisher, bounded retries, CLI error/log contract, ordinary update and per-service batch retention safety. Web update adapter **and post-restart P8 recovery must ship together** (D9 web compatibility prerequisite).
- **S2 (R2):** pinned update without a database-triggered reversal; follow-on pin gating; namespace-consumer fence exclusion and regression protection.
- **S3 (R1b):** CLI and web rollback, a new CLI pre-rollback source backup, correct image claims, web fallback gating and P9 guard.
- **S4 (R3):** Compose apply completion integration, namespace-update ambiguous-commit characterisation (tests only, D6), cross-path consistency.

Test gates include namespace-consumer update success unchanged; web internal own-fence revalidation; drifted Compose file lists, moved project and same stack/service aliases; shared-image owners; old `NULL` manual protections unchanged; unclear commit plus failed reads; History/fence atomicity; source/target evidence enrichment; CLI-only crash; service-batch partial failure followed by retention; all deletion and service mutation bypasses; HTTP/SSE redaction; guarded backup TTL; malformed evidence; G2-only resolved-row pruning; offline migration, older-binary refusal and downgrade safety.

## 8. Compatibility and rollout

- **Schema 10 is the approved design direction, not an authorised migration.** It requires a separate offline quiescent 9→10 transition with snapshots, integrity checks and explicit operator approval. Schema-9 binaries refuse schema 10, mechanically preventing their image/backup cleanup from operating on new guard state.
- The `core_schema_identity` trust contract and older version gate remain strict; avoid implicit migrations. Validate complete rollback eligibility: never restore a stale schema-9 snapshot over newer History or unresolved recovery claims.
- Additive History `details` and web `summary/result` keys remain backward readable in the new binary, but schema 10 means **binary revert is not an authorised data rollback**. A supported state-preserving 10→9 route, if needed, must be separately designed and reviewed.
- **D9's `unresolved` status is approved as policy**; implementation still requires an API/UI/SSE, frontend and older-web-compatibility gate. No G2 web completion path activates without its matching post-restart recovery.
- **Namespace/Compose compatibility:** dedicated G2 tables never replace `compose_bootstrap_fences`, existing namespace markers or their recovery receipts; service admission must check both systems. No automatic recovery replay.
- Production deployment freeze remains in force. No stage implies deployment or restart.

## 9. Approved decision register

**Policy accepted by the author on 2026-10-16.** The decisions settle the architectural direction, not permission to merge PR #15, deploy, migrate production, or activate a fence writer. Evidence and compatibility gates below must be proved during separate, approved implementation slices.

| ID | Approved policy | Required implementation evidence / gate |
| --- | --- | --- |
| D1 | CLI exit `EXIT_FATAL` (30) for succeeded Docker work with unverified History; report workload success and publication failure separately. | Typed error, bounded/redacted CLI diagnostics, no automatic post-command retention. |
| D2 | Web `succeeded` only when matching History has durably committed; unverified successful work is `unresolved`. | History/terminal read-back and restart recovery tests (D9). |
| D3 | Dedicated service-scoped fences and independently owned image/backup claims; shared-image owners remain distinct and existing manual protections intact. | Stable-identity admission, all deletion guards, strict evidence and atomic release tests. |
| D3b | Schema-9 binaries refuse schema 10; require an explicit offline, quiescent 9→10 transition, never restore stale schema-9 state over newer evidence. | Both UPT locks, validated backup, interruption/idempotence tests, old-binary refusal and a state-preserving downgrade/refusal gate. |
| D3c | Preserve exact claimed backups while a completion remains unresolved, including beyond normal TTL and forced retention; other backups retain expiry. | Strict managed-root path/owner proofs and revalidation immediately before deletion. |
| D4 | Fail closed on rollback when selected History's known `new_image_id` differs from the actual running image. | Out-of-band drift and second-rollback regressions. |
| D5 | One 60-second monotonic completion deadline covering all completion-side SQLite reads/writes, retries and sleeps. | S0a primitives integrated without an additional operation after deadline; ambiguous outcomes reported truthfully. |
| D6 | Preserve existing namespace fences; characterise ambiguous namespace update commits first and scope corrections separately. | Tests-only characterisation in S4 and namespace exclusion tests. |
| D7 | Defer unrelated single-write mutation paths; create follow-on tracking before S1 merges. | Explicit inventory of `do_pin`, removal and remaining writers. |
| D8 | Before any G2 fence writer activates, provide minimal audited **operator-only** named-fence reconciliation. No blind unlock or fabricated success. | Lock-held trusted local command, stable owner/service identity, running image, backup/source hashes, matching History, durable audit; if proof fails retain fence. Operator attestation alone is not an implied override. |
| D9 | New terminal web `unresolved` status for successful but unpublished History and guard-present interrupted operations; keep observed workload outcome separate. | API/polling/SSE/UI and older-client compatibility, plus post-restart fail-closed recovery in the same activation slice. |
| D10 | **Option B:** schema-10 `completion_fences` and indexed `completion_fence_claims`; keep namespace/bootstrap fences and `operation_runs` independent. | DDL/identity, claim lifecycle, privacy, cross-path enforcement and migration tests. |

**Implementation order and controls:** S0a (#16) and cleanup protection (#19) are complete. PR #15 is documentation only. Following author review, S0b may be separately scoped and authorised for offline migration tooling, new storage and *inert* guards, with no new fence writers. S0c prepares atomic publication and audited release; activate a writer only together with its corrected S1/S2/S3 handler and tested operator release. G3 (#10) remains independent.

**Deployment boundary:** No implicit schema 9→10 migration on startup. Production database migration, service restarts, Docker operations, deployment and rollback require their own explicit operator approval.

## 10. Risks

- Lock hold under contention is bounded by the P4 deadline (recommended 60 s) plus at most one non-interruptible in-flight statement.
- Without a unique index, duplicate prevention depends on the P5 invariant and on single-writer-per-key under the update lock and per-operation worker.
- P11 retains image, backup and durable completion evidence until verified or manual/G3 reconciliation: disk cost by design.
- Operation-scoped guards require every deletion and admission path to consult durable state; an incomplete rollout must fail closed, not silently trust old `protected_images` semantics.
- D9 touches the web wire contract and requires an explicit terminal/polling compatibility gate.
- Dedicated schema-10 tables avoid namespace/bootstrap fence collision, but still require scoped malformed-evidence refusal, own-fence web revalidation, stable identity drift checks, auditable release and safe pruning.

## 11. Review history

- **Initial technical review of the first draft** (commit `eb3bd3b`): corrected citations, the scope of the uncertain outcome, and the reconciliation gaps.
- **technical architecture review of `eb3bd3b`:** two High and two Medium findings, accepted after checking against the code:
  - (H1) P8 could not reconstruct an outcome from absent History → P8 rewritten as a fail-closed three-case contract with durable markers and an unresolved status (D9);
  - (H2) no durable protection when nothing commits → P11 pre-mutation marker with pending protection, enforced by existing cleanup/retention, sequenced as G2-S0 (P12);
  - (M3) retry after an ambiguous commit with a failed read could duplicate → P5 invariant and decision tree, `contradictory` outcome, tests 3–5;
  - (M4) the deadline bounded writes only → P4 single monotonic deadline covering every completion-side step.
- **author review of `84d5170`:** identified manual ownership collision, expiry of backup evidence, missing mutation admission and inconsistent protocol capability; the first S0 architecture was proposed.
- **technical review of `8acdac5`:** H1–H4 found summary-only fencing incompatible with existing gate semantics, synthetic CLI web-operation lifecycle, no safe resolution path and non-atomic guard release. M1–M6 identified admission/removal bypasses, shared-image overblocking, web evidence leaks, missing rollback claims, batch retention and late post-restart recovery.
- **technical re-review of `740555e`:** shared `compose_bootstrap_fences` reuse conflicts with namespace updates, while new G2 fences require precise in-flight own-operation revalidation; schema 9 cannot mechanically exclude older cleaners. M1–M5 require protection ownership, stable identity, strict claims, release evidence and G2-only pruning. The [schema-10 design](g2-s0-recovery-fence-design.md) records Option B as the approved policy direction; implementation and deployment remain separately gated.

## 12. Author review and implementation gates

**Policy direction:** D1–D10, including D3b and D3c, accepted by the author on 2026-10-16. This draft now records decisions rather than presenting them as outstanding policy choices. The design still requires final author review before PR #15 may merge.

**Separate implementation authorisation:** Do not start S0b solely because the policy was accepted. First approve the exact offline migration scope, DDL, old-binary refusal, state-preserving downgrade/refusal proof, inert guard coverage and operator/recovery evidence. Subsequent S0c and S1–S4 need separately reviewed PRs, exact-head CI and explicit author approval. D9's web wire compatibility is an implementation gate, not permission to publish an incomplete status.

**No production actions:** This PR changes documentation only. No source, schema, tests, CI policy, live Docker or production state, no deployment and no service restart. Preserve the deployment freeze.
