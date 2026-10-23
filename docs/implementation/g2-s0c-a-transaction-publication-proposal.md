# G2-S0c-A — Transaction ownership and atomic publication proposal

**Status:** design for author review; no implementation authority is implied. This PR changes documentation only. No G2 writer is active, and none is activated here.

**Verified baseline:** public `main` at `2d4e49a23b7184843e2600dc761e25dd071b7f7d`, the merge of [PR #20](https://github.com/rdna897/upt/pull/20) on 2026-10-22. PR #16 supplied opt-in SQLite outcome primitives; PR #20 supplied schema 10, offline transition tooling and inert enforcement. The older policy/design/S0b records contain pre-merge status and historical line numbers; use this baseline map for current implementation facts. Their historical decisions are not rewritten here.

**Authority:** [G2 policy P1–P12 and D1–D10](g2-mutation-completion-policy.md), [S0 fence design](g2-s0-recovery-fence-design.md), [S0b implementation record](g2-s0b-schema10-implementation.md), [Stage 6a transaction contract](stage6-sqlite-state-ownership-review.md), and [development policy](../development-policy.md). Work remains tracked by [issue #9](https://github.com/rdna897/upt/issues/9). G3 [#10](https://github.com/rdna897/upt/issues/10) remains a separate programme.

**Scope and freeze:** propose transaction composition, non-destructive image protection, a future publication contract, tests and sequencing. Schema 10, its exact DDL/indexes/triggers and core identity remain unchanged. No changes to `src/`, tests, namespace/bootstrap behaviour, migration, running databases, Docker, Compose or production services. Design approval, CI, a merge and any future release are separate from operator approval to deploy; the production deployment freeze remains in force.

## 1. Recommendation and invariants

Keep `State` as transaction owner. Add an explicit optional `transaction` argument to `State.record()` and extract its SQL body into one private helper. Existing calls retain `State.connect()` and its raw exceptions; the future publisher supplies the restricted handle from `State.write_transaction()`. The helper must never open, commit, roll back or close a transaction. Do not introduce a repository layer, pooling, ambient connection or nested transaction/savepoint.

Replace protection replacement with an insert targeted only at an absent image key, and insert a separate rollback reference for the new History ID. Preserve every existing protection row, including its reason, timestamp and `NULL history_id`. These are the only proposed generally active behavioural changes in S0c-A. Classified publication and lifecycle support stay opt-in and disconnected from mutation handlers until their later activation gates pass.

The future atomic unit is:

1. Exactly one truthful History row for a stable completion identity.
2. Its normal rollback reference, when the existing eligibility predicate requires one, and a non-destructive legacy protection insert.
3. Validation of the exact expected G2 owner, evidence and claims.
4. Conditional resolution of exactly that owner's `active` fence, when resolution proof permits it.

All four commit or none of the attempted changes commit. Successful Docker work stays successful when publication fails; persistence does not authorise pin restoration, source restoration, container recreation or a contradictory FAILED row. An unresolved owner continues to protect its claims independently of History and `protected_images`.

## 2. Current transaction ownership and call map

Source links below refer to the reviewed baseline. Each `connect()` is a new `BEGIN IMMEDIATE` transaction. External effects occur between these completion calls; no arrow here authorises an encompassing transaction.

| Entry/call chain | Current write owner and contents | Current publication fault exposure |
| --- | --- | --- |
| CLI `main → execute → do_update` | [`operations.py`](../../src/docker_update_manager/operations.py), `do_update`: `record(SUCCESS)` after health verification; [`State.record`](../../src/docker_update_manager/state.py) owns History/protection/ref transaction | Success write remains inside workload try; exception handler writes FAILED and re-raises. Persistent failure can leave no row; after-commit error can leave SUCCESS plus FAILED |
| `do_update → _do_pinned_update` | Same standalone `record()` ownership after pull, source pin write, recreate and verification | Completion exception can restore the pin/recreate the previous digest. Namespace post-marker handling is a distinct exception |
| CLI `do_rollback` | Separate `connect()` rollback-ref read, source restore/tag/recreate/verification, then standalone `record(ROLLED BACK)` | Completion failure escapes after rollback; no durable completion may exist. CLI lacks the web's current-running-image versus latest-update check |
| Web `_update_worker → do_update → record`, then `audit`, then `finish_operation` | Core agent uses `State`; three separate completion transactions. `finish_operation` atomically changes terminal status and events, not History | History/terminal failure enters generic failure handling; a success-terminal error can lead to a failed terminal attempt |
| Web `_rollback_worker → do_web_rollback → record`, then `audit`, then `finish_operation` | Core rollback History separate from adapter terminal publication | Raw SQLite error escapes core's handler tuple; adapter may insert FAILED / NO CHANGES MADE after actual rollback, or leave History and terminal state disagreeing |
| Namespace image update `NamespaceImageUpdate.before_exec → mark_namespace_update`, later `record(namespace_operation_id=...)` | Pre-Compose transaction writes legacy bootstrap fence, operation marker and `INSERT OR IGNORE` NULL-history image protection. Success `record()` transaction validates running/marked operation and commits History/ref/protection, operation result, legacy fence resolution and both completion events | Dedicated protocol already exists. No G2 dual arming. Namespace-update ambiguous completion remains a characterisation item, not a correction in this design |
| Ordinary Compose Apply/discard `_finish_compose_reconcile → write_history → record`, then audit/terminal | Three-attempt History loop deduplicates by parsed `details.operation_id`; `compose_reconcile` creates no image rollback ref. Trusted baseline/recovery bundle has its own earlier publication | Factual workload result survives History failure, but persistent database failure can prevent warning/terminal publication. Fallback can repeat finalisation |
| Namespace Apply `publish_namespace_apply`, bootstrap `publish_bootstrap_success` | Dedicated `State.connect()` SQL, without calling `record()`: trust/baseline, History, audit, operation/event, verification and legacy fence state commit together | Namespace Apply has `namespace_apply_published()` read-back after ambiguous publication; retain this independent contract |

Additional verified details:

- [`State.connect()`](../../src/docker_update_manager/state.py) owns BEGIN/commit/rollback/close, catches `BaseException`, returns a raw connection, and does not classify commit failure. Default timeout remains 30 seconds.
- `State.write_transaction(timeout=...)` is already merged and unused by these live completion paths. It yields [`OwnedTransaction`](../../src/docker_update_manager/sqlite_outcome.py), prohibits transaction-control SQL and cursor/connection escape, and wraps ordinary exceptions as `WriteOutcomeError(outcome, phase, cause)`. `NOT_COMMITTED` requires an unattempted commit and the original still-open transaction; commit acknowledgement failures, automatic transaction loss and ownership bypass are conservative `AMBIGUOUS`. `BaseException` propagates unclassified. Normal context exit establishes commit; a body return value does not.
- `record()` currently uses `INSERT OR REPLACE` for both `protected_images` and `rollback_refs`. It creates a ref when `old_image_id` is truthy, result is not BLOCKED and action is neither `compose_reconcile` nor `compose_bootstrap`. This includes genuine failure and rollback records; do not redefine eligibility incidentally.
- `history_for_service()` performs unbounded service queries and can inspect backup metadata to attribute legacy NULL-stack rows after closing its initial read. It is not a SQL-only transaction helper. P3's description of a bounded scan is a future requirement, not today's behaviour.
- [`completion_fence.py`](../../src/docker_update_manager/completion_fence.py) validates exact schema objects, identities, claims and exact v1 evidence fields. `unresolved_fences()` accepts active/manual owners only; it is not a resolved-owner reconciliation API. Triggers allow claim addition to active/manual owners, prohibit unresolved claim deletion/updates and identity edits, and make resolved final. Production code currently writes no G2 rows, enforced by `StorageConstraintTests.test_no_production_code_writes_g2_tables`.
- [`retention.py`](../../src/docker_update_manager/retention.py) protects all active rollback refs, unresolved legacy protection and unresolved G2 claims. Manual NULL-history protection is unresolved even if another ref to that image expired; forced overrides do not release it. Metadata deletion of a protection row uses its own matching ref plus absence of any active ref to that image. G2 metadata is not pruned today. Claimed managed backups survive TTL and forced cleanup.
- Current web rollback verifies the exact `rollback_refs(history_id,image_id)` and locally available image identity; it does not require the single legacy row to be reassigned to the new History owner. CLI SQLite/OSError handling added by earlier work is cleanup-specific; other commands can still expose raw SQLite errors. Current terminal statuses remain succeeded/failed/blocked; `unresolved` is approved policy, not implemented UI/API behaviour.

## 3. S0c-A transaction composition

### 3.1 Proposed small internal interface

Illustrative signatures, not code to install:

```python
State.record(*, transaction=None, namespace_operation_id=None, **history_fields) -> int
State._record_in_transaction(c, *, namespace_operation_id=None, **history_fields) -> int
```

- With `transaction=None`, serialize the same accepted values and enter `self.connect()` exactly once, invoking the helper inside it. Preserve return type, legacy exception types, 30-second default, field handling, ref predicate and namespace SQL/event order. Protection preservation is the explicit reviewed exception to legacy behaviour.
- With `transaction=tx`, accept only a live `OwnedTransaction` issued by this same `State` instance. Invoke the helper on that handle and return a **provisional** History ID. Do not call `connect()`, `read()`, `_ensure_schema()` or another method that opens a connection. The outer `write_transaction()` exit is the sole commit point.
- PR #16's handle has no State provenance today. Add the smallest private issuer token/check to `OwnedTransaction` and `State.write_transaction()` so a handle from a different `State`/database cannot be accepted. An open handle and `isinstance` alone do not establish database ownership. Preserve current handle restrictions and reject expired, raw, foreign and thread-transferred handles before SQL; bind the loan to its issuing thread as part of this check.
- The private helper may receive the raw connection only from the legacy wrapper, or a checked restricted handle from the opt-in branch. It uses the common execute/result subset. It cannot be used to lend arbitrary raw connections through the public argument.
- Initially reject `transaction` together with `namespace_operation_id` before any SQL. Existing namespace calls take the unchanged legacy wrapper/helper branch. No namespace caller needs composition for G2, and this avoids exposing a second namespace completion owner. A future change to that restriction requires separate namespace review.
- Let any body validation/SQL exception escape the transaction context. Callers must not catch and suppress it inside the body: that could commit earlier History/ref inserts. Publication failure is interpreted only **after** context exit/rollback. Keep this internal API restricted to reviewed callers; it is not a general public unit-of-work API.

### 3.2 Precise entry/exit boundaries

| Interval | Allowed work | SQLite ownership |
| --- | --- | --- |
| Preparation under `update.lock` | Stable completion ID, external preflight, backup creation/hash checks, Docker/Compose mutation and observed workload result, immutable expected publication snapshot | No publication transaction. Any existing short state reads/writes must finish before an external call |
| Before a completion attempt | Serialize/validate in-memory payload and expected owner/proof; check shared deadline | No transaction; no new observation may silently change a frozen workload result |
| `with state.write_transaction(timeout=deadline.step_timeout()) as tx` entry | Connection setup/schema compatibility first, then `BEGIN IMMEDIATE`, then issue handle | `State.write_transaction()` exclusively owns transaction control; no payload/file inspection here |
| Body | SQL-only owner/claim/evidence reads, completion-key scan, factual comparison, `record(transaction=tx)`, reference/protection verification, conditional fence update and optional resolution receipt in fence evidence | One write transaction and one connection. No helper may acquire another connection |
| Normal exit | Revoke handle, commit once, close | Only now may a newly inserted ID/result be reported committed. An idempotent match still needs successful outer exit, or read-back classification |
| Exceptional exit | Revoke handle, rollback conservatively, classify ordinary exceptions, close | No result inferred from body progress or `lastrowid`; no retry while this context remains open |
| Reconciliation | Fresh `State.read(timeout=...)`, SQL-only reads of History, exact owner, claims and receipt in one snapshot, then close | Separate read transaction. No Docker, network, filesystem observation or sleep until it closes |
| Back-off/reporting/web terminal | Sleep within remaining deadline; expose factual W and separate P; terminal publication/read-back in its own short transaction | No SQLite transaction spans the sleep or any external operation. Terminal write shares the completion deadline |

The ban covers filesystem reads as well as writes: backup inspection, digesting, path resolution, logging and reporter callbacks must occur outside the body/read snapshot. SQLite's own database I/O and connection setup are intrinsic; the rule forbids application filesystem operations while holding the transaction. Do not call `history_for_service()` inside either snapshot. Legacy retention bundle filesystem work already inside a transaction is pre-existing Stage 6 debt, not a pattern to copy or a refactor authorised here.

### 3.3 Non-destructive History and image protection

For a newly inserted History ID `h` and qualifying old image `i`:

```sql
INSERT INTO rollback_refs(history_id,image_id) VALUES(?,?);
INSERT INTO protected_images(image_id,reason,history_id) VALUES(?,'rollback',?)
  ON CONFLICT(image_id) DO NOTHING;
```

Use a targeted conflict clause instead of broad `OR IGNORE`: only the existing image-key collision is acceptable. The existing `rollback_refs` PK is by History ID, so a plain insert for a new `h` should succeed; a conflict is an integrity error, not permission to replace another ref. An idempotent publication returns the already verified History/ref without re-inserting or refreshing creation time, expiration or purge state.

Read the resulting protection and matching ref in the same transaction. Classify the protection as inserted or preserved; it is acceptable for the preserved row's `history_id` to be NULL or another ID. Never UPDATE it to this History ID. Any ref for `h` must identify exactly `i`; do not quietly repair a mismatched row. Existing malformed or unmatched owners remain fail-closed under current retention rules; publication cannot assert their ownership was resolved. Only transaction-local metadata reports inserted/preserved; avoid adding a general public output contract to `record()`.

| Existing owner of image `i` | Publication effect | Subsequent protection/retention |
| --- | --- | --- |
| No legacy row | Insert row owned by new `h`; insert ref for `h` | Existing ref/retention semantics |
| NULL-history manual or namespace row | Preserve all four columns byte-for-byte; insert ref for `h` | Manual protection remains unresolved, even after this ref expires or is forced expired |
| Different History owner | Preserve old row/ref; insert ref for `h` | Every active ref protects image. A legacy row may be removed only under existing own-ref/all-inactive conditions |
| Several unresolved G2 owners | No G2 claim is reassigned or deleted | Resolving this publication's owner removes only its unresolved authority; another active/manual owner still blocks image/backup deletion |
| Configuration-only or BLOCKED History | Existing no-ref predicate remains | No synthetic image rollback eligibility; independent owners retain protection |

**Schema limitation:** `protected_images.image_id` is the sole PK. It cannot represent multiple independent legacy owners/reasons/timestamps, and it is not an authoritative complete ownership ledger. `rollback_refs` can represent several History owners of one image but only one image per History ID. G2 claims support multiple images/backups and multiple owners independently. S0c-A adds only the appropriate existing one-image ref, never uses the legacy row as a G2 owner, and performs no schema change or implicit ownership migration. It cannot repair previously overwritten ownership. An existing NULL row may keep an image indefinitely; that is the intended safety cost, not grounds to drop it. This also makes namespace-created NULL protection survive success where current replacement consumes it: author approval and explicit regression coverage are required for that retention effect.

## 4. Future atomic completion contract (S0c-B infrastructure; later activation)

### 4.1 Request and result

Proposed internal values, constructed by trusted core code and not from browser-supplied exemption IDs:

```text
CompletionPublication:
  completion_id                 # 32 lowercase hex; CLI UUID or web operation ID
  expected_owner                # operation_id == completion_id, logical_key,
                                # stack, compose_service, fence action, created_at
  expected_evidence             # validated version + evidence revision/content digest
  expected_claims               # exact validated owner-scoped (kind,value) set
  history                       # frozen factual History fields and details
  disposition                   # resolve_active OR retain_unresolved
  resolution_proof              # required for resolve_active; none inferred from result alone

PublicationResult:
  outcome                       # committed | not_committed | ambiguous
  verification                  # matched | absent | contradictory | unreadable
  history_id                    # only a verified committed matching row
  fence_disposition             # resolved | retained | unknown
  reason                        # fixed diagnostic code, no raw evidence
  cause                         # private original cause/phase, never public exception text

publish_completion(state, request, *, deadline) -> PublicationResult
lookup_completion_in_transaction(c, request, *, deadline) -> verified observation
```

Use one caller-supplied `Deadline(60)` from the workload completion/failure point, shared with web terminal publication; do not grant each retry/adapter a new 60 seconds. Pre-mutation arming is a separately bounded admission phase and must be durably proven before effects. CLI does not create a web operation row. Web History retains `details.operation_id` for existing consumers and adds `details.completion_id`; CLI uses `details.completion_id`. `details.workload_outcome` stores not_started/failed/succeeded/uncertain separately from publication.

Fence action and History action are not identical: `pinned_update` fence maps to History `update`, `web_rollback` to History `rollback`. Validate that mapping explicitly. Exact owner comparison includes the immutable columns, reproducible service identity, lifecycle and expected evidence/claims, not merely an operation ID or a matching image. No bypass for namespace/bootstrap owners; a request combining those protocols is invalid.

The tri-state outcome reports whether the **requested atomic bundle** is established. Preserve P5's fourth, integrity-specific `contradictory` classification in `verification`; never reduce it to a retryable operational error. A contradictory durable bundle returns `outcome=ambiguous, verification=contradictory` (requested publication cannot be certified), stops all writes and requires operator review. This mapping is a proposed internal representation requiring author approval; it must retain the policy's explicit contradictory reporting. It does not claim a contradictory row's existence is unknown.

### 4.2 SQL-only attempt

After `BEGIN IMMEDIATE` and before any insert:

1. Load/strictly validate the exact owner including resolved owners; load all its claims in the same transaction. Reject missing/wrong owner, wrong action/service identity, malformed evidence, changed evidence/claims or unsupported lifecycle. For a resolved replay, validate the receipt binding the original request digest and pre-resolution evidence digest; do not compare the enriched receipt bytes directly to the old active evidence bytes and reject a valid commit. Front-door and claim readers still fail closed independently.
2. Scan History by stable completion key and compare the full factual snapshot. Require exactly one matching row or established absence. Compare action, result, stack/service, old/new immutable image IDs (including expected unknown values), completion/workload identities, backup/recovery binding and relevant rollback provenance. Preserve image/digest facts; never downgrade a mismatch to “already recorded.” Exclude mutable retention `rollback_result`/ref-expiry/purge fields and display timestamps from immutable identity, while validating their legitimate lifecycle separately. A retained receipt can bind the original canonical factual digest.
3. A single exact row plus the **requested** consistent fence/ref/protection/receipt state is an idempotent match; return its ID only after context exit or verified read-back. A History row alone is insufficient. Duplicates, differing rows, resolved fence without matching History, or matching History with a still-active fence when resolution was requested are contradictory; do not add corrective rows automatically.
4. If no row exists, require the exact active owner for `resolve_active`. Insert History with `record(transaction=tx)`, verify its ref/protection, store any resolution receipt, and run the conditional transition below. For `retain_unresolved`, require the expected active/manual owner and leave it unresolved. The truthful failure row/ref can commit without releasing unsafe recovery claims; `committed` then means History publication with the explicitly retained disposition, not permission to mutate or clean up.
5. Let every ownership, evidence, ref or affected-row error escape the context and discard the entire attempted publication. Never consume a provisional ID outside it.

Illustrative resolution predicate (fixed parameterized SQL):

```sql
UPDATE completion_fences SET lifecycle='resolved', updated_at=?
WHERE operation_id=? AND logical_key=? AND stack=? AND compose_service=?
  AND action=? AND created_at=? AND lifecycle='active' AND evidence=?;
```

Require `rowcount == 1`, and verify the exact resolved owner/receipt before context exit. Matching the original evidence bytes is a compare-and-set after validation; any enriched receipt may be assigned in the same UPDATE with the old bytes in WHERE. Claims remain stored; existing readers derive authoritative protection from owning fence lifecycle. Resolution must not delete claims. Zero rows is an error, never a no-op success. Multiple rows are impossible with the valid PK and this predicate; still enforce `!= 1` defensively and test a synthetic incorrect cursor count. Do not corrupt production-compatible DDL to manufacture duplicates.

`resolve_active` needs independently established successful postconditions, proved no effects after arming, or verified safe recovery after genuine failure. FAILED History alone never proves safe release; uncertain/manual-required outcomes retain claims. Ordinary automated completion cannot resolve a manual owner. Operator reconciliation of a manual fence is a separately audited S0c-C transition, never an expanded `WHERE lifecycle IN (...)` in the ordinary publisher.

### 4.3 Key lookup, serialization and bounded work

There is no History completion-key unique index in schema 10, and none is added. Require the existing cross-process `update.lock` throughout publication/reconciliation and one trusted writer per key. Also perform read-before-insert **inside** `BEGIN IMMEDIATE`, so two cooperating publishers serialize their check/insert even if started together. No global deduplication guarantee extends to arbitrary SQL writers or legacy writers that disregard this protocol.

Implement a SQL-only key lookup, without `json_extract` or legacy backup attribution. Scan stored `details` with bounded-memory keyset pages (proposed 256 rows) and parse the completion ID in Python. An exact stack/service query can be a fast first check, but a complete key scan must detect the same key under another identity before declaring absence or uniqueness. If a page/read/parse cannot establish the answer, the lookup is incomplete, never “absent.” Do not use substring matching as identity proof. A truncated recent-history window cannot prove absence. Malformed rows that cannot be ruled out as a claimant prevent certification and require diagnosis; do not skip them silently.

Publication/reconciliation must open only the existing compatible core database, never create or initialise replacement state after a missing/unavailable database. Use the issuing State's existing-only mode, or add an explicit opt-in existing-only transaction/read option in B; keep standalone `record()` defaults unchanged. A new empty database is not proof that no completion committed. Validate database/schema identity before trusting absence; a replaced/unverifiable database cannot authorise a retry or release.

Check the deadline before every new SQLite statement/page, including COMMIT initiation; recompute busy timeout from remaining budget before blocking statements. PR #16 currently applies the timeout at connection open only and commits on context exit without a deadline callback. S0c-B must add an opt-in remaining-budget hook at statement/commit boundaries (preserving legacy defaults), or equivalent owner-controlled checks. `Deadline.step_timeout()` once per connection is insufficient for a multi-statement transaction. If budget expires in the body, raise out of it and roll back; do not start COMMIT after expiry. Mandatory rollback/close cleanup still runs. A statement/commit already in flight is not interrupted and may finish beyond the deadline; report its outcome without starting another read. Python parsing is also checked between bounded pages. A full scan may exhaust the budget as History grows; refuse certification/reinsertion instead of weakening uniqueness. This schema-10 performance limitation and page size require author review.

### 4.4 Commit classification and retries

Normal `write_transaction()` exit proves commit. Retain PR #16's conservative classification and original cause; do not infer absence from `rollback()` after a commit error. An acknowledgement lost after a durable commit is ambiguous until read-back. An automatically lost transaction is also ambiguous. A close error after established commit does not undo it.

Before a first insert, a successful complete lookup must establish absence. After a retryable `sqlite3.OperationalError`, use P5:

- Proven pre-commit rollback: requested changes did not commit. A new attempt may begin within budget but repeats owner validation and read-before-insert.
- Ambiguous write: only reconciliation reads may follow until a successful complete snapshot establishes matching commit or absence. Failed reads never unlock another insert. Exactly one matching History plus matching resolved/retained owner bundle is committed; no row plus the expected unchanged unresolved owner establishes non-commit and may permit a fresh attempt. Missing owner, partial publication or conflicts require diagnosis.
- On a permitted retry, re-check inside the next write transaction. A successful earlier absence read is not a substitute for the serialized check.
- Retry writes only for the original `OperationalError`; not `IntegrityError`, ownership/rowcount errors, `ValueError`, `TypeError`, `OSError` or programming errors. A successful read can classify such an error, but cannot make it retryable.
- Back-off 0.2, 0.4, 0.8 seconds, then at most 1 second, bounded by remaining budget and always outside transactions. Reads may retry within the same budget. Deadline plus positive back-off bounds attempts; do not add an independent three-times-30-seconds loop.
- Preserve an ambiguity latch across failed reads. If no write could have committed and complete initial lookup established absence, exhaustion is not_committed. If an earlier attempt may have committed, or initial lookup could never prove whether a prior invocation exists, exhaustion is ambiguous. A fresh process never assumes absence from its own empty in-memory attempt history.
- A later invocation/operator may reconcile the **same** ID and frozen payload. Never mint a replacement key to bypass uncertainty or re-run Docker to repair History. Before pruning any resolved evidence/History, preserve all unfinished web/reconciliation dependencies and the deduplication window; S0c introduces no automatic G2 pruning.

Current retention can prune old History independently of G2 fences. Before any writer activates, add a narrowly scoped retention exclusion for History/ref/receipt dependencies needed by unresolved owners, pending web terminals and the agreed deduplication horizon. Keeping fence rows alone is insufficient. Test replay after legitimate ref expiry/purge without refreshing it, and fail closed if required evidence was unexpectedly lost. This dependency guard belongs with B's dormant-protocol support or its activation slice; it must be present before S1/S2/S3 activation.

Interruptions/process death are not publication acknowledgements. Preserve claims and reconcile durable state after acquiring `update.lock`; do not catch `BaseException` and manufacture a successful result.

### 4.5 Evidence enrichment without a schema change

S0b v1 evidence is exactly version/working_dir/compose_files. Adding target images, source hashes or receipt fields under v1 fails validation. S0c-B should introduce an explicitly versioned, bounded v2 JSON contract and readers that accept validated v1 **and** v2, without editing `COMPLETION_SCHEMA`, version 10, indexes, triggers or core identity. This is application evidence compatibility, not an implicit database migration.

Before enabling v2 writers, update every admission, deletion, backup, downgrade-diagnostic and operator reader that consumes evidence. Older schema-10 binaries reject unresolved v2 and may globally block operations; document this as a binary compatibility gate, with no claim that equal schema numbers imply evidence compatibility. No automatic rewriting of existing v1 rows. V1 lacks enough evidence to release many real outcomes; keep them unresolved unless independent proof satisfies S0c-C.

Proposed v2 content: stable v1 identity, monotonic evidence revision, bounded before/after immutable target observations, managed backup references and source/backup digests, and an optional resolution receipt binding completion ID, History ID, canonical factual digest and resolution proof class. Define exact field sets, byte limits and redaction in the S0c-B review before coding. Do not store source contents, environment values or credentials.

Collect filesystem/runtime proof outside SQLite under `update.lock`; perform evidence compare-and-set and claim additions in a short transaction before any effect that requires the new identity. Claims are immutable/additive while unresolved; never replace or drop earlier claims during enrichment. On ambiguity prove the exact new evidence and complete claim set before proceeding. Failure keeps earlier claims and blocks further effects needing unproved enrichment. Proof may become stale despite the lock because external operators are not serialized by UPT; re-observe at the applicable external boundary, close all reads, and refuse on changed identity. No recovery decision is based on SQLite evidence alone when runtime/source postconditions remain unknown.

## 5. Failure-state and recovery decisions

W is observed workload outcome; P is requested publication outcome. “Retain” means all remaining active/manual owners and their image/backup claims remain authoritative, including under forced retention. Logging/output must work independently of SQLite, with bounded operator-safe diagnostics and no raw evidence on HTTP/SSE.

| Trigger/evidence | P / verification | Write/retry decision | Workload/reporting and recovery |
| --- | --- | --- | --- |
| Normal complete context exit | committed / matched | Return verified ID; no repeat insert | Report W; fence resolved only if proof permitted requested resolution |
| Statement fails while original transaction remains open; commit unattempted | not_committed / absent when absence was proved | Roll back History/ref/protection/resolution together; only OperationalError may retry | W unchanged; retain fence/claims |
| Commit acknowledgement errors after real commit; full read matches | committed / matched | Return existing ID; no duplicate/ref refresh | W unchanged; resolved owner stays resolved |
| Commit errors; successful read proves key absent and exact owner unchanged | not_committed / absent | Bounded retry only if cause permits; repeat serialized check | Retain until one complete transaction commits |
| Commit ambiguity plus failed/incomplete reconciliation reads | ambiguous / unreadable | Reads only until budget; no further insert | W unchanged; record not verified; retain every unresolved claim; operator reconciliation |
| Database unavailable before first lookup | ambiguous / unreadable (prior publication cannot be excluded) | No insert; bounded reads | No fabricated failure/commit; pre-boundary arming unverified means no mutation; after mutation preserve W |
| Known non-commit followed by unavailable database | not_committed if earlier absence and all attempts provably rolled back; otherwise ambiguous | No new step after deadline | Preserve workload error if W failed; publication cause secondary |
| Existing exact History and complete requested bundle | committed / matched | Idempotent return; no SQL changes to refs/protection/receipt | No repeat mutation, events or release |
| Duplicate key, different factual row, or partial History/fence/ref bundle | ambiguous / contradictory | Stop writes, including “repair” inserts; fixed integrity diagnostic | Never report durable publication success; operator investigates preserved evidence |
| Wrong owner/key/service/action/evidence or unresolved lifecycle mismatch | Attempt rolled back; requested publication uncertified until valid read | Non-retryable; no alternate owner lookup or broad UPDATE | Retain owners; workload observation unchanged |
| Resolution count 0 or greater than 1 | Entire attempt rolled back; phase/cause retained | Non-retryable integrity error; read only to diagnose | No History-only success; preserve claims |
| Genuine mutation failure with verified safe recovery/no-effect proof | committed if accurate FAILED/BLOCKED bundle commits | May resolve exact active owner with proof; not from label alone | Original workload failure/refusal remains primary |
| Genuine failure/uncertain outcome without release proof | committed with retained disposition, or unverified if persistence fails | Truthful failure publication may retain owner; never automatic resolution | Manual recovery required; no unsupported success or NO CHANGES MADE |
| W succeeded, History publication not verified | not_committed/ambiguous, possibly contradictory | No failure History or compensating Docker action | CLI says Docker succeeded, publication unverified, exit 30; skip post-command snapshot/retention and follow-on pin. Web policy is unresolved after compatibility gate |
| History/fence committed; separate web terminal write fails | Core committed; terminal separately unverified | Read-back/retry terminal only with same deadline; never insert History again | No fallback failed audit/status. If terminal cannot persist, leave durable operation active and log; S1 restart recovery reconstructs from exact evidence |

CLI batch behaviour must propagate unverified completion so the automatic post-command cleanup cannot silently run after a per-service warning. A genuinely failed workload is still failed even if its failure History cannot be written. Web `succeeded` requires matching committed History; D9's `unresolved` needs API/SSE/polling/UI/older-client tests and same-slice restart recovery. None of these handler/presentation changes belongs in S0c-A.

## 6. Implementation acceptance tests (specifications only)

All new tests use newly created synthetic schema-10 SQLite databases under temporary directories, invented service/image identities, mocked Docker/Compose/registry/filesystem boundaries, fake monotonic clock/sleep, and the fail-closed [`scripts/run_tests.py`](../../scripts/run_tests.py) harness. No tests are added or changed by this design PR. Every concurrency test has bounded event waits, joins and cleanup. Verify database contents after leaving the fault context; inspect all four publication components rather than only exceptions or row counts.

### 6.1 Exact new cases

Proposed new files and method names are implementation commitments, not claims they exist today.

| Slice / proposed test | Fixture/fault | Required assertions |
| --- | --- | --- |
| A: `tests/test_state_record_transactions.py::test_legacy_record_preserves_return_and_raw_errors` | Normal call and `history_insert` before_commit | One legacy transaction; same integer ID/raw exception; no classified wrapper for old callers |
| A: `test_borrowed_record_has_one_outer_commit` | Two records plus other SQL in one owned transaction | No extra connection/BEGIN; provisional IDs invisible to another State until exit; exactly one commit |
| A: `test_outer_failure_discards_history_refs_and_new_protection` | Raise after `record(transaction=tx)` | All attempted rows absent; pre-existing protection unchanged |
| A: `test_record_rejects_foreign_raw_expired_and_cross_thread_handles` | Handles from other instance/database, raw connect, expired loan, bounded second thread | Rejected before History SQL; original transaction and ownership restrictions preserved |
| A: `test_namespace_cannot_use_borrowed_record` | Both namespace and transaction parameters | Early refusal, no publication SQL |
| A: `test_manual_null_protection_survives_new_history_byte_for_byte` | Existing synthetic NULL-history row | Same image/reason/NULL/created; new History owns its distinct ref |
| A: `test_other_history_owner_survives_shared_image_publication` | Old ref and protection, two new histories for same image | Old row/ref unchanged; three distinct refs; expire one and image remains protected |
| A: `test_ref_and_image_conflicts_are_not_replaced` | Inject mismatched ref/integrity error | Full rollback; only image PK conflict tolerated; no swallowed unrelated constraint error |
| A: `test_record_keeps_blocked_compose_and_failure_ref_rules` | Parameterize BLOCKED, compose_bootstrap, compose_reconcile, FAILED, ROLLED BACK | Existing ref predicate and serialization unchanged |
| B: `tests/test_completion_publication.py::test_success_commits_complete_bundle` | Exact active owner/evidence/claims | One matching History/ref, legacy row inserted or preserved, exact resolved owner/receipt; claim rows retained |
| B: `test_each_body_failure_rolls_back_every_component` | Faults at History insert, ref insert, protection insert/read, receipt/resolution UPDATE and final verification | No partial publication; owner/claims/evidence unchanged; classification/cause correct |
| B: `test_after_commit_error_reconciles_without_duplicate` | `sqlite_fault(..., mode='after_commit')` | Real durable complete bundle; read-back committed; one History/ref, unchanged creation times, no new mutation |
| B: `test_ambiguous_commit_and_failed_reads_never_reinsert` | after_commit plus repeated `select_from('history')`/fence read_failure | Only reads after ambiguity, deadline exhaustion ambiguous, exactly one durable row after faults removed |
| B: `test_absence_proof_permits_one_retry` | Retryable pre-commit error; separately ambiguous non-durable commit with successful absence snapshot | Repeat in-transaction check; one committed row; no absent-to-insert shortcut after failed read |
| B: `test_duplicate_attempt_returns_same_bundle` | Repeat request and two bounded concurrent State publishers | One History/ref/receipt, same ID; no timestamp/expiration reset; update-lock plus SQLite serialization honoured |
| B: `test_conflicting_or_duplicate_key_stops_writes` | Same key different result/image/stack/action; two rows; malformed/truncated key scan | Explicit contradictory/incomplete status; no extra History, no success/failure alternation |
| B: `test_wrong_owner_or_lifecycle_rolls_back` | Parameterize wrong ID/key/stack/service/action/created_at/evidence/claims; missing/manual/resolved owner without matching receipt | Non-retryable; every attempted insert rolled back; no other owner touched. Exact resolved replay separately succeeds |
| B: `test_resolution_rowcount_must_equal_one` | Real zero-row conditional update; synthetic result wrapper reports 2 after executing real single-row UPDATE | Entire transaction, including actual fence update, rolled back. Valid schema retained; >1 is a defensive fault case |
| B: `test_partial_bundle_is_never_certified_or_repaired` | History with active fence for resolve request, resolved owner without History, mismatched/missing ref | Contradictory; no repair insert or release |
| B: `test_shared_claims_keep_other_owner_authoritative` | Two different services' active/manual fences claim same image/backup | Resolve one; other still blocks normal/forced/dangling/remove deletion; legacy row unchanged |
| B: `test_retained_failure_publishes_without_releasing_claims` | Truthful failure/uncertain W, no recovery proof | One accurate row/ref where eligible; owner remains unresolved; no fabricated success/no-effect proof |
| B: `test_unavailable_and_nonretryable_failures_keep_classification` | Initial read unavailable, known rollback then unavailable, automatic transaction loss, IntegrityError/ValueError/TypeError | Tri-state plus verification accurate, ambiguity latch retained, no forbidden write retry |
| B: `test_deadline_covers_pages_statements_commit_and_terminal` | Fake time expires between SQL statements, before commit, during read-back/back-off/terminal | Per-step capped timeouts; no new statement/COMMIT after budget, except cleanup; one in-flight operation may finish; no new deadline per stage |
| B: `test_key_lookup_proves_complete_absence_and_uniqueness` | Key outside recent pages, elsewhere in service identity, malformed details; large synthetic History | No substring proof, no false absence/unique match on truncation; memory paged; budget fail closed |
| B: `test_missing_or_replaced_database_never_proves_absence` | Delete/replace a temporary fixture database between attempts; unavailable read | No new database/schema initialisation, no retry insert or release based on empty replacement state |
| B: `test_retention_preserves_publication_dependencies_and_replay_does_not_renew_refs` | Synthetic aged History, unresolved owner/resolved owner with pending terminal, legitimately expired refs | Needed History/receipt remains; verified replay does not renew protection/eligibility; missing required evidence refuses certification |
| B: `test_evidence_enrichment_is_versioned_additive_and_conditional` | v1/v2; wrong version/size/revision, ambiguity, failed enrichment read | Reader compatibility, exact compare-and-set, all original claims retained; no subsequent effect requiring unproved target |
| C: `tests/test_completion_reconciliation.py::test_operator_release_requires_named_owner_lock_proof_and_audit` | Missing lock/proof, drift, wrong owner, unavailable audit, manual owner | No blind release; all failed proofs/audits preserve lifecycle/claims; no web release interface |
| C: `test_operator_publication_audit_and_release_are_atomic_and_idempotent` | Proven named-owner reconciliation plus before/after-commit audit/release faults | Corrective History only from facts with provenance; audit/receipt/release one transaction; same key reconciliation without duplicates |

Extend [`tests/sqlite_faults.py`](../../tests/sqlite_faults.py) with exact matchers for rollback-ref/protection writes, conditional owner/evidence UPDATE, claim insertion and resolution/audit read-back. Existing modes are before_commit, after_commit, unavailable and read_failure. The first mode fails at the matched statement, not at COMMIT; add a separate commit-before-durability fault for the ambiguous-then-absent branch. Add a narrow result wrapper for synthetic rowcount 2, never loosen schema validation. Preserve `connection_timeouts`, real durable commits for after_commit, and original exception/cause assertions. PR #16's composition fixture is an example, not the production publisher or a complete bundle check.

### 6.2 Exact existing suites to retain or adapt

| Existing evidence | Implementation treatment |
| --- | --- |
| `test_sqlite_completion_primitives.py`: `CommitClassificationTests`, `TransactionOwnershipTests`, `LegacyBehaviourTests`, `ReconciliationCompositionTests` | Retain raw legacy semantics and classification tests; extend issuer/thread/deadline checks. Preserve `test_ambiguous_commit_then_failed_reads_never_duplicates`, `test_ambiguous_commit_resolved_by_a_later_successful_read`, `test_established_non_commit_permits_exactly_one_retry`, `test_expired_deadline_starts_no_sqlite_step`; add complete-bundle tests above |
| `test_g2_completion_fences.py`: `StorageConstraintTests.test_independent_owners_share_an_image_and_resolution_is_owner_scoped`, `ClaimOwnerEvidenceTests.test_valid_shared_owners_and_resolved_claims_keep_their_behaviour`, `DeletionTests.test_metadata_pruning_retains_g2_rows_and_null_history_protection` | Extend with publication rather than test-only resolution SQL, shared legacy ownership and versioned evidence; keep migration/exact-schema, old-binary refusal, source fencing and deletion coverage intact |
| `StorageConstraintTests.test_no_production_code_writes_g2_tables` | Keep unchanged through A. B introduces reviewed dormant storage methods, so replace only this blanket lexical assertion with an explicit writer/caller allowlist and activation-boundary tests that fail if any live CLI/web/startup/retention path invokes them. Do not delete the inertness requirement or weaken runtime guards to get green |
| `test_compose_namespace_update.py`: `PostMarkerTests.test_web_owned_success_is_published_atomically_with_history`, `test_web_owned_success_persists_all_eight_stages_with_the_final_one_before_terminal`; `PinnedUpdateTests.test_pinned_post_marker_failure_retains_new_pin_without_recovery` | Preserve transaction/event ownership and no dual G2 owner; add `test_success_preserves_namespace_null_protection_and_adds_history_ref`. Add **characterisation only** `test_current_behaviour_ambiguous_history_commit_keeps_namespace_protocol` in S4; do not assert the generic G2 fix already covers namespace |
| `test_compose_namespace_apply.py`: `SuccessTests.test_successful_apply_publishes_atomically_with_one_strict_invocation`, `test_success_publication_ambiguity_reads_durable_commit_and_never_recreates`, `test_success_publication_failure_is_manual_and_discards_only_unpublished_material` | Retain unchanged; assert no generic publisher/G2 creation on this path, with existing trust/fence/receipt and recovery isolation |
| `test_compose_apply.py`: `test_history_write_is_retried_before_finalization`, `test_persistent_history_failure_keeps_factual_success_but_never_claims_the_record_stage`, `test_late_terminal_persistence_failure_keeps_success_and_one_history_row`, `test_terminal_commit_failure_rolls_back_the_final_stage_so_a_retry_emits_it_once`, `test_current_behaviour_unavailable_database_cannot_surface_the_history_warning` | Keep through A–C. S4 adapts only after approved integration: same operation key, no image refs, explicit persistence outcome, same deadline, at-most-once final stage and truthful unresolved presentation/restart recovery; preserve recovery bundles and no repeated Compose invocation |
| `test_cleanup_protection.py`: `test_null_history_manual_protection_blocks_removal`, `test_manual_protection_survives_an_expired_ref_for_the_same_image`, `test_shared_image_stays_protected_while_any_owner_requires_it`; `test_disk_retention.py::RetentionTests.test_shared_image_retained_when_one_reference_active` | Extend after a real proposed `record()` publication; check TTL/forced overrides, all owners and no protected metadata loss |
| `test_sqlite_completion_characterisation.py`: `OrdinaryUpdateHistoryFailureCurrentBehaviour`, `PinnedUpdateHistoryFailureCurrentBehaviour`, `CliRollbackHistoryFailureCurrentBehaviour` | Keep throughout foundation work. S1 replaces the four ordinary defect expectations with truthful W/P and no contradictory History; S2 replaces database-triggered pin reversal expectations with no compensation; S3 replaces post-rollback raw-error expectation. Preserve real workload-failure and concurrent-edit recovery protections |
| `test_web_rollback.py`: `test_current_behaviour_completed_rollback_with_failed_history_write_is_recorded_as_no_changes_made`, `test_current_behaviour_failed_success_terminal_write_leaves_history_and_operation_disagreeing`, `test_current_behaviour_persistent_unavailability_after_rollback_leaves_no_terminal_state` | S3 replaces these defect expectations with truthful rollback/terminal outcomes, bounded reconciliation and restart reconstruction; retain eight-stage, recovery-on-genuine-failure and no third recreate assertions |
| `test_web_operations.py::WebOperationAgentTests`, `test_operation_state.py::OperationStateTests`, `test_web_browser.py` | S1 adds `test_successful_update_history_failure_is_unresolved_without_failed_fallback`, `test_terminal_failure_never_reclassifies_workload`, `test_restart_uses_completion_bundle_and_protocol_capability`; S3 equivalents for rollback. Cover auth/CSRF/privacy, API/SSE/polling/UI terminal vocabulary and old clients |
| `test_core.py`, `test_pin_history_image.py`, `test_post_mutation_reconciliation.py` | S1/S2/S3 add CLI exit-30/no-traceback, skipped post-command snapshot/retention and follow-on pin, mixed batch propagation, actual workload failure remaining primary, and no extra Docker/source action on persistence faults |

At every implementation PR head run the affected tests through isolation plus the required full Python 3.10/3.13 and Chromium CI with `merge-gate`. Passing foundation tests cannot attest corrected live handler behaviour before S1–S4. This documentation PR runs lightweight diff/link checks and exact-head full CI; it does not execute these proposed tests.

## 7. Reviewable implementation sequence and activation gates

| PR | Implementable after separate approval | Must remain inactive / dependencies |
| --- | --- | --- |
| **S0c-A: transaction ownership and non-destructive publication** | Small `record()` SQL helper/optional owned loan, issuer/thread validation, preserved standalone/namespace wrapper, plain new ref insert and targeted legacy protection insert, tests in §6 for A | No G2 DML, creation, resolution, enrichment, publisher adoption, CLI/web outcome change or namespace protocol change. Depends on merged #16/#20. Author must accept persistent manual/namespace protection effect |
| **S0c-B: lifecycle, evidence and reconciliation primitives** | Strict exact-owner readers including resolved receipts, v1/v2 compatibility, short arm/enrich/active→manual/conditional resolve primitives, SQL-only dedup/read-back, existing-only database checks, shared deadline/outcome publisher, nonretryable integrity handling, dependency-retention guards and activation-boundary tests | Depends on A. All G2 writers and publisher remain unreachable from live mutation/startup paths. No production evidence upgrade. No activation without C and corresponding S1/S2/S3 handler; no automatic G2 pruning |
| **S0c-C: audited operator reconciliation and safe release** | Trusted local operator-only named-owner command; lock-held external observations outside transactions, proof validation, exact compare-and-set, provenance and audit atomic with any corrective History and release; read-back and refusal tests | Depends on B. No automatic or web release, blind unlock, mutation replay or unsupported attestation. Command must not fabricate History or release on missing proof/audit. Existence of command alone does not enable writers or approve a rollout |
| **S1: ordinary update and web completion/restart** | Correct W/P exception boundaries, actual activation/own-fence admission and durable pre-boundary identity/claims, CLI/batch/log contract, web terminal and protocol-aware restart recovery together | Requires A/B/C, D9 wire/client support, audited operator acceptance and exact-path end-to-end faults. No activation in a half-enabled build |
| **S2: pinned updates** | Remove persistence-only pin reversal, gate follow-on pin, correct own-source checks and enrichment | Requires A/B/C and matching S2 proof/recovery tests; namespace consumer remains on existing protocol. Can follow S1; do not partially enable pinned calls through S1 |
| **S3: CLI/web rollback** | Pre-rollback backup, running-image eligibility guard, accurate rollback result and no web NO CHANGES MADE fallback after effects | Requires A/B/C, corresponding web compatibility/restart recovery and evidence proving both running/target images and backups protected before mutation |
| **S4: Compose/cross-path closure** | Integrate ordinary Compose completion without G2 dual arming; namespace-update ambiguity characterisation; cross-path dedup/retention/terminal closure | Separate approval. Schema-10 G2 actions exclude compose_reconcile; do not expand DDL or retrofit namespace/bootstrap fences here |

Three foundation PRs are sufficient by default. If B is too large to review coherently, split **B1 (versioned readers, exact-owner/lifecycle/evidence primitives)** from **B2 (publisher, deadline enforcement and read-back)**. B2 depends on B1; both remain dormant and C follows B2. Do not split a writer activation away from its corrected completion/restart handlers or operator recovery. No additional broad refactor is warranted.

For C, preflight/digest/runtime observation and audit payload preparation happen before the write transaction. Revalidate the stored owner/evidence snapshot in the transaction; changed proof refuses. Successful release requires a durable core audit event, an unambiguous resolution receipt and appropriate History/ref publication in the **same** commit. Failed/ambiguous audit publication never grants release; reconcile that whole bundle before retry. Releasing manual owners needs its own exact `manual→resolved` predicate and proof classification; ordinary `resolve_active` stays unchanged. Failure to establish facts leaves the owner unresolved with a report of missing proof. No direct SQLite editing procedure is offered as recovery.

## 8. Compatibility, rollout risks and author decisions

Risks requiring review are explicit: preserved NULL protections can retain images indefinitely; one legacy row cannot encode all owners; JSON key lookup has no unique index and can exhaust the deadline; malformed History can block certification; same-schema evidence versions can still be binary-incompatible; provisional IDs can escape if helpers are misused; legacy live handlers remain defective until their own slices. A retained resolution receipt cannot replace independently observed workload facts. Long-term resolved History/evidence retention and duplicate prevention require one reviewed pruning contract; until then preserve them. No schema 11, implicit migration, namespace/bootstrap rewrite or production action is part of the response to these risks.

The author is asked to approve these concrete design decisions before implementation begins:

| Decision | Proposed approval | Consequence / unresolved detail |
| --- | --- | --- |
| A1 | Optional same-State owned transaction on `record()`, private SQL helper, reject namespace+loan, preserve legacy errors/defaults | Small private provenance/thread/deadline extensions to PR #16 need implementation review; no raw caller connection support |
| A2 | Preserve every existing protection; plain new ref insert plus `ON CONFLICT(image_id) DO NOTHING` | Accept longer/manual namespace retention rather than silently consuming independent protection; no ownership repair/migration |
| A3 | Verify the entire bundle, exact owner and `rowcount == 1`; distinguish requested retained failure from resolution | Approve explicit proof classes for no-effect/safe recovery and manual release during B/C; until proved keep claims |
| A4 | Tri-state result plus explicit contradictory verification, frozen factual digest and SQL-only complete paged lookup | Approve mapping to P5 and conservative malformed/incomplete lookup handling; proposed page size 256 subject to synthetic performance evidence |
| A5 | Versioned v2 evidence/receipt in existing JSON column; all readers first; no schema change or v1 rewrite | Exact v2 format, revision/proof/digest rules and same-schema downgrade restrictions need B review before any writer |
| A6 | A → B → C foundations, optional B1/B2 split, activation only with corrected path and audited operator recovery | D9/restart gate must ship with web activation; no broad feature toggle that accidentally enables unfinished paths |
| A7 | Operator release requires independently verifiable evidence and atomic audit; no attestation-only override | Whether any exceptional attestation can ever suffice remains unresolved and requires separate explicit author decision. Default is refusal |
| A8 | Preserve resolved evidence/History while dedup/restart dependencies remain; no pruning in S0c | Finite metadata retention duration and durable dedup horizon remain a later reviewed decision; do not silently age away the only proof |

Approval of this proposal does not merge the PR, begin implementation, migrate state or lift the deployment freeze. Leave the design PR open for final author review in this conversation.
