# Stage 6 assessment (brought forward): SQLite state and transaction ownership

**Status:** Draft — architecture assessment for owner review. **No implementation is authorised by this document.**
**Canonical repository:** `rdna897/upt` (public).
**Baseline:** `main` at `f50eb5e3a68a14c504d68d5a297d780057660f5f` (Phase 3 merged). Re-verify cited lines before any implementation.
**Sequencing:** this is the Stage 6 *assessment* performed before detailed Stage 4/5 designs, as required by the [working index](architectural-refactor-index.md). It is not Stage 6 implementation.
**Deployment:** the production deployment freeze remains mandatory.

## Objective

Establish who owns SQLite state, where transactions begin and end, how SQLite publication interleaves with Docker and filesystem side effects, and which concurrency contracts Stages 4 and 5 must preserve. Then decide whether any extraction or stronger internal boundary is justified now. No extraction is a valid outcome.

## Evidence conventions

- **P (proven):** demonstrated by an existing test or by a synthetic probe run under `scripts/run_tests.py` isolation for this review (probes were scratch files outside the repository and are not committed).
- **C (code-read):** established by reading the cited code path; no executing test isolates it.
- **I (inferred):** a consequence of C-level facts that has not been executed.

Validation for this review: 620 tests in the state-boundary suites passed under isolation with synthetic temporary state only (`test_operation_state`, `test_schema_compatibility_boundary`, `test_state_rollback_compatibility`, `test_post_mutation_reconciliation`, `test_compose_apply`, `test_compose_namespace_apply`, `test_compose_bootstrap`, `test_compose_recovery_retention`, `test_disk_retention`, `test_web_closure_scan`, `test_web_session_persistence`, `test_web_rollback`, `test_web_operations`, `test_service_verification`, `test_runtime_health`, `test_core`). No production database was opened.

## 1. Databases, processes and cross-process locks

| Store | File | Opened by | Writers | Notes |
| --- | --- | --- | --- | --- |
| Core state | `<state_dir>/history.sqlite3` | `State` in the privileged agent (`webcli.py:131`) and the CLI (`cli.py:519`); offline `state_transition.py` | Agent threads (scan worker, targeted verification, runtime monitor, update/rollback/Compose workers, post-mutation reconciliation); CLI commands | Schema 9 with immutable `core_schema_identity` (`state.py:322-392`) |
| Web state | `<web_state_dir>/history.sqlite3` | `WebState` in the unprivileged web process (`webapp.py:263`, `webcli.py:25`) | Request handlers (sessions, users, credentials, web audit) | Separate schema (`webstate.py`, version 4), path validation before every open; never holds Docker/history tables |

The web process never opens the core database; it reaches core state only through bounded agent RPCs. This privilege separation is a hard invariant for any Stage 6 change. **(C)**

| Lock | Scope | Holders | Contract |
| --- | --- | --- | --- |
| `update.lock` (`lock.py`, non-blocking `flock`) | Cross-process; all mutations | CLI modifying commands (`cli.py:527`, retention `cli.py:385`), agent update/rollback/Compose workers (`webservice.py:1373, 1546, 1879, 2018, 2255, 2286`), offline transition | Serialises every Docker/Compose/source mutation and `recover_abandoned_operations` (`state.py:778` docstring: caller must hold it). **(C)** |
| `scan-worker.lock` (blocking `flock`) | Cross-process; scan worker lifetime | `State.scan_worker_guard` (`state.py:290`); probed non-blockingly by `_scan_worker_is_live` | Lease for stale-scan recovery (`claim_scan`, `recover_stale_scans`). **(C)** |
| `web.lock` | Web admin CLI | `webcli.py:150,153` | Serialises offline user-administration commands. **(C)** |
| In-process `threading.Lock`s | Agent | `_lock`, `_baseline_lock`, `_health_lock` | Protect in-memory intents, thread maps and caches; none spans a SQLite transaction across threads. **(C)** |

## 2. Transaction primitives (the single authority)

All core and web SQL runs through three `State` primitives (`state.py:181-288`):

- `_new_connection()` opens a fresh connection per transaction (`timeout=30`, `busy_timeout=30000`, `foreign_keys=ON`, `0600` file and sidecar permissions). There is no connection pooling and no connection shared between threads. **(C)**
- `connect()` opens **`BEGIN IMMEDIATE`**, then commits on normal exit or rolls back on any `BaseException`, and always closes. This reserves the single SQLite writer slot for the whole block. **(C)**
- `read()` opens a deferred `BEGIN` read transaction and always rolls back. Under WAL (`_ensure_schema` sets `journal_mode=WAL`), readers never block the writer. **(C)**
- `_ensure_schema()` runs migrations once per `State` instance under a process-local lock and one `BEGIN IMMEDIATE` transaction. `ensure_compatible()` re-checks the version and identity on every mutation front door. **(P, `test_schema_compatibility_boundary`)**
- `compact_if_needed()` runs `VACUUM` on a separate autocommit connection after a read-only free-page check (`state.py:585-605`). **(C)**

Contract properties verified for this review:

- **No nested transactions.** No `State` method opens a write transaction while another write transaction of the same thread is open. Methods that compose several public operations (`finish_scan`, `create_operation`, `recover_abandoned_operations`) call them **sequentially**, as separate transactions. Doing otherwise would block for 30 s and then fail with `database is locked`. **(C, AST inventory of every `State` method)**
- **Check-then-recheck.** Pre-transaction read checks are re-validated inside the write transaction where it matters; for example, `publish_bootstrap_success` re-queries the competing fences inside its `BEGIN IMMEDIATE` (`state.py:1147-1170`). **(C)**
- **Retries.** SQLite retries only via `busy_timeout`. The only application-level retry of a history write is the Compose apply path (`webservice.py:2643-2654`, three attempts (`COMPOSE_HISTORY_ATTEMPTS = 3`), then keeps the factual workload outcome and adds a warning). **(P, `test_compose_apply.test_history_write_is_retried_before_finalization`, `test_persistent_history_failure_keeps_factual_success_...`)**

## 3. Ownership matrix

"Owner" is the code that issues the SQL. "Leak" marks SQL issued outside `state.py`/`webstate.py`.

| Table group | State owner methods | Other direct SQL (leaks) | Serialisation | Key invariants | Tests |
| --- | --- | --- | --- | --- | --- |
| `history`, `protected_images`, `rollback_refs` | `record` (history, protection and rollback ref in one transaction), `history*`, `protected` | `operations.py:390` (rollback point read via `connect()`); `webservice.py:971, 1232` (rollback ref reads via `connect()`); `webservice.py:2144` (history read); `retention.py:80-274` (expiry, purge status, history `rollback_result`, deletion); `removal.py:23, 40, 209` (rollback ref reads, expiry) | `update.lock` | A rollback point exists only for `SUCCESS` updates; never silently remove the only usable rollback point; purge is idempotent (`ALREADY ABSENT` reconciliation) | `test_state_rollback_compatibility`, `test_web_rollback`, `test_disk_retention`, `test_compose_recovery_retention` |
| `operation_runs`, `operation_events` | `create_operation`, `set_operation_running`, `operation_event`, `finish_operation`, `recover_abandoned_operations`, bootstrap/namespace publish and finish methods, `operation_status` | none | `update.lock` for creation and recovery | One active mutation; abandoned operations are recovered only under `update.lock`; the terminal event is written in the same transaction as the terminal status | `test_operation_state`, `test_web_operations`, `test_compose_bootstrap`, `test_compose_namespace_apply` |
| `compose_baselines`, `compose_bootstrap_fences`, `compose_recovery_receipts` | `insert/delete_compose_baseline`, `publish_bootstrap_success`, fence and namespace-apply methods | reads only: `compose_baseline.py:249`, `compose_bootstrap.py:210` | `update.lock`, plus `_baseline_lock` in the agent | Trust publication, fence resolution, history and audit commit together | `test_compose_bootstrap`, `test_compose_apply`, `test_same_project_baseline_reconciliation` |
| `scan_runs`, `scan_events`, `service_snapshots`, `latest_scan` | `claim_scan`, `start_scan`, `scan_event`, `touch_scan`, `stage_scan_result`, `mark_scan_terminal`, `recover_stale_scans`, `web_prune` | none | `scan-worker.lock` lease; one active scan | Partial or failed scans never replace the last complete inventory | `test_web_closure_scan`, `test_post_mutation_reconciliation` |
| `service_verifications` | `save_verification`, `invalidate_verification`, `reconcile_runtime`, `publish_*` (invalidation inside publication) | none | none across processes; ordering by identity and invalidation | A late scan cannot revive an invalidated update; invalidation commits with the runtime publication | `test_service_verification`, `test_post_mutation_reconciliation`, `test_targeted_verification_worker` |
| `runtime_snapshot` | `save_runtime_snapshot`, `record_runtime_failure`, `reconcile_runtime`, `runtime_snapshot` | none | `attempted_at` ordering guard (E4/E5, [#6](https://github.com/rdna897/upt/issues/6)) | The previous success is retained on failure; older attempts are rejected | `test_runtime_health`, `test_post_mutation_reconciliation` |
| `audit_events` (core), `disk_snapshots` | `audit`, `save_disk_snapshot`, `web_prune` | none | none needed | Bounded, redacted details | `test_disk_retention`, `test_web_closure_scan` |
| `users`, `web_sessions`, `web_credentials`, `audit_events` (web) | `WebState` inherits the `State` user/session/credential/audit methods | none | `BEGIN IMMEDIATE`; `web.lock` for admin CLI | Separate DB; path validation per connection | `test_web_session_persistence`, `test_web_closure_auth` |
| `schema_version`, `core_schema_identity` | `_ensure_schema`, `_migrate`, `ensure_compatible`; offline `state_transition.py` | `state_transition.py` (offline, read-only plus staged copy, under `update.lock` and `scan-worker.lock`) | migration transaction | Never downgrade; the identity row is immutable (triggers) | `test_schema_compatibility_boundary` |

## 4. Read/write and side-effect call graph (mutation paths)

```text
CLI modifying command (cli.py:519-532)
  ensure_compatible -> [update.lock] -> quick_snapshot (disk_snapshots)
  -> execute(): do_update / do_rollback / do_pin / remove_service / retention
  -> quick_snapshot -> retention_cleanup(automatic) -> [release update.lock]

do_update (operations.py:237) - ordinary path (operations.py:272-375)
  ensure_compatible, assert_service_unfenced           (read txns)
  backup_files (filesystem)                            no DB intent row for CLI
  docker pull / tag / compose up                       Docker effects
  health wait (discover)
  state.record(SUCCESS)                                ONE write txn: history + protected_images + rollback_refs
  except -> state.record(FAILED|BLOCKED) -> raise

_do_pinned_update (operations.py:87-233)
  backup -> pull -> atomic_write pin -> validate -> compose up -> health
  state.record(SUCCESS)                                ONE write txn
  except -> restore pin -> best-effort compose up of old digest -> state.record(FAILED ...) -> raise

Agent web mutation (webservice.py:1546-, 1373-, 2255-, 2426-)
  [update.lock] ensure_compatible -> recover_abandoned_operations -> create_operation (durable intent)
  -> worker thread: operation_event* -> do_update/do_rollback/compose apply -> record / publish_* -> finish_operation
  -> post-mutation: reconciliation.py -> state.runtime_snapshot (read) -> reconcile_runtime (write txn: invalidate + snapshot)

Scan worker (scan_worker.py) [scan-worker.lock]
  claim_scan (write txn incl. lease probe) -> scan_event*/touch_scan -> per-service save_verification
  -> stage_scan_result (write txn: snapshots + latest_scan, status=finalizing)
  -> housekeeping: audit, web_prune, compact_if_needed (VACUUM) -> mark_scan_terminal (write txn)

Retention (retention.py:205-282) [update.lock]
  expire refs (write txn) -> docker image rm -> purge_status/rollback_result (write txn) -> delete resolved refs -> compact
```

## 5. Risk register

Severity combines impact and likelihood. "Existing" means present on the baseline and **not** to be fixed silently by Stage 4/5/6 work.

| ID | Severity | Evidence | Finding | Proposed treatment |
| --- | --- | --- | --- | --- |
| S6-R1 | **High** (high impact, low likelihood) | **P** (synthetic probe, ordinary update path) | **A successful update can be recorded as FAILED.** In the ordinary `do_update` path, if `state.record(SUCCESS)` raises after a healthy recreate (for example, `database is locked` after the 30 s busy timeout, or an I/O error), the `except` branch records `FAILED` and re-raises. The container keeps running the new image, but no `SUCCESS` row, and therefore no usable rollback point for that update, exists. `do_rollback` then refuses ("no successful update rollback point exists"). The CLI path stores the raw exception text in history details. | Existing defect; track separately; characterisation test first. Align with the Compose-apply policy (retry, then keep the factual outcome with a durable warning). **Prerequisite for Stage 5.** |
| S6-R2 | Medium | **C** (pinned path, operations.py:156-199); **I** for runtime effect | **Same window on the pinned path triggers compensating recovery.** A failure of `state.record(SUCCESS)` after a healthy recreate enters the recovery branch: it restores the old pin and, because `recreate_started` is true, recreates the old digest. A healthy update is therefore reversed because of a database write failure, and the reversal is recorded only as `FAILED`. | Characterisation test, then decide the policy together with R1. Stage 5 must define one "durable completion point" rule for all mutation kinds. |
| S6-R3 | Medium | **C** | **Inconsistent completion policy across mutation kinds.** Compose apply retries the history write and never revokes a committed workload outcome; image update (R1/R2) does neither; namespace update and bootstrap publish completion atomically with operation state. | Stage 5 decision gate: one written policy (retry bounds, warning surface, no compensating Docker action for DB-only failures). |
| S6-R4 | Medium | **C** | **No durable intent for CLI mutations.** Web mutations create an `operation_runs` row before any Docker effect and are recoverable by `recover_abandoned_operations`. CLI updates, rollbacks and removals write history only after the effect, so a process kill between recreate and `record` leaves no history and no rollback reference for that change. | Document as an accepted limitation, or add a CLI operation record in Stage 5. Owner decision. |
| S6-R5 | Medium | **C** | **Rollback-point SQL is spread across five modules.** `rollback_refs` and `history` are read or written directly by `operations.py`, `webservice.py` (×3), `retention.py` and `removal.py`. The protection invariant ("never silently remove the only usable rollback point") is enforced by convention across modules rather than by one owner. | Smallest justified boundary: move these statements behind named `State` methods, with identical SQL and transactions, when Stage 5 touches the code ("encapsulate on touch"). |
| S6-R6 | Low | **C** | **Reads through write transactions.** `operations.py:390` and `webservice.py:971, 1232` read `rollback_refs` with `connect()` (`BEGIN IMMEDIATE`). They reserve the writer slot and can wait up to 30 s behind another writer. No correctness impact; all three run under `update.lock`. | Use `read()` when the statements move behind `State` (R5). |
| S6-R7 | Low | **C/I** | **Scan finalisation spans transactions.** `stage_scan_result` publishes `latest_scan` (status `finalizing`) before housekeeping and `mark_scan_terminal`. If the worker dies in between, stale-scan recovery marks the run `failed` while `latest_scan` already shows its (complete) results. The data is trustworthy; only the run status disagrees. | Document as intended two-phase publication; add a characterisation test if Stage 6 implementation proceeds. |
| S6-R8 | Low | **C** | **`VACUUM` from scan housekeeping is not under `update.lock`.** It runs concurrently with agent or CLI writers and relies on `busy_timeout`; a large database could stall writers for the vacuum duration. | Accept (the database is small and bounded); record the expected duration bound in the policy. |
| S6-R9 | Low | **C** (Phase 3 evidence) | Post-mutation reconciliation reads `runtime_snapshot` in one transaction and publishes in another; merged diagnostic counters can be one tick old. Ordering is protected by the `attempted_at` guard. | Accept; display-only data. |
| E4–E5 | Low / Info | **P** (Phase 3) | Wall-clock ordering of runtime snapshots ([#6](https://github.com/rdna897/upt/issues/6)). The same wall-clock dependency exists in scan heartbeat staleness (`claim_scan`, `recover_stale_scans`: 600 s) and abandoned-operation age (`julianday('now')`). | Keep in #6; extend its scope note to heartbeat and age checks. No change here. |

Not defects (verified): there are no nested write transactions; schema migration is atomic, and mutation front doors refuse incompatible schemas before side effects; the web process cannot open core state; abandoned-operation recovery always runs under `update.lock`; retention purge is idempotent across interruption (`ALREADY ABSENT`); and in-process locks never span a SQLite transaction across threads.

## 6. Alternatives

| Option | Description | Benefit | Cost and risk | Verdict |
| --- | --- | --- | --- | --- |
| **A — Retain the architecture; document the contract; add characterisation tests** | Keep `State` as the single transaction authority, write down the contract in §2, and add tests that pin R1/R2/R4/R7 current behaviour without endorsing it | Zero behavioural risk; makes Stage 5 hazards visible | Leaves R1–R3 unfixed until separately approved | **Recommended now** |
| **B — Encapsulate on touch** | Move the leaked rollback-point SQL (R5) behind named `State` methods with identical statements and transactions, and switch the three reads to `read()` (R6), as part of the Stage 5 change that touches those call sites | One owner for the rollback-protection invariant; small diff; no schema change | Touches safety-critical code; needs focused tests | **Recommended as a Stage 5 prerequisite step**, separately approved |
| **C — Repository / unit-of-work split** | Split `State` (2,092 lines) into per-aggregate repositories with a shared transaction object | Smaller files | Fragments transactions that today commit trust, history, audit and operation state atomically; large diff; high regression risk; no correctness gain | **Rejected** |
| **D — Connection pooling or a long-lived connection** | Reuse connections | Marginal performance | Thread-safety and transaction-leak risk; no evidence of a performance problem | **Rejected** |

## 7. Recommended decision

1. **No structural extraction** of `State` (Option C rejected). The one-connection-per-transaction model, `BEGIN IMMEDIATE` writes, WAL reads, `update.lock` mutation serialisation and atomic multi-table publication are sound and should be preserved verbatim.
2. Adopt §2 as the written **transaction-ownership contract** that Stage 4/5 designs must cite.
3. Treat **S6-R1/R2/R3** as a separately tracked correctness issue (owner decision G2), resolved **before** Stage 5 finalises its completion semantics.
4. Apply **Option B** only inside Stage 5 changes that already touch those call sites, with identical SQL and transaction boundaries, after explicit approval.

## 8. Implications for Stages 4 and 5

- **Stage 4 (Compose observation versus mutating/trust authority):** observation must stay on `read()` transactions only. Trust publication must remain one `State` transaction that commits baseline, fence, history, audit and operation status together (`publish_bootstrap_success`, `publish_namespace_apply`). Splitting it across modules or transactions is prohibited. Mutation remains under `update.lock`.
- **Stage 5 (update, rollback, Compose mutation coordination):** must define a single durable-completion policy (G2), decide whether CLI mutations get durable intent (G3), and own the rollback-point invariant through `State` methods (Option B). It must not introduce compensating Docker actions for database-only failures without explicit approval.
- **Both:** no new connections outside `State`, no nested write transactions, no schema change without a versioned migration, and the web process must never open the core database.

## 9. Acceptance criteria for this assessment

1. Every `State` method is classified by transaction type (done: AST inventory, §3).
2. Every direct SQL site outside `state.py`/`webstate.py` is listed (done: §3 "leaks").
3. Every risk has a severity, an evidence level (P/C/I) and a treatment (done: §5).
4. At least one critical claim is proven by execution rather than inference (done: S6-R1 probe; Phase 3 tests for E4/E5).
5. The independent review finds no unaddressed Blocker/High issue.
6. The owner records decisions G1–G4.

## 10. Regression-test strategy (for later, separately approved work)

- **Characterisation first** (tests only, `src/` unchanged): R1 ordinary update with `record(SUCCESS)` failing; R2 pinned update with `record(SUCCESS)` failing; R4 kill window simulated by raising `BaseException` after recreate; R7 worker death between staging and the terminal mark. Assert current behaviour as **documented current behaviour**, not as desired contract (the Phase 3 pattern).
- **Contract tests** for Option B moves: identical SQL effects before and after each move, run on synthetic state for success, expiry, purge, removal and rollback refusal paths.
- **Concurrency:** two `State` instances on one temporary database exercising `update.lock` refusal, `BEGIN IMMEDIATE` contention under a short `busy_timeout`, and the scan lease; use events, never production state.
- Keep the fail-closed isolation guards (`scripts/run_tests.py`) for all of the above.

## Decision gates (owner approval required)

- **G1 — Accept this assessment:** Option A now; Option C rejected; §2 adopted as the transaction contract.
- **G2 — S6-R1/R2/R3:** open a public tracking issue and approve a characterisation-test PR, followed by a separately reviewed correctness fix. Choose the target policy: retry, then keep the factual outcome with a durable warning (the current Compose-apply behaviour) — recommended — or another explicitly approved policy.
- **G3 — S6-R4:** accept "no durable intent for CLI mutations" as a documented limitation, or require it in Stage 5.
- **G4 — Option B:** approve "encapsulate on touch" for rollback-point SQL as part of Stage 5.

Until G1–G4 are recorded, Stage 4/5 detailed designs may cite this contract but must not implement changes to `State`, transactions or completion semantics.

## Excluded scope

Any `src/` or test change; schema or migration changes; E1–E5 fixes; new dependencies; changes to CI, repository settings or deployment; production database access.
