# Stage 6 assessment (brought forward): SQLite state and transaction ownership

**Status:** Owner decisions G1–G5 recorded (see [Owner decisions](#owner-decisions-recorded)); approved as the architectural baseline for Stages 4 and 5 once merged. **This document authorises no implementation.** Each corrective item below needs its own separately reviewed PR.
**Canonical repository:** `rdna897/upt` (public).
**Baseline:** `main` at `f50eb5e3a68a14c504d68d5a297d780057660f5f` (Phase 3 merged). Re-verify cited lines before any implementation.
**Sequencing:** this is the Stage 6 *assessment* performed before detailed Stage 4/5 designs, as required by the [working index](architectural-refactor-index.md). It is not Stage 6 implementation.
**Deployment:** the production deployment freeze remains mandatory.

## Objective

Establish who owns SQLite state, where transactions begin and end, how SQLite publication interleaves with Docker and filesystem side effects, and which concurrency contracts Stages 4 and 5 must preserve. Then decide whether any extraction or stronger internal boundary is justified now. No extraction is a valid outcome.

## Evidence conventions

- **P (proven):** demonstrated by an existing test or by a synthetic probe run under `scripts/run_tests.py` isolation for this review, by the author or the independent reviewer (probes were scratch files outside the repository and are not committed).
- **C (code-read):** established by reading the cited code path; no executing test isolates it.
- **I (inferred):** a consequence of C-level facts that has not been executed.

Validation for this review: 620 tests in the state-boundary suites passed under isolation with synthetic temporary state only (`test_operation_state`, `test_schema_compatibility_boundary`, `test_state_rollback_compatibility`, `test_post_mutation_reconciliation`, `test_compose_apply`, `test_compose_namespace_apply`, `test_compose_bootstrap`, `test_compose_recovery_retention`, `test_disk_retention`, `test_web_closure_scan`, `test_web_session_persistence`, `test_web_rollback`, `test_web_operations`, `test_service_verification`, `test_runtime_health`, `test_core`). No production database was opened.

## 1. Databases, processes and cross-process locks

| Store | File | Opened by | Writers | Notes |
| --- | --- | --- | --- | --- |
| Core state | `<state_dir>/history.sqlite3` | `State` in the privileged agent (`webcli.py:131`) and the CLI (`cli.py:519`); offline `state_transition.py` | Agent threads (scan worker, targeted verification, runtime monitor, update/rollback/Compose workers, post-mutation reconciliation); CLI commands | Schema 9 with immutable `core_schema_identity` (`state.py:322-392`) |
| Web state | `<web_state_dir>/history.sqlite3` | `WebState` in the unprivileged web process (`webapp.py:263`, `webcli.py:25`) | Request handlers (sessions, users, credentials, web audit) and the offline admin CLI (`upt web reset-admin` and similar, `webcli.py:88-154`, under `web.lock`) | Separate schema (`webstate.py`, version 4), path validation before every open; never holds Docker/history tables. `WebState` inherits every `State` method; only the web-schema methods are valid against it (boundary by convention, not by type) |

The web process never opens the core database; it reaches core state only through bounded agent RPCs. This privilege separation is a hard invariant for any Stage 6 change. **(C)**

| Lock | Scope | Holders | Contract |
| --- | --- | --- | --- |
| `update.lock` (`lock.py`, non-blocking `flock`) | Cross-process; all mutations | CLI modifying commands (`cli.py:527`, retention `cli.py:385`), agent update/rollback/Compose workers (`webservice.py:1373, 1546, 1879, 2018, 2255, 2286`), offline transition | Serialises Docker/Compose/source mutations and `recover_abandoned_operations` (`state.py:778` docstring: caller must hold it). **Not** held by: rollback *review* (`webservice.py:1163-1168`, reaches the `connect()` read at `webservice.py:971`), passive baseline capture (`webservice.py:3180-3185`, `_baseline_lock` only), read-only CLI inventory (`upt retention`, `cli.py:477`), scans, the runtime monitor or post-mutation reconciliation. **(C)** |
| `scan-worker.lock` (blocking `flock`) | Cross-process; scan worker lifetime | `State.scan_worker_guard` (`state.py:290`); probed non-blockingly by `_scan_worker_is_live` | Lease for stale-scan recovery (`claim_scan`, `recover_stale_scans`). **(C)** |
| `web.lock` | Web admin CLI | `webcli.py:150,153` | Serialises offline user-administration commands. **(C)** |
| In-process `threading.Lock`s | Agent | `_lock`, `_baseline_lock`, `_health_lock` | Protect in-memory intents, thread maps and caches; none spans a SQLite transaction across threads. **(C)** |

## 2. Transaction primitives (the single authority)

All online core and web transactions are opened by three `State` primitives (`state.py:181-288`). Exceptions: the offline `state_transition.py` tool opens its own connections (read-only snapshots, staged copy and `os.replace`), and `compact_if_needed` uses its own autocommit connection. Several modules issue SQL on a `State`-opened connection ("SQL ownership" differs from "transaction ownership"; see §3).

- `_new_connection()` opens a fresh connection per transaction (`timeout=30`, `busy_timeout=30000`, `foreign_keys=ON`, `0600` file and sidecar permissions). There is no connection pooling and no connection shared between threads. **(C)**
- `connect()` opens **`BEGIN IMMEDIATE`**, then commits on normal exit or rolls back on any `BaseException`, and always closes. This reserves the single SQLite writer slot for the whole block. **(C)**
- `read()` opens a deferred `BEGIN` read transaction and always rolls back. Under WAL (`_ensure_schema` sets `journal_mode=WAL`), readers never block the writer. **(C)**
- `_ensure_schema()` runs migrations once per `State` instance under a process-local lock and one `BEGIN IMMEDIATE` transaction. `ensure_compatible()` re-checks the version and identity on every mutation front door. Online code never downgrades. The offline transition (`state_transition.py:65-123`) is the only path that can replace the database with an earlier snapshot, and only with explicit quiescence confirmation, `update.lock` and `scan-worker.lock` held, a pre-replacement snapshot retained, and an explicit state-loss acknowledgement. **(P, `test_schema_compatibility_boundary`; C for the transition)**
- `compact_if_needed()` runs `VACUUM` on a separate autocommit connection after a read-only free-page check (`state.py:585-605`). **(C)**

Contract properties verified for this review:

- **Side effects inside write transactions.** Two paths hold `BEGIN IMMEDIATE` across non-database effects: `rollback_points(image_details=True)` runs `docker system df` (timeout 120 s) inside its write transaction (`retention.py:121-124`), reached from the read-only `upt retention` command without `update.lock` (`cli.py:477`); and recovery-bundle expiry deletes the filesystem bundle inside the transaction that deletes its receipt (`retention.py:80-87`), so a later rollback of the receipt delete cannot restore deleted files. `_migrate_refs` also writes (`INSERT OR IGNORE INTO rollback_refs`) from that read-only inventory path. **(C)**
- **No nested transactions.** No `State` method opens a write transaction while another write transaction of the same thread is open. Methods that compose several public operations (`finish_scan`, `create_operation`, `recover_abandoned_operations`) call them **sequentially**, as separate transactions. Doing otherwise would block for 30 s and then fail with `database is locked`. **(C, AST inventory of every `State` method)**
- **Check-then-recheck.** Pre-transaction read checks are re-validated inside the write transaction where it matters; for example, `publish_bootstrap_success` re-queries the competing fences inside its `BEGIN IMMEDIATE` (`state.py:1147-1170`). **(C)**
- **Retries.** SQLite retries only via `busy_timeout`. The only application-level retry of a history write is the Compose apply path (`webservice.py:2643-2654`, three attempts (`COMPOSE_HISTORY_ATTEMPTS = 3`), then keeps the factual workload outcome and adds a warning). That warning is surfaced through `finish_operation`, which is itself a further SQLite write (`webservice.py:2669`); if the database stays unavailable, the operation remains non-terminal until `recover_abandoned_operations`. **(P, `test_compose_apply.test_history_write_is_retried_before_finalization`, `test_persistent_history_failure_keeps_factual_success_...`; C for the persistent-unavailability consequence)**

## 3. Ownership matrix

"Owner" is the code that issues the SQL. "Leak" marks SQL issued outside `state.py`/`webstate.py`.

| Table group | State owner methods | Other direct SQL (leaks) | Serialisation | Key invariants | Tests |
| --- | --- | --- | --- | --- | --- |
| `history`, `protected_images`, `rollback_refs`, `disk_snapshots` | `record` (history, protection and rollback ref in one transaction), `history*`, `protected`, `save_disk_snapshot` | `operations.py:390` (rollback point read via `connect()`); `webservice.py:971, 1232` (rollback ref reads via `connect()`); `webservice.py:2144` (history read); `retention.py:92-124` (`_migrate_refs` inserts; inventory read with Docker accounting inside the transaction), `retention.py:205-274` (expiry, purge status, history `rollback_result`), `retention.py:274-280` (deletes disk snapshots, resolved refs, protection, old history); `removal.py:23, 40, 209` (rollback ref reads, expiry) | `update.lock` for mutations; **not** for rollback review or `upt retention` inventory | `record()` creates a protection reference for every update/rollback row with `old_image_id` except `BLOCKED` and Compose actions, including `FAILED` rows (`state.py:454-457`). **Rollback eligibility** is narrower: only the latest `SUCCESS` update row for the service (`operations.py:387`, `webservice.py:965`). Never silently remove the only usable rollback point; purge is idempotent (`ALREADY ABSENT`) | `test_state_rollback_compatibility`, `test_web_rollback`, `test_disk_retention`, `test_compose_recovery_retention` |
| `operation_runs`, `operation_events` | `create_operation`, `set_operation_running`, `operation_event`, `finish_operation`, `recover_abandoned_operations`, bootstrap/namespace publish and finish methods, `operation_status` | reads: `compose_bootstrap.py:210-211` (active-operation check), `compose_recovery_retention.py:224` (lifecycle proof) | `update.lock` for creation and recovery | One active mutation; abandoned operations are recovered only under `update.lock`; the terminal event is written in the same transaction as the terminal status | `test_operation_state`, `test_web_operations`, `test_compose_bootstrap`, `test_compose_namespace_apply` |
| `compose_baselines`, `compose_bootstrap_fences`, `compose_recovery_receipts` | `insert/delete_compose_baseline`, `publish_bootstrap_success`, fence and namespace-apply methods, `prune_operations` (receipt archiving) | `compose_baseline.py:249` (read); `compose_recovery_retention.py:183-278` (fence/receipt reads and `INSERT OR IGNORE` receipts on the caller's connection, including inside `State.prune_operations`); `retention.py:80-87` (receipt delete with bundle removal) | `update.lock` for mutation paths; passive baseline capture uses only `_baseline_lock` (`webservice.py:3180-3185`) | Trust publication, fence resolution, history and audit commit together | `test_compose_bootstrap`, `test_compose_apply`, `test_same_project_baseline_reconciliation` |
| `scan_runs`, `scan_events`, `service_snapshots`, `latest_scan` | `claim_scan`, `start_scan`, `scan_event`, `touch_scan`, `stage_scan_result`, `mark_scan_terminal`, `recover_stale_scans`, `web_prune` | none | `scan-worker.lock` lease; one active scan | Partial or failed scans never replace the last complete inventory | `test_web_closure_scan`, `test_post_mutation_reconciliation` |
| `service_verifications` | `save_verification`, `invalidate_verification`, `reconcile_runtime`, `publish_*` (invalidation inside publication) | none | none across processes; ordering by identity and invalidation | A late scan cannot revive an invalidated update; invalidation commits with the runtime publication | `test_service_verification`, `test_post_mutation_reconciliation`, `test_targeted_verification_worker` |
| `runtime_snapshot` | `save_runtime_snapshot`, `record_runtime_failure`, `reconcile_runtime`, `runtime_snapshot` | none | `attempted_at` ordering guard (E4/E5, [#6](https://github.com/rdna897/upt/issues/6)) | The previous success is retained on failure; older attempts are rejected | `test_runtime_health`, `test_post_mutation_reconciliation` |
| `audit_events` (core), `disk_snapshots` | `audit`, `save_disk_snapshot`, `web_prune` | `retention.py:276` deletes expired `disk_snapshots` rows directly (listed with the rollback-point group above) | `update.lock` is not held for `upt retention` | Bounded, redacted details | `test_disk_retention`, `test_web_closure_scan` |
| `users`, `web_sessions`, `web_credentials`, `audit_events` (web) | `WebState` inherits the `State` user/session/credential/audit methods | none | `BEGIN IMMEDIATE` per method; `web.lock` serialises admin CLI commands only (not the running web server) | Separate DB; path validation per connection; credential consumption plus password change plus session revocation commit together (`state.py:670-690`) | `test_web_session_persistence`, `test_web_closure_auth` |
| `schema_version`, `core_schema_identity` | `_ensure_schema`, `_migrate`, `ensure_compatible`; offline `state_transition.py` | `state_transition.py` (offline, own connections, snapshot/staged copy/`os.replace`, under `update.lock` and `scan-worker.lock`) | migration transaction; offline quiescence | Online code never downgrades; offline restoration of an earlier snapshot requires explicit state-loss acknowledgement; the identity row is immutable (triggers) | `test_schema_compatibility_boundary` |

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

Web rollback (webservice.py:1163 review [no update.lock] -> 1368- execute [update.lock])
  review: _completed_rollback_candidate -> connect() read of rollback_refs (webservice.py:971)
  execute: create_operation -> _rollback_worker (webservice.py:2014) -> do_web_rollback (operations.py:430-) -> docker tag / compose up / verify
  -> state.record(ROLLED BACK) (operations.py:564)
  except (OSError, RuntimeError, ValueError, TypeError, KeyError, CommandError) -> recovery
  [sqlite3.Error is not in that tuple] -> webservice.py:2134-2160 -> record(FAILED, "NO CHANGES MADE")
  -> audit -> finish_operation

Passive baseline capture (webservice.py:3175-3195) [_baseline_lock only]
  ensure_compatible -> assert_service_unfenced -> insert_compose_baseline

Web login (webapp.py:640-661)                 Admin reset (webcli.py:88-99) [web.lock]
  web_user() + verify_password (read txn)       update_password_with_credential (one write txn:
  revoke_session(old sid) (write txn)            password + revoke all sessions + consume code)
  create_session(new sid) (write txn)

Retention (retention.py:205-282) [update.lock]
  expire refs (write txn) -> docker image rm -> purge_status/rollback_result (write txn) -> delete resolved refs -> compact
  recovery-bundle expiry (retention.py:80-87): [write txn: lifecycle proof -> remove bundle files -> delete receipt]

Read-only inventory: `upt retention` (cli.py:477) [no update.lock]
  _migrate_refs (write txn) -> rollback_points: [write txn held across `docker system df`, timeout 120 s]
```

## 5. Risk register

Severity combines impact and likelihood. "Existing" means present on the baseline and **not** to be fixed silently by Stage 4/5/6 work.

| ID | Severity | Evidence | Finding | Proposed treatment |
| --- | --- | --- | --- | --- |
| S6-R1 | **High** (high impact, low likelihood) | **P** (synthetic probe, ordinary update path; independently re-run by the reviewer) | **A successful update can be recorded as FAILED.** In the ordinary `do_update` path, if `state.record(SUCCESS)` raises after a healthy recreate (for example, `database is locked` after the 30 s busy timeout, or an I/O error), the `except` branch records `FAILED` and re-raises. The container keeps running the new image. The handler's own `state.record` (`operations.py:374`) is unguarded: if the database is persistently unavailable it raises as well, replaces the original exception, and the completed update has **no durable history row at all** (the same applies to the `BLOCKED` branch). When the second write succeeds, the `FAILED` row still carries a protection reference for the previous image (`state.py:454-457`), but it is **not rollback-eligible**: rollback selects the latest `SUCCESS` update, so it either refuses (no earlier `SUCCESS` row) or targets an **earlier** update's point (`operations.py:387`). The CLI path stores the raw exception text in history details. | Existing defect; tracked in [#9](https://github.com/rdna897/upt/issues/9) (G2); characterisation test first. Align with the Compose-apply policy (retry, then keep the factual outcome with a durable warning). **Prerequisite for Stage 5.** |
| S6-R1b | **High** (high impact, low likelihood) | **P** (reviewer's synthetic web-rollback probe); **C** mechanism | **A successful rollback can be recorded as "FAILED / NO CHANGES MADE".** `do_web_rollback`'s recovery handler catches `(OSError, RuntimeError, ValueError, TypeError, KeyError, CommandError)` (`operations.py:574`); `sqlite3.Error` is none of these. A failure of `state.record(ROLLED BACK)` after a healthy rollback therefore skips recovery, and the web wrapper records `FAILED` with `rollback_result="NO CHANGES MADE"` and the error text "review became stale before mutation" (`webservice.py:2156-2165`), while the container remains rolled back. Separately, if `finish_operation` fails after a successful record, history says success while the operation is marked failed or abandoned (`webservice.py:2134`). The CLI `do_rollback` records once after the effect with no handler (`operations.py:425`), so a write failure raises after the rollback and leaves no history row (see R4). | Existing defect; tracked with R1 in [#9](https://github.com/rdna897/upt/issues/9) (G2); characterisation test first. |
| S6-R2 | Medium | **C** (pinned path, operations.py:156-199); **I** for runtime effect | **Same window on the pinned path triggers compensating recovery.** A failure of `state.record(SUCCESS)` after a healthy recreate enters the recovery branch: it restores the old pin only if the source still holds UPT's bytes, then, because `recreate_started` is true, makes a **conditional, best-effort** recreate of the old digest (web callers add `pre_recovery_check`, which may refuse). Namespace updates that already passed their mutation marker take a separate branch with no restoration (`operations.py:161-163`). A healthy update can therefore be reversed because of a database write failure, and the reversal is recorded only as `FAILED`. | Tracked in [#9](https://github.com/rdna897/upt/issues/9): characterisation test, then the policy together with R1. Stage 5 must define one "durable completion point" rule for all mutation kinds. |
| S6-R3 | **High** (policy gap behind R1/R1b/R2) | **C** | **Inconsistent completion policy across mutation kinds.** Compose apply retries the history write and never revokes a committed workload outcome, but surfacing its warning needs another write (`finish_operation`, `webservice.py:2669`). Image update (R1/R2) and rollback (R1b) do neither. Namespace update and bootstrap publish completion atomically with operation state. Only Namespace Apply defines behaviour for an **ambiguous commit** (an exception after SQLite has committed): it re-reads durable state via `namespace_apply_published` (`namespace_apply.py:778`, `state.py:1448`), never recreates again, and has regression coverage (`tests/test_compose_namespace_apply.py:484`). No other mutation path does, and no path defines behaviour for **persistent** database unavailability; the shared policy is missing. | Tracked in [#9](https://github.com/rdna897/upt/issues/9). Approved G2 programme (see [Owner decisions](#owner-decisions-recorded)): one written policy covering factual workload outcome, rollback eligibility and protection, retry bounds, the warning surface when no write succeeds, ambiguous commits, and no compensating Docker action for database-only failures. |
| S6-R4 | Medium | **C** | **No durable intent for ordinary CLI mutations.** Web mutations create an `operation_runs` row before any Docker effect and are recoverable by `recover_abandoned_operations`. Ordinary CLI updates, rollbacks and removals write history only after the effect, so a process kill between recreate and `record` leaves no history and no rollback reference for that change. **Exception:** CLI namespace updates already create an operation and commit a mutation marker before recreation (`namespace_update.py:210-222`), although earlier pull/pin effects precede that marker. | Decided (G3): Stage 5 extends the existing operation lifecycle to ordinary CLI mutations, preserving the namespace model; tracked in [#10](https://github.com/rdna897/upt/issues/10). |
| S6-R5 | Medium | **C** | **Rollback-point SQL is spread across five modules.** `rollback_refs` and `history` are read or written directly by `operations.py`, `webservice.py` (×3), `retention.py` and `removal.py`. The protection invariant ("never silently remove the only usable rollback point") is enforced by convention across modules rather than by one owner. | Decided (G4): move these statements behind named `State` methods when Stage 5 touches the code ("encapsulate on touch"), preserving data semantics and invariants (see Option B). |
| S6-R6 | Low | **C** | **Reads through write transactions.** `operations.py:390` and `webservice.py:971, 1232` read `rollback_refs` with `connect()` (`BEGIN IMMEDIATE`). They reserve the writer slot and can wait up to 30 s behind another writer. `webservice.py:971` is also reached from rollback **review** without `update.lock` (`webservice.py:1168`). No correctness impact found. | Use `read()` when the statements move behind `State` (R5); an explicitly approved transaction-boundary improvement (Option B). |
| S6-R10 | Medium | **P** (reviewer's synthetic probe: mocked accounting held in the transaction and a shortened busy timeout; competing writes fail while WAL reads continue); **C** for the CLI path | **A read-only command holds the writer slot across a Docker call.** `upt retention` (no `update.lock`, `cli.py:477`) runs `rollback_points(image_details=True)` (`retention.py:118`), which opens `state.connect()` (`BEGIN IMMEDIATE`) and, still inside that transaction, calls `_docker_image_accounting()` (`retention.py:124`), i.e. `docker system df` with a 120 s timeout. The SQLite writer slot can therefore be held for up to 120 s. `_migrate_refs` also writes from the same read-only path. Any agent or CLI writer that waits longer than `busy_timeout` (30 s) fails with `database is locked`. **This is a realistic trigger for R1/R1b** and for runtime-monitor or scan persistence failures. | Decided (G5): fix in a separate, early corrective PR **before** Stage 5 implementation ([#11](https://github.com/rdna897/upt/issues/11)): Docker accounting outside any write transaction, scoped read transactions, no unnecessary mutation from read-only inventory paths, retention and rollback-protection behaviour preserved, deterministic concurrency regression test. |
| S6-R11 | Low | **C** | **Filesystem deletion inside a write transaction.** Recovery-bundle expiry removes the bundle and then deletes its receipt in one transaction (`retention.py:80-87`). If the commit fails, the receipt survives while the files are gone; later lifecycle proof must tolerate a receipt without a bundle. | Characterisation test; document the expected recovery. |
| S6-R12 | Medium | **P** (reviewer's synthetic `State` interleaving); **C/I** for the login consequence | **Login versus password-reset race.** Login verifies the password hash in a read transaction and creates the session in a later write transaction (`webapp.py:647-660`). A concurrent `reset-admin` (`update_password_with_credential`, `state.py:670-690`) can change the password and revoke all sessions in between, after which the stale login still creates a fresh authenticated session. | Decided (G5): tracked in [#12](https://github.com/rdna897/upt/issues/12); make session creation conditional on the credential state observed at verification; must be resolved before final release readiness. Existing session, CSRF and authentication protections are preserved. |
| S6-R13 | Low | **C** | **Offline transition is outside the online contract.** `state_transition.py` opens connections outside `State` and can restore an earlier snapshot after explicit state-loss acknowledgement. | Document only; any change needs its own review. |
| S6-R7 | Low | **C/I** | **Scan finalisation spans transactions.** `stage_scan_result` publishes `latest_scan` (status `finalizing`) before housekeeping and `mark_scan_terminal`. If the worker dies in between, stale-scan recovery marks the run `failed` while `latest_scan` already shows its (complete) results. The data is trustworthy; only the run status disagrees. | Document as intended two-phase publication; add a characterisation test if Stage 6 implementation proceeds. |
| S6-R8 | Low | **C** | **`VACUUM` from scan housekeeping is not under `update.lock`.** It runs concurrently with agent or CLI writers and relies on `busy_timeout`; a large database could stall writers for the vacuum duration. | Accept (the database is small and bounded); record the expected duration bound in the policy. |
| S6-R9 | Low | **C** (Phase 3 evidence) | Post-mutation reconciliation reads `runtime_snapshot` in one transaction and publishes in another; merged diagnostic counters can be one tick old. Ordering is protected by the `attempted_at` guard. | Accept; display-only data. |
| E4–E5 | Low / Info | **P** (Phase 3) | Wall-clock ordering of runtime snapshots ([#6](https://github.com/rdna897/upt/issues/6)). The same wall-clock dependency exists in scan heartbeat staleness (`claim_scan`, `recover_stale_scans`: 600 s) and abandoned-operation age (`julianday('now')`). | Keep in #6; extend its scope note to heartbeat and age checks. No change here. |

Not defects (verified): there are no nested write transactions; schema migration is atomic, and mutation front doors refuse incompatible schemas before side effects; the web process cannot open core state; abandoned-operation recovery always runs under `update.lock`; retention purge is idempotent across interruption (`ALREADY ABSENT`); and in-process locks never span a SQLite transaction across threads.

## 6. Alternatives

| Option | Description | Benefit | Cost and risk | Verdict |
| --- | --- | --- | --- | --- |
| **A — Retain the architecture; document the contract; add characterisation tests** | Keep `State` as the single transaction authority, write down the contract in §2, and add tests that pin R1/R2/R4/R7 current behaviour without endorsing it | Zero behavioural risk; makes Stage 5 hazards visible | Leaves R1–R3 unfixed until separately approved | **Approved (G1)** |
| **B — Encapsulate on touch** | Move the leaked rollback-point SQL (R5) behind named `State` methods, preserving the data semantics and invariants of each statement. Two **transaction-boundary changes** are explicitly part of this option: switching the three `connect()` reads to `read()` (R6), and taking Docker accounting out of the inventory transaction (R10, delivered earlier under G5). These are intentional improvements, not behaviour-neutral moves. Done as part of the change that touches those call sites | One owner for the rollback-protection invariant; small diff; no schema change | Touches safety-critical code; needs focused tests, including equivalence of results before and after each move | **Approved (G4)** as narrowly scoped work inside Stage 5; no general database rewrite |
| **C — Repository / unit-of-work split** | Split `State` (2,092 lines) into per-aggregate repositories with a shared transaction object | Smaller files | Fragments transactions that today commit trust, history, audit and operation state atomically; large diff; high regression risk; no correctness gain | **Rejected** |
| **D — Connection pooling or a long-lived connection** | Reuse connections | Marginal performance | Thread-safety and transaction-leak risk; no evidence of a performance problem | **Rejected** |

## 7. Decision

Approved by the owner (see [Owner decisions](#owner-decisions-recorded)):

1. **No structural extraction** of `State` (Option C rejected; connection pooling rejected). The one-connection-per-transaction model, `BEGIN IMMEDIATE` writes, WAL reads, `update.lock` mutation serialisation, separate core/web databases and privilege boundaries, and atomic multi-table publication are sound and are preserved.
2. §2 is the written **transaction-ownership contract** that Stage 4/5 designs must cite.
3. **S6-R1/R1b/R2/R3** are a separately tracked corrective programme (G2), resolved before Stage 5 finalises its completion semantics.
4. **R10** is fixed in a separate early PR before Stage 5 implementation (G5); **R12** is tracked separately and must be resolved before final release readiness.
5. **Option B** applies only inside Stage 5 changes that already touch those call sites (G4); transaction-boundary improvements must be explicit and tested.

## 8. Implications for Stages 4 and 5

- **Stage 4 (Compose observation versus mutating/trust authority):** today, passive status reads can **write** trust material (passive baseline capture, `webservice.py:3175-3195`, under `_baseline_lock` only, not `update.lock`). Making observation read-only would therefore be a **proposed boundary change**, not a description of current behaviour, and needs its own approval and tests. Trust publication must remain one `State` transaction that commits baseline, fence, history, audit and operation status together (`publish_bootstrap_success`, `publish_namespace_apply`); splitting it across modules or transactions is prohibited. Mutation paths remain under `update.lock`.
- **Stage 5 (update, rollback, Compose mutation coordination):** depends on the G5 fix for R10 and on the G2 policy, and must define a single durable-completion policy for updates, rollbacks and Compose operations, including terminal-publication failure, ambiguous commits and persistent unavailability (G2); extend the existing operation lifecycle to ordinary CLI updates, rollbacks and relevant removals while preserving the namespace model (G3); and own rollback eligibility versus protection through `State` methods (G4). Stage 5 designs are approved separately; this document does not authorise every Stage 5 change. It must not introduce compensating Docker actions for database-only failures without explicit approval.
- **Both:** no new connections outside `State` (the offline transition excepted), no nested write transactions, no Docker or filesystem effects inside a write transaction in new code (R10/R11 are existing exceptions), no schema change without a versioned migration, and the web process must never open the core database.

## 9. Acceptance criteria for this assessment

1. Every `State` method is classified by transaction type (done: AST inventory, §3).
2. Every direct SQL site outside `state.py`/`webstate.py` is listed (done: §3 "leaks").
3. Every risk has a severity, an evidence level (P/C/I) and a treatment (done: §5).
4. At least one critical claim is proven by execution rather than inference (done: S6-R1 probe; Phase 3 tests for E4/E5).
5. The independent review finds no unaddressed Blocker/High issue.
6. The owner records decisions G1–G5 (done: [Owner decisions](#owner-decisions-recorded)).

## 10. Regression-test strategy (for later, separately approved work)

- **Characterisation first** (tests only, `src/` unchanged): R1 ordinary update with `record(SUCCESS)` failing; R1b web and CLI rollback with `record` or `finish_operation` failing; R2 pinned update with `record(SUCCESS)` failing; R10 a blocked accounting call holding the writer slot; R12 the login and reset interleaving; R4 kill window simulated by raising `BaseException` after recreate; R7 worker death between staging and the terminal mark. Assert current behaviour as **documented current behaviour**, not as desired contract (the Phase 3 pattern).
- **Contract tests** for Option B moves: identical SQL effects before and after each move, run on synthetic state for success, expiry, purge, removal and rollback refusal paths.
- **R10 regression (G5):** a deterministic test where a blocked accounting call must not prevent a competing `State` writer from acquiring the writer slot within a short `busy_timeout`.
- **Concurrency:** two `State` instances on one temporary database exercising `update.lock` refusal, `BEGIN IMMEDIATE` contention under a short `busy_timeout`, and the scan lease; use events, never production state.
- Keep the fail-closed isolation guards (`scripts/run_tests.py`) for all of the above.

## Owner decisions (recorded)

Recorded from the owner's approval of this assessment. They authorise the tracking and sequencing below, **not** any implementation in this PR.

- **G1 — Approved.** Option A: retain the existing `State` architecture and adopt §2 as the transaction-ownership contract. Repository/unit-of-work extraction and connection pooling are rejected. Separate core/web databases, privilege boundaries, WAL reads, per-transaction connections and atomic publication are preserved.
- **G2 — Approved corrective programme** ([#9](https://github.com/rdna897/upt/issues/9)): S6-R1, R1b, R2 and R3. Characterisation tests come first, then separately reviewed fixes. Not implemented in this PR. The policy specification must cover:
  - **Factual outcome versus persistence outcome.** A completed Docker operation is never reversed, revoked or misreported solely because SQLite history publication fails; the workload outcome and the history-publication outcome are recorded and reported separately.
  - **Persistent database unavailability.** The existing ordinary-update failure handler writes again after the first write fails (`operations.py:374`), so persistent unavailability can leave a completed mutation with **no durable history record** (R1), not merely an incorrect `FAILED` row. The policy must define behaviour when no write succeeds.
  - **Bounded retries, idempotency and ambiguous commits.** A bounded retry rule, idempotent publication, and reconciliation of an exception raised after SQLite committed, so a retry cannot duplicate or contradict a committed row. The existing Namespace Apply reconciliation (`namespace_apply_published`) is the reference pattern.
  - **Rollback eligibility and recovery evidence.** How eligibility is decided versus protection; rollback references, backups and other recovery artefacts stay protected whenever publication is incomplete or ambiguous. The sole usable rollback point is never silently removed.
  - **Durable intent and artefact protection.** Recovery intent and artefacts must survive interruption so an operator can reconcile; no new persistence mechanism is prescribed here and any such mechanism needs a separate design review.
  - **Operator visibility independent of SQLite.** Failures remain visible to the operator (CLI output and exit status, process logs and, where applicable, the web surface) even when no SQLite write succeeds.
  - **No compensating Docker mutation** triggered only by a database failure (this includes the pinned-path recovery in R2).
- **G3 — Durable CLI intent required** ([#10](https://github.com/rdna897/upt/issues/10)). Stage 5 extends the existing operation lifecycle to ordinary CLI updates, rollbacks and relevant removals; preserves the namespace-update model; records recoverable intent before irreversible mutation; and defines interruption recovery without unsafe automatic rollback. Designed and approved separately.
- **G4 — Option B approved.** Narrowly scoped rollback-point SQL encapsulation when Stage 5 touches the relevant code. Prefer named `State` methods and preserve existing data invariants. Explicitly approved improvements to read-only transaction boundaries are permitted (`connect()` to `read()`; Docker accounting outside a transaction). No general database architecture rewrite.
- **G5 — Approved.** R10 ([#11](https://github.com/rdna897/upt/issues/11)) is fixed in a separate, early corrective PR before Stage 5 implementation, with a deterministic concurrency regression test. R12 ([#12](https://github.com/rdna897/upt/issues/12)) is tracked separately and must be resolved before final release readiness; existing session, CSRF and authentication protections are preserved.

### Tracking issues

| Decision | Issue |
| --- | --- |
| G2 — mutation completion and history-publication failures (R1, R1b, R2, R3) | [#9](https://github.com/rdna897/upt/issues/9) |
| G3 — ordinary CLI durable mutation intent (R4) | [#10](https://github.com/rdna897/upt/issues/10) |
| G5 — retention inventory writer contention (R10) | [#11](https://github.com/rdna897/upt/issues/11) |
| G5 — login versus password-reset race (R12) | [#12](https://github.com/rdna897/upt/issues/12) |
| Runtime snapshot ordering debt (E4–E5) | [#6](https://github.com/rdna897/upt/issues/6) |

### Sequence

1. Merge this approved Stage 6a assessment.
2. Characterisation tests in a separate PR (tests only; documented current behaviour).
3. Fix R10 independently (#11).
4. Implement the G2 completion-policy corrections (#9) after design approval.
5. Prepare the Stage 4 specification using the accepted transaction contract.
6. Design Stage 5 around G2, G3 and G4.
7. Resolve R12 (#12) before final release readiness.

Stage 4 specification work may proceed in parallel with separately approved corrective work. Stage 4/5 designs may cite the contract but must not change `State`, transactions or completion semantics until the corresponding item above is separately approved. This list does not pre-authorise any Stage 5 change.

## Independent review record

Independent technical review, read-only, round 1: **request changes**, no Blocker. It independently confirmed: no nested write transactions; the web process uses a separate, path-validated `WebState`; R1 and the guarded R2 behaviour; the Compose history retry; schema refusal; and runtime ordering protection. Its findings, all verified against source and incorporated:

- (High) rollback and terminal-publication completion failures were missing → S6-R1b, R3 and G2 extended;
- (Medium) incomplete direct-SQL inventory (`compose_recovery_retention.py`, receipt and disk-snapshot deletion, `compose_bootstrap.py` reads `operation_runs`) → §3 corrected; SQL ownership distinguished from transaction ownership;
- (Medium) lock coverage overstated (rollback review, passive baseline capture) plus effects inside write transactions → §1, §2, §4, R6, R10, R11 and Stage 4 implications;
- (Medium) CLI durable intent needs a namespace-update qualification → R4 and G3;
- (Medium) protection references versus rollback eligibility conflated → §3, R1, R2;
- (Medium) login versus password-reset race and admin CLI as a web-DB writer → §1, §3, §4, R12, G5;
- (Low) offline transition exceptions → §2, §3, R13.

The author additionally identified R10 as a realistic trigger for R1/R1b, and the CLI rollback post-effect write.

Round 2 (commit `658665b`): **approve**. All seven round-1 findings were confirmed resolved against the cited source, with no new actionable findings. The reviewer confirmed the R10 trigger reasoning with a synthetic probe.

Round 3 (decisions update, commit `ba83268`): **request changes**, 1 Medium and 1 Low, both verified and fixed: the claim that no path handles ambiguous commits ignored Namespace Apply's existing reconciliation (R3 narrowed; G2 cites it as the reference pattern), and the `disk_snapshots` ownership row omitted the direct deletion at `retention.py:276`. All other checks passed (documentation-only diff, citations, Option B wording, G2 coverage, Stage 5 gates, sequence, links, public safety).

## Excluded scope

Any `src/` or test change; schema or migration changes; E1–E5 fixes; new dependencies; changes to CI, repository settings or deployment; production database access.
