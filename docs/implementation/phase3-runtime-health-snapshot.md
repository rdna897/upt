# Architectural refactoring — Phase 3: runtime health and snapshot coordination

**Status:** Ready — owner approved Option A (tests only) on 2026-10-10 (see [Owner decisions](#owner-decisions)). Implementation is limited to `tests/test_runtime_health.py`; no production-code change is authorised.
**Canonical repository:** `rdna897/upt` (public).
**Baseline:** `main` at `cc16dc74b998ea869490d3b291b8ddbf886c3859` (revalidate before implementation; re-run the review if any file in the [ownership map](#current-public-source-and-ownership-map-baseline) changed).
**Tracking:** [Architecture Phase 3 — issue #3](https://github.com/rdna897/upt/issues/3).
**Risk:** Low for the recommended tests-only outcome; medium for any code extraction; high if monitor lifecycle, failure handling or SQLite publication semantics change.
**Deployment:** Production deployment freeze remains mandatory through programme closeout and separate operator approval.

## Objective and prior work

Reduce coupling inside `ReadOnlyService` while retaining the current read-only runtime observation, health-cache and state-publication behaviour. Phase 1 already isolated full scanning in `scan_worker.py`; Phase 2 isolated single-container targeted verification behind `_verify_exact_container_once` with real-worker regressions (public PR #2). Neither is in scope here.

This phase must establish whether further extraction is justified **at all**. `runtime.py` already owns bounded Docker inventory collection and sanitisation; moving those routines again or inventing another worker framework is not the goal. A targeted test-only improvement or an evidence-based **not warranted** outcome is permissible with the owner's explicit acceptance.

## Review decision (summary)

**Approved: Option A — no production-code extraction; close the identified lifecycle, ordering and seam-coverage test gaps.** Extraction is recorded as **not warranted**. Option B was not selected; its [conditions](#option-b-conditions-only-if-the-owner-overrides-the-recommendation) are retained only as guidance for any future reconsideration. Option C is rejected.

Rationale in one line: the monitor code is already small (about 80 lines across five methods in a 3,650-line module), has a single external dependency direction (`webservice` → `runtime`/`state`), and its private names are relied on by tests in four suites; extraction would move about 45 lines while adding comparable glue and new seam risk, without removing any coupling that causes a present maintenance problem.

## Current public source and ownership map (baseline)

| Component | Present responsibility | Constraint |
| --- | --- | --- |
| `webservice.py`: `ReadOnlyService.__init__` | `_health_lock`, `_health_stop`, `_health_thread`, initial `_docker_health_cache` | No new shared unprotected mutable state |
| `ReadOnlyService.health()` | Copies cached Docker-health result under lock, returns agent version and liveness | Must stay cheap, cached, bounded and non-blocking; unauthenticated health traffic must not trigger Docker |
| `start_health_monitor()` | Under `_health_lock`: returns if the current thread is alive, otherwise clears the stop event and starts one daemon thread `upt-runtime-health`; loop is health probe → cache publish → runtime refresh → `stop.wait(max(5, int(interval)))` | Retain admission, scheduling and thread-ownership semantics; test real start/stop |
| `_docker_health()` | Function-local `from .system import run`; `docker version --format {{.Server.Version}}`, timeout 10 s; any exception → `{"ok": False, "error": "Docker daemon unavailable"}` | No raw exception text, shell expansion or new command privileges |
| `_refresh_runtime_snapshot()` | Records `attempted_at`; one `collect_runtime_containers(self.config)`; records classified failure or saves success with `captured_at`; safe structured warnings via the `docker_update_manager.webservice` logger | Keep failure classification, persistence and redaction exactly as published |
| `_safe_runtime_failure_class`, `_safe_runtime_exit_code` (module functions) | Sanitised class name / bounded integer exit code for logs | Used only by `_refresh_runtime_snapshot` |
| `stop_health_monitor()` | Sets the shared stop event; joins a different live monitor thread for at most 6 s; not under `_health_lock` | Do not silently change shutdown, overlapping start/stop or blocked-probe behaviour |
| `runtime.py` | Sanitised Docker list (timeout 10 s) / inspect (timeout 20 s), bounded inventory (512), error categories and at most one inventory-churn retry | Keep collection and privacy filtering here; no duplicate collector |
| `state.py` | `save_runtime_snapshot`, `_save_runtime_snapshot`, `record_runtime_failure`, `runtime_snapshot`, `reconcile_runtime` transactionally publish/read the singleton record | State retains SQLite transaction authority, the `attempted_at` ordering guard and previous successful payload |
| `reconciliation.py` | Post-mutation path captures its own `attempted_at`, merges diagnostic counters from `state.runtime_snapshot()` and calls `state.reconcile_runtime(...)`; on failure records `inventory_changed` | Second writer of the same singleton; unchanged by Phase 3 |
| `ReadOnlyService.handle()` and `AgentServer.serve_forever()` | Bounded `health` and `runtime_snapshot` RPCs; monitor starts after socket bind/listen and before the accept loop, and stops in `finally` | No wire-format, permission, RPC or service lifecycle changes |
| `webapp.py`, `webviews.py` | Authenticated runtime read/display and reconciliation of runtime-only and scanned services | Current/stale/unavailable and excluded-container semantics unchanged |

### Call and ownership flow

```text
AgentServer.serve_forever()
  -> ReadOnlyService.start_health_monitor()
      -> [single daemon thread, immediate first tick]
         -> self._docker_health() -> system.run(docker version, timeout=10) -> _docker_health_cache (under lock)
         -> self._refresh_runtime_snapshot()
              -> collect_runtime_containers(config)   [webservice module global; runtime.py]
              -> State.save_runtime_snapshot(containers, captured_at, attempted_at)
                or State.record_runtime_failure(attempted_at, safe_category)
         -> stop_event.wait(max(5, interval_seconds))
  -> ReadOnlyService.handle("health") -> health() -> cached health only
  -> ReadOnlyService.handle("runtime_snapshot") -> State.runtime_snapshot() -> persisted bounded read
  -> ReadOnlyService.stop_health_monitor() [agent server finally]

post-mutation reconciliation (reconciliation.py, separate thread)
  -> attempted_at = now(); discover(); state.runtime_snapshot() [counter merge, own read]
  -> State.reconcile_runtime(...)  [one transaction: invalidate verification + _save_runtime_snapshot]
```

## Coupling analysis

The coupling that is actually present:

1. **Shared lock for two purposes.** `_health_lock` guards both monitor admission (held across `Thread.start()`) and the health cache. This is harmless: the hold is microseconds and `health()` never waits behind Docker (verified: `health()` returns immediately while the probe is blocked).
2. **Shared stop event across monitor generations.** One `_health_stop` event serves every monitor instance. Together with the alive-check ordering this produces the lifecycle limitations listed under [Existing behaviour](#existing-behaviour-and-defects-not-to-be-fixed-in-phase-3).
3. **Implicit wall-clock dependency.** `_refresh_runtime_snapshot` calls `datetime.now(timezone.utc)` directly, so ordering tests must control timing with events instead of an injected clock.
4. **Test seams on private names.** Tests depend on `ReadOnlyService` private attributes and on module paths (see [Compatibility seams](#compatibility-seams-that-any-change-must-preserve)).

None of these is removed by moving `_refresh_runtime_snapshot` into another module: (1) and (2) live in the start/stop methods that every option keeps on the facade; (3) moves with the code; (4) becomes harder to preserve. The publication routine itself depends only on `config`, `state`, the collector, a logger and the clock. It is already a cohesive, side-effect-bounded method.

## Options assessment

| Criterion | A: tests only | B: extract probe-and-publish helper | C: monitor object |
| --- | --- | --- | --- |
| Production lines moved | 0 | ~45 (`_refresh_runtime_snapshot` + two helpers) | ~80 plus state |
| New glue | 0 | New module, call site, 4–5 injected dependencies (state, config, collector, logger, optionally clock) | New class, ownership hand-off, facade delegation for `health/start/stop`, cache relocation |
| Seams broken | None | `webservice.collect_runtime_containers` patch path unless late-bound; logger name unless injected | Additionally `ReadOnlyService.health(SimpleNamespace(_health_lock, _docker_health_cache))` in `test_version_contract.py`, instance patches of `_docker_health` / `_refresh_runtime_snapshot` |
| Lifecycle/race risk | None | Low if thread ownership stays on the facade | Medium: new admission/stop code paths |
| Coupling removed | None (documented) | Marginal: one cohesive method leaves a 3,650-line module | Marginal; adds a second owner of health state |
| Testability gain | Directly closes gaps | Small: the helper could take a clock | Small |

**Option A** is preferred: it closes the real gaps (no parallel-start, blocked-probe, stop/restart, monitor-path ordering or post-stop tests exist) with zero behavioural risk, and leaves a future extraction cheaper because the new tests pin behaviour at the facade boundary.

**Option B** is not wrong, but its benefit does not exceed its cost now. If the owner prefers it, it must follow the conditions below.

**Option C** is rejected: it relocates `_health_lock` / `_docker_health_cache` (a seam used directly by `tests/test_version_contract.py`), creates a second owner of lifecycle state, and introduces new admission/stop code exactly where the existing limitations are, which would invite silently changing them.

### Option B conditions (only if the owner overrides the recommendation)

- New module-level function (for example, `runtime_publication.refresh_runtime_snapshot(*, config, state, collect, logger)`), following the Phase 1 `run_full_scan` pattern of explicit keyword dependencies supplied by the facade.
- The facade passes `collect=collect_runtime_containers` looked up from the `webservice` module **at call time** and `logger=logging.getLogger("docker_update_manager.webservice")` (the logger name is asserted by `test_runtime_probe_and_persistence_logs_are_bounded` and is an operational contract).
- `ReadOnlyService._refresh_runtime_snapshot` remains as a one-line delegating method (instance patches depend on it). `start_health_monitor`, `stop_health_monitor`, `health`, `_docker_health` and all lock/event/thread/cache attributes stay on the facade unchanged.
- Move `_safe_runtime_failure_class` / `_safe_runtime_exit_code` with it only if no other caller exists at implementation time; otherwise import them.
- Timestamps must keep `datetime.now(timezone.utc).isoformat()` (microsecond precision). Do **not** substitute `runtime.utc_now()`, which truncates to seconds and would change equal-timestamp ordering against `reconcile_runtime`.
- The new module must not import `webservice` (no cycle) and must not import Docker/system runners directly.
- All Option A tests are still required and must pass unchanged before and after the move.

## Required behavioural invariants

1. **RPC and privilege:** exact existing `health` payload keys (`ok`, `service`, `version`, `docker`), `runtime_snapshot` response/status/freshness fields, bounded agent operation allowlist and UNIX-socket permissions are unchanged. No new network server, API route, agent token exposure or HTTP-triggered live Docker work.
2. **Scheduling:** one live agent-owned monitor; first health probe and snapshot refresh occur promptly on start; unchanged thread daemon flag and name `upt-runtime-health`, interval lower bound of 5 seconds, default `RUNTIME_INTERVAL_SECONDS` (30), stop-event behaviour and bounded 6-second join. Do not add a scheduler, extra interval task, duplicate daemon or restart side-effect.
3. **Health result:** retain original unchecked cache shape `{"ok": None, "status": "not checked"}`, lock-protected whole-dict replacement and shallow-copy read, bounded 10-second Docker version command and safe failure projection. Docker health and runtime snapshot are separate channels; a runtime collection failure must not overwrite the health cache, and vice versa.
4. **Runtime probe:** `collect_runtime_containers(self.config)` keeps its existing allowlisted container fields, bounded inventory size, single list/inspect retry policy, exclusion behaviour and fault classifications: `docker_unavailable`, `container_limit_exceeded`, `invalid_docker_response`, `inventory_changed`, `probe_failed`.
5. **Failure semantics:** classify `RuntimeProbeError` using its `stage`, `category`, `failure_class`, and optional `exit_code`; unexpected exceptions become `probe_failed` with safe class/exit code only. Failure recording errors are separately logged without raw exception content. Persistence failure after successful collection leaves the earlier record intact rather than recording a fabricated probe failure.
6. **SQLite and time ordering:** `attempted_at` is captured before collection and `captured_at` after collection, both as microsecond-precision UTC ISO strings. `State` rejects a write whose `attempted_at` is strictly older than the stored one (equal timestamps overwrite; an unparsable incoming timestamp bypasses the guard), and atomically replaces success or retains the last successful payload on failure. `reconcile_runtime` must continue to invalidate verification and save its runtime snapshot in a single transaction; a stale-rejected snapshot inside that transaction must not roll back the invalidation. Retain existing singleton schema and computed freshness (default 90 seconds).
7. **UI and safety:** no change to the `never`, `current`, `stale`, `unavailable` and `available` interpretations or `failure_category` presentation, nor to the fact that **missing Docker health checks are not healthy**. Never publish environment values, Docker inspect secrets, credential-bearing errors, mounts or unchecked full Docker metadata.
8. **Logging:** runtime monitor warnings remain on the `docker_update_manager.webservice` logger with the existing message formats.

## Compatibility seams that any change must preserve

| Seam | Used by |
| --- | --- |
| `docker_update_manager.webservice.collect_runtime_containers` (module-global lookup at call time) | `tests/test_runtime_health.py` (`RuntimeAgentBoundaryTests`) |
| Instance attributes `_docker_health`, `_refresh_runtime_snapshot` resolved via `self` inside the loop | `tests/test_runtime_health.py`, `tests/test_web_ux_hardening.py` |
| `ReadOnlyService.health` reading only `self._health_lock` and `self._docker_health_cache` | `tests/test_version_contract.py` (calls it unbound on a `SimpleNamespace`) |
| `_health_thread` attribute | `tests/test_runtime_health.py` |
| `stop_health_monitor()` as the worker-teardown hook | `tests/test_web_rollback.py` and other agent fixtures |
| `start_health_monitor` not called before the schema check in `serve_forever` | `tests/test_schema_compatibility_boundary.py` |
| `docker_update_manager.system.run` as the `_docker_health` runner seam (function-local import) | Fail-closed isolation guards |
| Logger name `docker_update_manager.webservice` | `assertLogs` in `tests/test_runtime_health.py`; operational log filters |

## Existing behaviour and defects (not to be fixed in Phase 3)

Tracking: E1–E3 [issue #5](https://github.com/rdna897/upt/issues/5); E4–E5 [issue #6](https://github.com/rdna897/upt/issues/6).

Verified on the baseline with synthetic, Docker-free probes. These are **existing** behaviours. Phase 3 must neither fix nor worsen them silently; each fix is a separate reviewed change if the owner wants it.

| ID | Severity | Existing behaviour | Evidence |
| --- | --- | --- | --- |
| E1 | Medium | **Restart after a timed-out stop is a silent no-op.** A tick can block for far longer than the 6 s join (`docker version` 10 s + `docker ps` 10 s + `docker inspect` 20 s, with up to one churn retry). If `start_health_monitor` is called while that thread is still alive, it returns before clearing the stop event; the old thread then exits after its probe, leaving **zero** monitors. Production calls start/stop once per `serve_forever`, so impact is limited to tests and any future in-process restart. | `webservice.py` `start_health_monitor` alive-check precedes `_health_stop.clear()` |
| E2 | Low | **One publication after stop.** A thread blocked in `_docker_health` when stop is called still runs `_refresh_runtime_snapshot` once (stop is checked only at loop top and in `wait`). This can write SQLite and update the health cache after `stop_health_monitor` returned. Test fixtures must hold isolation guards and temp directories until the thread has actually exited. | Loop order in `start_health_monitor.monitor` |
| E3 | Low | **Unexpected exception kills the monitor silently.** Exceptions outside the contained regions (practically only logging/clock failures) end the thread without a log; `is_alive()` becomes false, so a later start would restart it. | No `try` around the loop body |
| E4 | Low | **Wall-clock regression stalls publication.** If the system clock steps backwards, monitor writes are rejected by the ordering guard until the clock passes the stored `attempted_at`; the snapshot then reports stale. | `State._save_runtime_snapshot` / `record_runtime_failure` guard |
| E5 | Info | **Equal timestamps overwrite** (strict `>` comparison) and an unparsable incoming `attempted_at` bypasses the guard. Both writers supply microsecond timestamps from `datetime.now`, so ties are improbable. | Same guard |

Not defects (verified): concurrent `start_health_monitor` calls from eight barrier-synchronised threads produce exactly one monitor; `health()` returns the cached value immediately while the probe is blocked; monitor-versus-monitor out-of-order publication cannot occur because ticks are sequential in one thread and a second monitor cannot be admitted while the first is alive.

## Required focused test plan (synthetic and fail-closed)

Existing coverage: `tests/test_runtime_health.py` (`RuntimeCollectorTests`, `RuntimePersistenceTests`, `RuntimeAgentBoundaryTests`) covers bounded collection, safe fields, categories, retained last-success payload, cached RPC, sequential double start and safe logs; `tests/test_post_mutation_reconciliation.py::test_late_runtime_success_and_failure_cannot_overwrite_post_mutation_identity` covers the ordering guard at the **State** level only; `tests/test_web_runtime.py` covers authenticated `/api/runtime` and never/current/stale/unavailable presentation.

Add to `tests/test_runtime_health.py` (new class, for example `RuntimeMonitorLifecycleTests`), driving the **real** `ReadOnlyService` with a temporary `State`:

1. **Parallel start admission:** N (≥ 8) barrier-released `start_health_monitor` calls → exactly one live `upt-runtime-health` thread; exactly one initial health probe and one refresh before the first wait.
2. **Cached health under a blocked probe:** with `_docker_health` blocked on an event, `health()` returns `{"ok": None, "status": "not checked"}` promptly; mutating the returned `docker` dict does not change the next `health()` result; after release the cache shows the probe result.
3. **Success → classified failure → recovery through `_refresh_runtime_snapshot`:** with `webservice.collect_runtime_containers` patched, assert category, `attempted_at <= captured_at`, retained last payload during failure, and status/freshness via `State.runtime_snapshot(now=...)`.
4. **Persistence failures:** keep the existing redaction test; add assertions that a failed `save_runtime_snapshot` leaves the previous row byte-identical and that a failed `record_runtime_failure` does not change `attempt_success`.
5. **Monitor versus `reconcile_runtime` ordering at the facade path:** block the patched collector after the monitor has captured `attempted_at`; run `State.reconcile_runtime(...)` with a later `attempted_at`; release the collector (success, then a second case with failure) → the reconcile snapshot and the verification invalidation both survive. Ordering is forced by events, not sleeps or a fake clock.
6. **Stop with a blocked probe:** stop returns within the 6 s bound while the thread is still alive; the test then releases the probe and joins the thread before removing guards or the temp directory; no second monitor is ever alive. Record E1/E2 in test comments; do **not** assert the no-op restart as desired behaviour (owner decision D2).
7. **Server wiring:** `AgentServer.serve_forever` starts the monitor once after the schema check and calls `stop_health_monitor` in `finally` (extend existing coverage only if not already asserted).

Fail-closed rules: hold guards for `subprocess.run`, `subprocess.Popen`, `docker_update_manager.system.run` and `urllib.request.urlopen` **until every spawned thread has joined**; register cleanup so the gate is released and the thread joined before temp-directory removal; no real Docker, production sockets or live network. Use events/barriers; sleeps may not be the only synchronisation. Comply with `tests/_upt_isolation.py` / `scripts/run_tests.py` worker teardown.

## Exact change list (Option A)

| File | Change |
| --- | --- |
| `tests/test_runtime_health.py` | Add the lifecycle/ordering tests above; existing tests unchanged |
| `docs/implementation/phase3-runtime-health-snapshot.md` | Record outcome, test evidence and closeout |
| `docs/implementation/architectural-refactor-index.md` | Mark Stage 3 outcome |

No change to any file under `src/`.

## Acceptance criteria (measurable)

1. `git diff --stat <base>...<head> -- src/` is empty (Option A). Under an approved Option B, only `webservice.py` and one new module change, and every seam in the compatibility table still works without editing existing tests.
2. All seven test groups above exist, pass locally under `scripts/run_tests.py` isolation, and each new test completes in under 10 s (only test 6 may consume the existing 6 s join bound).
3. Existing `tests/test_runtime_health.py`, `tests/test_web_runtime.py`, `tests/test_post_mutation_reconciliation.py`, `tests/test_version_contract.py`, `tests/test_web_ux_hardening.py` and `tests/test_schema_compatibility_boundary.py` pass unmodified.
4. Isolation ledger reports no leaked `upt-runtime-health` thread and no un-guarded process/network call.
5. Full Python 3.10/3.13 and Chromium exact-head CI and `merge-gate` succeed on the implementation PR.
6. Independent code/disclosure review of the implementation PR finds no Blocker/High issue.
7. Owner records acceptance of the Phase 3 outcome in issue #3.

## Excluded scope

Fixing E1–E5; moving `_docker_health`, `health`, `start_health_monitor` or `stop_health_monitor`; changing `runtime.py` collection; any `State` schema, migration, transaction or ordering-guard change; changing `reconciliation.py`; new Docker commands, registry scans, Compose/update/rollback flow, auth/session changes, firewall/systemd/repository settings, production diagnostics or broad formatting. These are distinct reviewed tasks if ever required.

## Owner decisions

Recorded 2026-10-10 after independent review of commit `e7aa0f97127265a9646d2a5b74cc503b1df191f2`.

- **D1 — Approved: Option A.** No production-code extraction; no new runtime monitor module or class; all existing public and internal runtime contracts preserved. Implement the seven test groups above in `tests/test_runtime_health.py`. Extraction is recorded as **not warranted** (a completed outcome, not deferred work). Option B and Option C are not authorised.
- **D2 — E1 tracked separately** in [issue #5](https://github.com/rdna897/upt/issues/5), not fixed in Phase 3. A later lifecycle correction must design E1 and E2 together.
- **D3 — E2–E4 accepted as documented limitations for Phase 3** and tracked separately: E2–E3 with E1 in [issue #5](https://github.com/rdna897/upt/issues/5); E4 with E5 in [issue #6](https://github.com/rdna897/upt/issues/6). E5 is retained as technical debt and is an input to the Phase 6 SQLite boundary review.

Phase 3 tests may reproduce and document E1–E5 but must not assert them as desired long-term behaviour.

## Implementation evidence (tests-only PR)

Recorded for owner review; Phase 3 is **not** closed until the owner accepts the implementation PR.

- **Production code:** unchanged (`git diff --stat main...HEAD -- src/` is empty). Only `tests/test_runtime_health.py` and this closeout/roadmap documentation change.
- **New class:** `RuntimeMonitorLifecycleTests`, nine tests covering the seven required groups:

| Group | Test(s) | Contract proven |
| --- | --- | --- |
| 1 Parallel admission | `test_parallel_starts_admit_exactly_one_monitor_with_one_initial_tick` | 8 barrier-released starts admit one daemon `upt-runtime-health` thread; exactly one initial probe and refresh; idle stop is prompt |
| 2 Cached health | `test_health_rpc_serves_cached_copy_while_docker_probe_is_blocked`, `test_docker_probe_failure_projection_is_safe` | `handle("health")` returns promptly from cache while the real `_docker_health` is blocked at the exact `docker version` argv/10 s timeout boundary; returned dicts are copies; failure projection hides error text |
| 3 Success → failure → recovery | `test_runtime_success_classified_failure_and_recovery_through_facade` | Classified and unexpected failures (`docker_unavailable`, `probe_failed`) retain the last payload and capture time; `attempted_at <= captured_at`; current/stale/unavailable status; no secret in logs or payload |
| 4 Persistence failures | `test_persistence_failures_leave_previous_row_untouched` | Failed save or failure-record leaves the SQLite row byte-identical, never records a false failure, logs only safe class names |
| 5 Monitor vs `reconcile_runtime` | `test_late_monitor_success_cannot_overwrite_newer_reconciliation`, `test_late_monitor_failure_cannot_overwrite_newer_reconciliation` | A real monitor tick blocked after capturing `attempted_at` publishes after a newer reconciliation; reconciliation snapshot and verification invalidation survive |
| 6 Stop during blocked probe | `test_stop_during_blocked_probe_is_bounded_and_never_duplicates_monitor` | Stop honours the 6 s join bound; a restart never yields two live monitors; the stopped thread exits after release and publishes at most once. E1/E2 are reproduced and commented, not asserted as desired behaviour |
| 7 Agent server wiring | `test_agent_server_checks_schema_before_socket_and_owns_monitor_lifecycle` | Order is schema check (before socket) → monitor start (socket bound) → accept → monitor stop in `finally`; socket removed and monitor joined |

- **Isolation:** each test patches `docker_update_manager.system.run`, `subprocess.run`, `subprocess.Popen` and `urllib.request.urlopen` to fail closed; cleanup releases gates and joins every monitor thread before the guards and temporary directory are removed, and asserts no guard was hit. Runs under `scripts/run_tests.py` isolation with no ledger violations.
- **Mutation check (local, reverted):** each of eight deliberate production mutations failed at least one new test: un-copied health cache; removed admission alive-check; removed ordering guard; monitor started before schema check; save failure recorded as probe failure; raw exception text logged; shortened join bound; runtime refresh skipped.
- **Local validation (Python 3.13):** the new class passed 10 consecutive runs (about 6 s each, dominated by the existing 6 s join in group 6). Related suites passed unmodified: `test_runtime_health`, `test_web_runtime`, `test_post_mutation_reconciliation`, `test_version_contract`, `test_web_ux_hardening`, `test_schema_compatibility_boundary`, `test_web_rollback`, `test_web_foundation`, `test_targeted_verification_worker`, `test_web_remediation` (205 tests, 3 environment skips).
- **Limitations:** E1–E5 remain as tracked in #5 and #6. Group 6 necessarily spends the existing 6 s join bound once.
- **Exact-head CI and independent review:** recorded on the implementation PR.

## Deliverables, gates and freeze

**This PR:** documents the Phase 3 review, decision and acceptance criteria only. It makes no runtime/code/test changes.

**Implementation (approved, D1):** one separate narrowly scoped tests-only PR against the then-current public `main`, meeting the acceptance criteria above, with separate owner merge approval. Do not merge automatically. Phase 3 is not complete until the owner accepts that PR's outcome.

**Freeze:** never install, rebuild, restart or redeploy UPT; never change production Compose, Docker, SQLite, secrets, caches or snapshots. Completion or merge of Phase 3 is not permission for a release or production deployment.
