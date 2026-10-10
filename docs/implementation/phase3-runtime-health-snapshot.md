# Architectural refactoring — Phase 3: runtime health and snapshot coordination

**Status:** Draft for independent architecture review; implementation is **not** authorised by this document.
**Canonical repository:** `rdna897/upt` (public).
**Baseline:** `main` at `cc16dc74b998ea869490d3b291b8ddbf886c3859` (revalidate before review and implementation).
**Tracking:** [Architecture Phase 3 — issue #3](https://github.com/rdna897/upt/issues/3).
**Risk:** Medium for a bounded extraction; high if monitor lifecycle, failure handling or SQLite publication semantics change.
**Deployment:** Production deployment freeze remains mandatory through programme closeout and separate operator approval.

## Objective and prior work

Reduce coupling inside `ReadOnlyService` while retaining the current read-only runtime observation, health-cache and state-publication behaviour. Phase 1 already isolated full scanning in `scan_worker.py`; Phase 2 isolated single-container targeted verification behind `_verify_exact_container_once` with real-worker regressions (public PR #2). Neither is in scope here.

This phase must establish whether further extraction is justified **at all**. `runtime.py` already owns bounded Docker inventory collection and sanitisation; moving those routines again or inventing another worker framework is not the goal. A targeted test-only improvement or an evidence-based **not warranted** outcome is permissible with the owner's explicit acceptance.

## Current public source and ownership map (baseline)

| Component | Present responsibility | Constraint |
| --- | --- | --- |
| `webservice.py`: `ReadOnlyService.__init__` | `_health_lock`, `_health_stop`, `_health_thread`, initial `_docker_health_cache` | No new shared unprotected mutable state |
| `ReadOnlyService.health()` | Copies cached Docker-health result under lock, returns agent version and liveness | Must stay cheap, cached, bounded and non-blocking; unauthenticated health traffic must not trigger Docker |
| `start_health_monitor()` | Starts at most one live daemon thread; immediate first iteration; probes health, updates cache, refreshes runtime, waits between iterations | Retain startup, scheduling and thread-ownership semantics; test real start/stop |
| `_docker_health()` | Executes bounded `docker version --format {{.Server.Version}}` using `system.run`, timeout 10 seconds; maps failure to safe `Docker daemon unavailable` | No raw exception text, shell expansion or new command privileges |
| `_refresh_runtime_snapshot()` | Records attempt timestamp; performs one bounded runtime collection; records classified failure or saves successful snapshot with capture timestamp; safe structured warnings | Keep failure classification, persistence and redaction exactly as published |
| `stop_health_monitor()` | Sets shared stop event; joins a different live monitor thread for at most 6 seconds | Do not silently change shutdown, overlapping start/stop or blocked-probe behaviour |
| `runtime.py` | Already implements sanitised Docker list/inspect, bounded inventory, error categories and at most one inventory-churn retry | Keep collection and privacy filtering here; no duplicate collector |
| `state.py` | `save_runtime_snapshot`, `record_runtime_failure`, `runtime_snapshot`, and `reconcile_runtime` transactionally publish/read the singleton record | State retains SQLite transaction authority, monotonic `attempted_at` guard and previous successful payload |
| `ReadOnlyService.handle()` and `AgentServer.serve_forever()` | Bounded `health` and `runtime_snapshot` RPCs; monitor starts before accepting socket requests and stops in `finally` | No wire-format, permission, RPC or service lifecycle changes |
| `webapp.py`, `webviews.py` | Authenticated runtime read/display and reconciliation of runtime-only and scanned services | Current/stale/unavailable and excluded-container semantics unchanged |

### Call and ownership flow

```text
AgentServer.serve_forever()
  -> ReadOnlyService.start_health_monitor()
      -> [single daemon thread, immediate first tick]
         -> _docker_health() -> system.run(docker version) -> _docker_health_cache (under lock)
         -> _refresh_runtime_snapshot()
              -> collect_runtime_containers(config) [runtime.py]
              -> State.save_runtime_snapshot(containers, captured_at, attempted_at)
                or State.record_runtime_failure(attempted_at, safe_category)
         -> stop_event.wait(max(5, interval_seconds))
  -> ReadOnlyService.handle("health") -> health() -> cached health only
  -> ReadOnlyService.handle("runtime_snapshot") -> State.runtime_snapshot() -> persisted bounded read
  -> ReadOnlyService.stop_health_monitor() [agent server finally]
```

The separate post-mutation `State.reconcile_runtime()` also writes the runtime snapshot **within a transaction that invalidates verification evidence**. Any Phase 3 design must preserve coexistence with this writer and the stale-attempt guard. It must not move persistence into a second transaction layer.

## Required behavioural invariants

1. **RPC and privilege:** exact existing `health` payload keys (`ok`, `service`, `version`, `docker`), `runtime_snapshot` response/status/freshness fields, bounded agent operation allowlist and UNIX-socket permissions are unchanged. No new network server, API route, agent token exposure or HTTP-triggered live Docker work.
2. **Scheduling:** one live agent-owned monitor; first health probe and snapshot refresh occur promptly on start; unchanged thread daemon/name semantics, interval lower bound of 5 seconds, default `RUNTIME_INTERVAL_SECONDS`, stop-event behaviour and bounded 6-second join. Do not add a scheduler, extra interval task, duplicate daemon or restart side-effect.
3. **Health result:** retain original unchecked cache shape `{"ok": None, "status": "not checked"}`, lock-protected copy/publication, bounded 10-second Docker version command and safe failure projection. Docker health and runtime snapshot are separate channels; a runtime collection failure must not silently overwrite the health cache, and vice versa.
4. **Runtime probe:** `collect_runtime_containers(self.config)` keeps its existing allowlisted container fields, bounded inventory size, single list/inspect retry policy, exclusion behaviour and fault classifications: `docker_unavailable`, `container_limit_exceeded`, `invalid_docker_response`, `inventory_changed`, `probe_failed`.
5. **Failure semantics:** classify `RuntimeProbeError` using its `stage`, `category`, `failure_class`, and optional `exit_code`; unexpected exceptions become `probe_failed` with safe class/exit code only. Failure recording errors are separately logged without raw exception content. Persistence failure after successful collection leaves the earlier record intact, rather than recording a fabricated probe failure.
6. **SQLite and time ordering:** `attempted_at` is captured before collection and `captured_at` after collection; `State` validates/sanitises persisted fields, monotonically guards against older attempts and atomically replaces success or retains last successful payload on failure. `reconcile_runtime` must continue to invalidate verification and save its runtime snapshot in a single transaction. Retain existing singleton schema and computed freshness (default 90 seconds).
7. **UI and safety:** no change to `never`, `current`, `stale`, `unavailable`, `available`, `stale`, or `failure_category` interpretations, nor to the fact that **missing Docker health checks are not healthy**. Never publish environment values, Docker inspect secrets, credential-bearing errors, mounts or unchecked full Docker metadata.
8. **Compatibility:** preserve existing test patch paths (especially `docker_update_manager.webservice.collect_runtime_containers`, `_docker_health`, `_refresh_runtime_snapshot` and State fakes) where possible. If a proposal alters these seams, enumerate every affected test and prove equivalent real-facade coverage before accepting that change.

### Concurrency and lifecycle questions to resolve in architecture review

- Current thread creation/start occurs while `_health_lock` is held. Does the proposed boundary preserve atomic single-thread admission, avoiding duplicate monitor instances during concurrent starts?
- Current `stop_health_monitor` sets the event and joins for at most 6 seconds. A blocked probe can outlive that join; record present semantics and assess whether extraction creates overlapping workers on a later start. **Do not silently fix a distinct lifecycle bug inside a structural refactor.**
- Can `health()` read promptly while the monitor is blocked in Docker? Is the health cache lock held only for short assignments/copies?
- What happens when `_refresh_runtime_snapshot` or the health probe unexpectedly raises? Preserve existing exception containment and thread-stop semantics, or propose an explicitly separate correctness change.
- Could `reconcile_runtime()` and the periodic monitor publish in either order? The monotonic timestamp rule must prevent older observation from overwriting newer authoritative evidence. Specify a race regression at the real State/facade boundary.
- Does the proposal keep the current `webservice` module monkeypatch seams without function-level dependency injection proliferation or import-cycle risk?

## Candidate decisions (independent reviewer must choose and justify)

**Option A — no code extraction:** retain the small monitor in `ReadOnlyService`; strengthen missing lifecycle/race tests only. Prefer if introducing a new boundary adds more indirection than it removes.

**Option B — narrow, module-local worker boundary (provisional preference if worthwhile):** move the *single probe-and-publish attempt* into a small internal runtime-coordination helper (for example, `runtime_monitor.py`) while keeping monitor thread ownership, cached `health()`, scheduling, RPC dispatch and `State` publication authority in the existing facade. Avoid callback-heavy abstractions. Identify a testable signature, exact exception boundary, dependency imports and patch-seam strategy. Do **not** blindly move `_docker_health` or the entire thread loop if doing so increases risks.

**Option C — bounded monitor object:** consider only with concrete evidence that lifecycle ownership and tests measurably improve compared with A/B. It must not create a second scheduler, broaden privileges or require injected callbacks for every existing facade function.

The reviewer must compare A/B/C using moved code versus new glue, test patchability, failure containment, thread ownership, module dependency shape and compatibility. **No option is pre-approved as implementation.**

## Required focused test plan (synthetic and fail-closed)

Assess and close gaps in these existing suites before changing code:

- `tests/test_runtime_health.py`: `RuntimeCollectorTests`, `RuntimePersistenceTests`, `RuntimeAgentBoundaryTests`. Existing tests cover bounded collection, safe fields, categories, retained last-success payload, cached RPC and single-monitor start.
- `tests/test_web_runtime.py`: authenticated `/api/runtime`, never/current/stale/unavailable presentation, replacement and exclusion handling.
- `tests/test_web_browser.py` and `tests/test_web_foundation.py`: browser and existing general HTTP/RPC regressions.
- `tests/_upt_isolation.py` and `scripts/run_tests.py`: mandatory per-test process/Docker/network isolation and worker teardown contract.

Add deterministic facade-path tests as justified for:

1. Parallel `start_health_monitor` calls: only one worker, immediate first attempt, no extra initial ticks, bounded and safely joined cleanup.
2. Cached health under a **blocked** Docker probe: read remains prompt and does not invoke Docker; cached dict is not mutated by caller.
3. Success to classified runtime failure to recovery: exact categories, attempt/capture ordering, previous payload retained, freshness/status semantics unchanged.
4. Failure in `record_runtime_failure` and failure in `save_runtime_snapshot`: exact safe log projection, no secrets in logger or persisted payload, no false success/failure transition.
5. Monitor-vs-`reconcile_runtime` out-of-order attempts: protect last newer result and verification invalidation as one State transaction.
6. Stop with a blocked worker and potential immediate restart: document current limitations explicitly and prove no new duplicate monitor or leaked test worker. Any independent correctness fix requires separate review.
7. Server/facade routing: both read RPCs and monitor start/stop wiring remain unchanged.

For asynchronous tests, hold fail-closed guards for `subprocess.run`, `subprocess.Popen`, Docker runner and `urllib.request.urlopen` **until every spawned thread has joined**; do not use a fixture with real Docker, production sockets or live network calls. Tests may use events/barriers and an injected synthetic clock, not timing-sensitive sleeps as the only proof.

## Deliverables, gates and exclusions

**This PR:** documents the Phase 3 options and acceptance criteria only. It makes no runtime/code/test changes.

**Independent architecture review:** provide a concise call graph, proposed exact change list, A/B/C decision with quantified coupling benefit, failure/race analysis, current coverage gaps, affected patch paths, and blocking findings. Revise this Draft with decisions and evidence; explicitly obtain owner acceptance of a Ready scope before implementation.

**After approval only:** one separate narrowly scoped implementation PR against the then-current public `main`. Require isolated targeted tests, full Python 3.10/3.13 and Chromium exact-head CI, `merge-gate` success, independent code/disclosure review, and separate owner merge approval. Do not merge automatically.

**Never included:** altered `State` schema, migrations, new Docker commands, registry scans, Compose/update/rollback flow, auth/session changes, firewall/systemd/repository settings, production diagnostics or broad formatting. These are distinct reviewed tasks if ever required.

**Freeze:** never install, rebuild, restart or redeploy UPT; never change production Compose, Docker, SQLite, secrets, caches or snapshots. Completion/merge of Phase 3 is not permission for a release or production deployment.
