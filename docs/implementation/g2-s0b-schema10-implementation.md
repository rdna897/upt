# G2-S0b — Schema-10 recovery fences: storage, offline migration and inert enforcement

**Status:** implementation PR open for final author review. Not merged and not deployed. **No G2 fence writer is active.**
**Design:** [S0 schema-10 design](g2-s0-recovery-fence-design.md) (Option B; D3, D3b, D3c, D8, D9, D10) and [G2 policy](g2-mutation-completion-policy.md).
**Freeze:** the production deployment freeze is unchanged. Nothing here authorises a production migration.

## 1. Storage (schema 10)

Source of truth: `completion_fence.COMPLETION_SCHEMA`. The exact `sqlite_master` rows for these objects form the schema-10 compatibility identity; any edit is a schema change.

```sql
CREATE TABLE completion_fences(
  operation_id TEXT NOT NULL PRIMARY KEY CHECK(32 lowercase hex),
  logical_key TEXT NOT NULL CHECK(64 lowercase hex),
  stack TEXT NOT NULL CHECK(1..255 chars), compose_service TEXT NOT NULL CHECK(1..255 chars),
  action TEXT NOT NULL CHECK(action IN ('update','pinned_update','rollback','web_rollback')),
  lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','manual','resolved')),
  evidence TEXT NOT NULL CHECK(2..65536 chars),
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX idx_completion_fences_unresolved ON completion_fences(logical_key) WHERE lifecycle IN ('active','manual');
CREATE INDEX idx_completion_fences_service ON completion_fences(stack,compose_service) WHERE lifecycle IN ('active','manual');
CREATE TABLE completion_fence_claims(
  operation_id TEXT NOT NULL REFERENCES completion_fences(operation_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  kind TEXT NOT NULL CHECK(kind IN ('image','backup')),
  value TEXT NOT NULL CHECK(image: sha256:<64 hex>; backup: <managed root>/<entry>, no '..', one '/'),
  PRIMARY KEY(operation_id,kind,value)) WITHOUT ROWID;
CREATE INDEX idx_completion_fence_claims_value ON completion_fence_claims(kind,value);
```

Triggers (defence in depth): fence identity columns are immutable; `resolved` is final; unresolved fences cannot be deleted; claims are immutable, may only be added to an unresolved owner and cannot be deleted while their owner is unresolved. Foreign keys are enforced on every UPT connection.

- One unresolved fence per logical service; many owners may claim the same image/backup through separate owner-scoped rows. Resolving one owner never removes another owner's claim.
- **Evidence v1** is exactly `{"version": 1, "working_dir": <normalised absolute path>, "compose_files": [1..32 normalised absolute paths]}` (≤ 64 KiB). The stored `logical_key` must be reproducible from (stack, Compose service, working_dir, compose_files). It never contains Compose contents, environment values or credentials. Enrichment (target observation, source digests) needs a later versioned format (S0c).
- `compose_bootstrap_fences`, `operation_runs`, `protected_images` (including `NULL history_id` rows) and the immutable `core_schema_identity` row are unchanged. The core identity contract is extended: schema 10 additionally requires the exact G2 schema objects.

## 2. Offline 9→10 transition

`python -m docker_update_manager.state_transition upgrade-schema10 --state-dir DIR --confirm-quiescent`

1. Requires explicit acknowledgement that every UPT admission path and process is stopped.
2. Acquires `update.lock` and `scan-worker.lock` (no-follow).
3. Verifies a regular non-symlink database, `PRAGMA integrity_check`, exactly one integer version row equal to 9, the schema-9 identity, no pre-existing G2 objects, no `queued/running/finalizing` operation and an empty `foreign_key_check`.
4. Creates `schema-transitions/schema9-before10.sqlite3` (0600, directory 0700, fsync) with its SHA-256 file, then validates digest, version and an order-independent logical digest of every object and row against the live database.
5. In one `BEGIN IMMEDIATE` transaction: re-proves the unchanged state, creates the G2 objects, sets version 10, then proves the exact G2 schema, unchanged pre-existing objects/rows, empty `foreign_key_check` and `integrity_check` before `COMMIT`.
6. Re-opens with a normal schema-10 `State`.

**Failure recovery.** Any failure or interruption before `COMMIT` rolls back to schema 9 and retains the snapshot. A retry never overwrites a retained snapshot: it resumes only when the snapshot's digest file, version and logical digest exactly match current state; otherwise it refuses and asks the operator to preserve and review it (for example an unvalidated partial snapshot, or state changed since). A repeat invocation on validated schema 10 reports `current` and changes nothing. Normal startup, `State.connect()`, the CLI and the web/agent never migrate.

The existing `upgrade` (8→9) and `restore-schema8-backup` actions are unchanged; on schema-10 state the latter refuses (see §4). An 8→9 transition is now followed by `upgrade-schema10`.

## 3. Compatibility

| Database \ binary | Schema-9 binary | Schema-10 binary |
| --- | --- | --- |
| New (no tables) | creates 9 | creates 10 directly (`created_schema`) |
| Schema 9 | normal | **refused** on every open (incl. `require_existing`, cleanup) until `upgrade-schema10`; bytes unchanged |
| Schema 10 | **refused** (`unsupported core state database schema version 10`) by `_migrate` and the cleanup schema check, before any write | normal; exact G2 schema re-validated, including in long-lived processes |
| Schema 8 / legacy / unversioned / invalid version / future | unchanged behaviour | **refused before any write, including the WAL journal-mode change**; legacy steps remain reachable only through an explicit transition instance |
| Web-owned state (`WebState`) | unchanged | unchanged (no G2 tables, version 4) |

## 4. Downgrade contract

No state-preserving 10→9 transition exists. `downgrade-schema9` performs a read-only diagnosis (count of unresolved G2 fences) and always refuses; `restore-schema8-backup` refuses schema-10 state. The retained schema-9 snapshot is never restored over post-upgrade History, rollback points or claims. A binary revert alone is unsupported: the schema-9 binary refuses schema 10.

## 5. Service admission map

Predicate: `State.assert_completion_unfenced(service)` (also called at the end of `assert_service_unfenced`, after the unchanged namespace/bootstrap checks so their precedence is preserved). A fence covers the exact logical key and, against identity drift, any service with the same (stack, Compose service), or the same Compose service in the same project directory or sharing a Compose source. Image sharing never blocks. A Compose service with incomplete identity is refused while any fence exists; a standalone container has no Compose identity a fence can own. Malformed or unreadable evidence refuses every admission. There is no owner exemption.

| Front door | Gate |
| --- | --- |
| Ordinary/pinned update, namespace consumer update, pull, pin, CLI rollback | existing `assert_service_unfenced` calls |
| Web update/rollback review, start, workers, in-flight `_verify_compose_runtime_identity`, baseline capture/trust | existing `assert_service_unfenced` calls |
| `do_web_rollback` (core) | added after `require_mutation_safe` |
| Restart (CLI pre-check for the whole selection, `do_restart` with state) | added |
| `remove` (before planning and immediately before container removal) | added |
| Conversion generate/deploy (service and target `compose.yml` source), conversion rollback (both containers) | added |
| `restore-compose` (incl. dry run) | `assert_sources_unfenced` on every restored source and the recorded (stack, service) |
| Compose bootstrap `make_plan` / `do_compose_bootstrap` | added (`completion_unresolved` reason) |
| Compose Apply/reconcile, namespace Apply (`do_compose_reconcile`), discard (`do_compose_discard`) | added before any bundle/source/runtime effect |
| Web Compose plans (`_compose_plan`) | `UNVERIFIABLE` with `completion_unresolved` |

Dry-run update/pull previews remain read-only and do not consult fences, as for bootstrap fences.

### 5a. Compose source-write boundaries

Service admission protects the selected logical service. Independently, every path that rewrites a Compose source calls `State.assert_sources_unfenced(paths)` with the exact files it will write. A fence owns its Compose files and its project `.env`, compared lexically and through symlinks, so a sibling in the same project cannot rewrite them. Siblings remain operable when they write no fenced source (restart, ordinary update without `--pin`, Compose Apply, which writes no source on success).

| Writer | Before first write | Later boundary | Recovery write |
| --- | --- | --- | --- |
| `do_pin` (incl. `update --pin`) | actual pin target (image file or project `.env`); `update --pin` checks before backup/pull | — | after failed validation: fence recheck, then restore the exact original bytes only if the source still holds exactly the bytes the pin wrote (checked at the atomic replacement); otherwise keep source and backup, record `MANUAL RECOVERY REQUIRED` |
| Pinned update (`_do_pinned_update`) | pin target, before backup | recheck after the pull, immediately before the write | recheck before restoring UPT's own pin; refusal records `MANUAL RECOVERY REQUIRED` |
| CLI rollback (`do_rollback`) | every restored source, before any write | each source before its write | — |
| Web rollback (`do_web_rollback`) | every restored source, before backup | each source before its write | each source in `restore_current_sources`; refusal is manual recovery |
| Compose Apply recovery (`do_compose_reconcile`) | — (success writes no source) | — | changed sources before each `replace_sources` and per file |
| Compose discard (`do_compose_discard`) | pending source, before bundle/dry run | recheck immediately before the write | recheck before restoring pending bytes |
| `restore-compose`, conversion generate/deploy | unchanged (§5) | | |
| `remove --purge-data` (deletion) | eligible config files (`source_refusal`) and bind trees containing any fenced Compose file or project `.env` (`tree_refusal`), marked `SKIP — UNRESOLVED RECOVERY FENCE` in the plan and dry run, re-proved after confirmation before the container is removed | fresh check immediately before each file/tree deletion | — |

Fences are matched from validated evidence, so an absent service (no container) still owns its sources. A fence introduced after planning skips only the affected deletion; unrelated volumes, binds and files keep their existing eligibility. Malformed evidence present at the start refuses the removal before any effect (service admission); malformed or unreadable evidence discovered later keeps every remaining config file and bind tree (`RECOVERY FENCES UNVERIFIABLE`).

No SQLite transaction spans these filesystem or Docker effects: each check is its own short read. A recovery recheck refuses on a proven conflict or malformed evidence; when the database itself is unreadable it keeps the pre-existing S0a compensation (the sources were proved unfenced before the first write and only the operation's own verified bytes are restored), preserving the characterised S0a outcome.

## 6. Guarded deletion paths

| Path | Eligibility | Final boundary |
| --- | --- | --- |
| Automatic and explicit `upt retention cleanup` images (incl. `--override-protection`, `--all`) | `_removal_blocker` (claims read on the same short read) | fresh `_image_claim_blocker` after the caller revalidation, immediately before `docker image rm` |
| `upt cleanup` (dangling) | `CleanupState.protection()` includes claims (`UNRESOLVED RECOVERY CLAIM`); malformed claims refuse the run | re-read before each removal |
| `remove --images` | dry-run status | fresh claim read immediately before each `docker image rm` |
| Backups (`backups`, `conversion-file-backups`, `conversion-snapshots`, `restore-bundles`) under TTL and forced retention | inventory marks claimed artefacts `protection: claimed` (or `unverifiable`) and not expired | claim name **and** filesystem identity (lstat/stat of every claimed path, defeating symlinked-root aliases) plus an unchanged-inode check against substitution, rechecked outside SQLite immediately before deletion |

Claim owners are trusted only after the same full validation as admission (`unresolved_fences`: owner, lifecycle, action, logical key, stack/Compose service, evidence format/version and logical-key reproducibility), read in the same transaction as the claims; claim kind/value and owner relationship are then checked. Any invalid unresolved fence refuses the whole claim set. An unreadable or malformed claim set keeps the affected images/backups (`RECOVERY CLAIMS UNVERIFIABLE`); it is never an empty protection set. No SQLite transaction spans Docker or filesystem effects. `compose-recoveries`, R10 and PR #19 semantics are unchanged; unclaimed resources keep existing expiry. Metadata pruning never touches G2 rows (unresolved rows are also trigger-protected).

## 7. Inert boundary and deferred work

No production module inserts, updates or deletes G2 rows (enforced by a source-scan test). Not implemented: fence writers, evidence enrichment, atomic History/fence resolution, the shared publisher, compensation changes, automatic release, the operator reconciliation command (D8), web `unresolved` status (D9), and resolved-fence pruning. These belong to S0c/S1–S4 and need separate approval.

## 8. Fail-closed decisions for author review

1. Legacy (<8) and unversioned databases are no longer silently migrated by a normal open; this changes the earlier `test_ordinary_unversioned_legacy_migration_preserves_protection` expectation to refusal plus an explicit (transition-instance) migration that still preserves protection. No operator action migrates pre-8 state with this binary.
2. Admission identity rule in §5; siblings in the same project that share a Compose file are **not** blocked from service mutation (per-service design), but every write to a fenced service's Compose source is refused (§5a).
3. Any malformed unresolved fence or claim refuses all admissions/deletions (global blast radius by design).
4. Evidence v1 is minimal; `action` admits `web_rollback`; claims may be added to `manual` owners.
5. `State.record` still uses `INSERT OR REPLACE` for `protected_images`; preserving `NULL history_id` rows on publication is S0c work. S0b does not modify any protection row.
6. Core `do_restart` callers without a `State` (tests/internal) skip the G2 check; the CLI always supplies state.
7. Sibling services sharing Compose sources are not blocked from service mutation, but any write to a fenced service's Compose file or project `.env` is refused (§5a). `env_file` and other referenced inputs are not part of evidence v1 and are not source-fenced.
8. A recovery recheck that cannot read the database proceeds with the existing compensation (§5a) rather than abandoning it; forward source writes fail closed on the same condition. For `do_pin` the compensation additionally requires the exact written bytes at the replacement boundary.
9. `remove --purge-data` skips, rather than aborts on, fenced deletions, consistent with its other safety skips; the container and unrelated resources are still removed.

## 9. Remaining risks

- Quiescence is an operator acknowledgement; locks cannot prove an old binary is stopped.
- Resolved G2 rows and their claims accumulate until a reviewed G2-scoped pruning policy exists; claim reads scan unresolved owners' claims.
- Snapshot SQLite sidecar files may appear next to the private snapshot inside the 0700 transition directory.
