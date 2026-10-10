# S6-R10 — SQLite writer contention during retention inventory

**Tracking:** [issue #11](https://github.com/rdna897/upt/issues/11) (G5, Stage 6a).
**Base:** public `main` at `c0e8365a376897800f7bf350c3129efac6945766`.
**Scope:** `src/docker_update_manager/retention.py` and regression tests.
**Production deployment freeze:** remains in force. This change is not deployment or merge approval.

## Existing failure

`upt retention` calls `inventory(image_details=True)` without holding
`update.lock`. `rollback_points` entered `state.connect()`, which takes
`BEGIN IMMEDIATE`, and then invoked Docker `system df` (120-second timeout)
while retaining SQLite's single writer slot. A competing history writer could
time out after its 30-second SQLite busy timeout, creating the S6-R1/R1b
publication-failure trigger. `_migrate_refs` also performed an unconditional
write-transaction attempt from read-only inventory.

## Accepted local correction

1. `rollback_points` uses `state.read()` for exactly one rollback-point
   SELECT, fetches the complete row snapshot, and closes the read transaction
   before starting Docker accounting or computing/enriching its report.
2. The SELECT projects persisted `rollback_refs` plus legacy migration
   candidates via `UNION ALL`. One module-level SQL selection is shared by
   projection and `_migrate_refs` (`INSERT OR IGNORE ... SELECT`): a candidate
   has a non-NULL `history_id`, no existing ref with that ID, and is the only
   protected row with that ID. Columns, ordering, history joins and defaults
   (`expired=0`/`purge_status=NULL`) match materialisation without writing.
   Unique orphaned IDs still qualify, with NULL stack/service from the join.
3. The actual, non-dry-run `cleanup` path retains its existing
   `_migrate_refs` call to materialise legacy references before applying
   retention rules. The final protection prune requires a ref matching both
   `history_id` and `image_id`, and no active ref for the image. The per-image
   delete after successful/absent image removal, shared-reference checks and
   terminal-status checks remain unchanged. Dry runs never materialise refs.
4. `State.connect`, `State.read`, schema identity, busy timeout, WAL
   configuration and all other database owners remain unchanged.
   Lazy, one-time `State` schema checking is an existing independent
   initialisation contract; this change does not redesign it.

## Legacy compatibility correction

Previously, NULL-history protections acquired fabricated SQLite row IDs on
repeated migration, making manual-recovery images eligible for expiry and
removal. Shared-history rows projected as multiple points although migration
kept only one; the final prune could silently drop the others' protection.
NULL and ambiguous legacy rows now remain protected, are neither migrated nor
projected as rollback points, and require explicit handling. `--all` does not
invent eligibility for them. Non-migrated rows without their own matching ref
also survive the final prune. Normal expiry (including expired-but-in-use
protection pruning), shared-image protection and purge idempotence are retained.

## Synthetic regression evidence

`tests/test_retention_writer_contention.py` includes:

- A blocked Docker accounting call, controlled by `threading.Event`, while a
  separate `State` instance must commit a history write **before**
  accounting is released. The inventory result remains the earlier snapshot.
  All test threads have bounded waits and `finally` cleanup.
- Real cleanup paused during accounting while a separate main-thread writer
  commits an active ref for the same image as an expired snapshot ref. Cleanup
  rechecks active refs, reports `SKIPPED - SHARED ACTIVE ROLLBACK`, never removes
  the image, and leaves the new ref active.
- A legacy protection reference missing `rollback_refs`, proving that plain
  inventory and retention dry-run expose it without calling `state.connect`
  or inserting a reference.
- Non-dry-run cleanup materialising that legacy ref while preserving the
  projected rollback status, expiry, scope and active protection.
- Normal, duplicate, NULL-history and unique orphaned legacy fixtures checking
  unchanged database bytes/rows during inventory, projection/materialisation
  equality, dry-run/real cleanup selection, repeated cleanup, and protected
  legacy images excluded from removal even with `--all`.
- Matching history/image prune boundaries and normal expired-but-in-use behavior.
- An injected accounting exception followed by a successful separate writer,
  guarding transaction release even on exceptions.

Every fixture uses a temporary database and mocked Docker accounting. No live
Docker or production SQLite database is accessed.

## Non-goals and gate

Not included: G2 completion-policy corrections, Stage 4/5 designs or
implementation, recovery-bundle filesystem/receipt ordering, R12, schema
migrations, web or agent interfaces, and operational changes.

Run the repository's guarded test harness first, then full exact-head CI
(Python 3.10, Python 3.13, Chromium and merge gate). An independent reviewer
must inspect the final exact-head diff for races, stale inventory implications,
legacy-reference semantics, rollback protection and disclosure risk. Record
their findings and re-run CI after any changes. Leave the PR unmerged pending
explicit owner approval. Do not deploy.
