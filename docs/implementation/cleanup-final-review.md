# PR #19 — final cleanup corrections

**Status:** Implemented; exact-head CI and author approval required before merge.
**Reviewed base:** `7e2b10177d4d3cff77a04b3ed95ec6fe946ec416`.

## Objective and requirements

Automatic retention from `upt cleanup` must refuse an invalid or replaced pinned
database at every destructive boundary: reference migration and expiry, each
recovery artefact deletion, each Docker image removal, outcome metadata writes,
final pruning and compaction. Database checks must use the write transaction
being authorised, with another check before commit. Never retain a SQLite
transaction across Docker or filesystem operations. Keep `update.lock` unchanged.

The before/after disk snapshots written by `upt cleanup` use the same pinned
transaction gate; collection stays outside the transaction and other commands
keep ordinary snapshot persistence.

Existing-only State must refuse unversioned legacy databases repeatedly without
initialising schema metadata. Ordinary legacy migrations remain supported.

## Scope and safety boundaries

Keep the correction explicit and limited to cleanup, its pinned-state helper,
existing-only schema validation and relevant regressions. Preserve standalone
R10 expiry and forced retention, canonical identities, rollback protection,
SQLite ownership and namespace/bootstrap behaviour. No schema version change,
G2-S0b/S0c, production access, live Docker mutation, deployment, service restart,
PR #15 change or merge. PR #19 remains open for explicit author approval.

## Definition of done

- Deterministic temporary-database/mocked-Docker regressions cover inventory and
  accounting replacement, individual artefact boundaries, migration/expiry,
  image removal, pruning/compaction and verification-to-transaction replacement.
- Repeated existing-only legacy refusals leave the database unchanged; ordinary
  migration and standalone age/forced retention still pass.
- Demonstrate regressions against the reviewed base, then run focused cleanup,
  R10 retention, SQLite compatibility, rollback protection and the full guarded
  regression suite. Review the complete diff and run `git diff --check`.
- Push only the existing PR #19 branch and verify exact-head full GitHub Actions
  CI using one blocking run watch. Report the exact head, results and limitations.

## Validation evidence

- The 16 defect regressions fail against the reviewed base; all 56 cleanup
  protection tests pass with the corrections. Ordinary legacy migration and
  standalone age/forced retention pass on both versions.
- Focused R10 retention, SQLite compatibility/completion and rollback suites
  pass. Cleanup and CI-selection suites pass together (118 tests).
- The full guarded Python 3.13 regression suite passes: 1,360 tests, three
  conditional skips. `git diff --check` passes.
- Snapshot correction: six snapshot defect regressions fail against
  `1df1398788192192deb2dc47ee442168ad974c7a` and pass with the correction; the
  successful-cleanup and other-command snapshot tests pass on both. All 64
  cleanup protection tests and 335 focused cleanup, retention, SQLite,
  rollback, core and CI-selection tests pass. The full guarded suite passes:
  1,368 tests, three conditional skips.
- The synthetic Compose bundle fixture adds a direct dependency on the recovery
  implementation. Its CI test-group entry is extended so changes to that
  dependency also select cleanup protection; workflow gates remain unchanged.

## Remaining limitations

Filesystem and Docker effects cannot be atomic with SQLite verification without
retaining transactions across those effects. A non-cooperating external writer
can still race the final check; a detected invalidation aborts the remaining
work, and completed effects are not undone. VACUUM owns its internal transaction;
the pinned check uses its actual autocommit connection immediately before and
after compaction. Other database writes check their actual reserved transaction
before executing and again before State commits it.

## Handoff notes

None.
