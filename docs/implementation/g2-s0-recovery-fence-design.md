# G2-S0 — Operation-scoped recovery fence (proposed architecture)

**Status:** Proposed ChatGPT architecture for review, not implementation authorisation. Linked from [G2 policy](g2-mutation-completion-policy.md), [G2 #9](https://github.com/rdna897/upt/issues/9) and [G3 #10](https://github.com/rdna897/upt/issues/10). This design deliberately brings forward the **minimum durable-intent foundation needed for safe G2 completion**; full CLI interruption recovery and operator tooling remain G3. Production deployment is frozen.

## Decision and rejected approach

**Use independent operation-scoped guards. Do not upsert pending `protected_images` rows.** That table is keyed by `image_id`, not operation/owner. `INSERT OR REPLACE` destroys existing manual-recovery ownership; an ordinary `State.record` can overwrite it again. A `NULL history_id` row also cannot encode multiple outstanding owners for a shared image. Adding a pending row to that table is not a safe general-purpose journal.

**Preferred schema-9 implementation for review:** reuse the existing durable core `operation_runs` row and its bounded `summary` JSON for both web and the minimum CLI intent required here. Record a versioned `completion_guard` object, with operation ID, exact stack/service identity, old image ID, strict absolute backup-directory identity (where applicable), and lifecycle `pending / unresolved / resolved`. Keep this independent of any `protected_images` record; normal `State.record` continues to publish History, rollback refs and ordinary image protections atomically. A CLI operation uses a new operation row before the mutation boundary. This is a **bounded advance of G3's durable-intent foundation**, not full G3 recovery.

Reuse of `operation_runs` is contingent on proving the existing lifecycle, 4,096-byte summary limit, terminal-event semantics, and older stored rows can support a CLI kind safely. If that cannot be proved without compromising invariants, stop and request owner approval of a narrowly scoped schema change; do **not** silently fall back to `protected_images` replacement. No public G2 implementation starts until this choice is accepted.

## Transaction and guard lifecycle

1. **Capability/identity recorded before mutation.** A web operation is created with `completion_protocol=1` while queued; the CLI creates its own durable operation row under `update.lock`, also with protocol and exact logical identity. This is independent of writing the guard. If that write cannot commit, refuse mutation.
2. **Back up first, guard before the first effect.** Validate and capture the existing backup path, old image ID, immutable operation/completion key and the service identity. In one short SQLite write transaction, commit a `pending` guard on the operation row **before** the first image pull, Docker tag, Compose-source change or recreate. If the transaction is ambiguous, reconcile by operation ID; no effect is authorised until guard presence is positively proven. No database transaction spans Docker, sleep or filesystem work.
3. **Preserve ownership.** A guard never deletes, overwrites or resolves an existing `protected_images` record. Admission refuses a pre-existing unresolved/manual image protection conflict, or any conflicting unresolved completion guard for that service/image. Normal historical rollback refs remain intact. A later `State.record` must not overwrite independent manual protection: revalidate ownership inside its transaction or fail completion publication **while retaining the guard**.
4. **Complete conservatively.** Clear/resolve *only this operation's* guard after verifying its correlated History (or an explicitly approved proven-safe no-change outcome) and web terminal publication where applicable. If release fails, leave the guard in place (overprotection). If History is absent, contradictory, unreadable or outcome unverified, retain `unresolved` protection. An interrupted/unknown mutation is never automatically replayed or rolled back.
5. **Never prune unresolved evidence.** `prune_operations` must retain every `pending/unresolved` guard and its identity irrespective of operation status or age/row-count cap; malformed or unsupported guard JSON must fail closed. A resolved guard may be pruned only when the complete recovery contract permits it.

## All destructive/admission paths must honor the same guard

**One named State query** (e.g. `unresolved_completion_guards`) owns the guard projection. Its read failure is an explicit **refusal**, not "no guards". Changes must cover:

- **Image removal:** CLI `upt cleanup`, retention cleanup, forced/override retention, and every other UPT image-removal caller. Image selection and a last guard check must protect all images claimed by *any* unresolved operation. Preserve the existing R10 rollback-ref, manual and ambiguous-protection checks. `update.lock` must serialize image deletion against new guard publication, or deletion must otherwise provide equivalent atomic exclusion.
- **Recovery file removal:** age-based cleanup of `backups/<stamp>` must skip a guarded backup regardless of age, including forced modes. The projection and immediate pre-delete check must validate the path as an exact direct descendant of the intended managed root, reject symlinks, and refuse deletion if state is unreadable. Preserve existing compose-recoveries lifecycle and never remove arbitrary paths from JSON.
- **Mutation admission:** refuse update, pinned update, rollback, Compose apply, relevant service removal/restart and any path that can mutate the guarded service or dispose of its recovery image/backup. Include CLI and web front doors and any bypass paths. When a path cannot prove non-interference, refuse rather than assume safe. Read-only inventory/monitoring remains available. An `unresolved` terminal web status **does not** release the fence.
- **Concurrency:** normal UPT mutations and cleanup already use `update.lock` in many paths; audit and close every gap, including direct internal callers. Test creation of a guard while cleanup is paused, and termination between History publication and guard release. Never hold a SQLite transaction over Docker/Compose or filesystem deletion.

## Web terminal state and compatibility

- A *new-protocol* web operation must advertise protocol capability when `create_operation` commits, **before** any later guard write. Thus capability present + no committed guard proves the boundary was never authorised; the new-protocol operation may recover as `blocked`. A marker without correlated History, contradictory History, or unreadable state recovers as `unresolved`. Legacy rows retain legacy semantics. Both cases require a synthetic interrupted-worker test.
- A dedicated `unresolved` status is a **separate owner decision (D9)**. Update server validators, operation projection, UI, polling/SSE termination and test contracts together. Status is distinct from guard lifecycle: terminal display must not imply mutation permission.
- Rollback/downgrade to binaries that do not understand operation-scoped guards or their retention/admission rules is **unsupported while any guard is unresolved**. R10 alone is insufficient. Production upgrade/downgrade must be a separate explicitly approved migration/rehearsal gate. Do not claim all slices are independently binary-revertible across this guard boundary.

## Mandatory S0 design checks and synthetic tests

Use temp SQLite, fake files, mocked Docker, bounded threads and the guarded test harness:

1. Two operations share an image: both owners are preserved; completing one cannot release the other's claim.
2. An existing `NULL history_id` namespace/manual protection remains byte-for-byte intact through attempted admission and another operation's completion; mismatched ownership must refuse.
3. The image's normal rollback refs remain intact; a legitimate completion publishes History + protection exactly once, and releases only its own guard.
4. All cleanup/forced cleanup paths refuse a guarded image; protected backups survive past their TTL; unrelated files still expire; unreadable DB state fails closed.
5. An interrupted/ambiguous pre-mutation guard write never authorises Docker; capability without guard proves not started; a committed guard without History stays unresolved after recovery.
6. Concurrent guard publication and cleanup demonstrate lock/revalidation exclusion; failures between History commit, web terminal write and guard release leave evidence safely retained.
7. Existing web terminal/SSE/UI behaviour and future `unresolved` semantics are assessed across web-version compatibility before enabling them.

**Gate:** Architectural Opus critique, independent ChatGPT re-review and explicit owner approval. Until then PR #15 remains draft, docs-only, open and unmerged. No production access or service restart.
