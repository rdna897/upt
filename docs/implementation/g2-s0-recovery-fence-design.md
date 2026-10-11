# G2-S0 — Durable recovery fence: revised architecture for review

**Status:** Proposed design after independent Opus review; **not approved** for implementation, merging or deployment. See [G2 policy](g2-mutation-completion-policy.md), [G2 #9](https://github.com/rdna897/upt/issues/9), [G3 #10](https://github.com/rdna897/upt/issues/10).
**Safety:** Public-safe synthetic evidence only. No runtime, CI, schema, production database or Docker changes in this draft.

## 1. Decision D10: storage choice (provisional)

| Option | Merits | Costs / decision |
| --- | --- | --- |
| **A — reuse `compose_bootstrap_fences`** | Existing schema-9 table, keyed by `operation_id`, with unique unresolved `logical_key`; existing `bootstrap_fence`, `assert_service_unfenced` and offline `state_transition` already consult it; no `operation_runs` FK | **Preferred for S0, subject to code/compatibility proof.** Store *typed, bounded, private, versioned* G2 evidence in `evidence`; preserve all existing bootstrap/namespace fence semantics. Extend image and backup deletion paths explicitly. |
| B — dedicated schema-10 recovery claims | First-class typed claims, indexed image ownership, clean handling of malformed evidence, migration gate via schema version | Requires separately approved offline migration, mixed-version deployment and rollback plan. Select if A cannot safely meet safety invariants. |
| C — `operation_runs.summary` only | Reuses JSON with no table changes | **Rejected:** invisible to existing fence and offline-transition gates, collides with web-only active-slot and abandoned-operation lifecycle when CLI rows are added. |

**Do not call A universally downgrade-safe.** Existing R10 retention and `upt cleanup` do **not** consult `compose_bootstrap_fences`. A compatibility-belt `INSERT OR IGNORE` into `protected_images` is harmless to existing ownership, but if a row already exists it cannot guarantee an independent image claim; a history-linked row may subsequently expire. The **new** guard-aware cleanup/retention is mandatory. An older binary, including R10, cannot be run while unresolved G2 guards exist; `state_transition` must also refuse under any unresolved guard. Validate the supported downgrade and deployment matrix explicitly.

## 2. Fence representation and identity

- Reuse `compose_bootstrap_fences(logical_key, operation_id, evidence, lifecycle, created_at, updated_at)`. An unresolved row has `lifecycle='active'` while its operation is in flight; **`manual`** after recovery or a known unverified outcome. Both already participate in the unique partial index. Do not introduce a separate `pending`/unresolved status just for enforcement.
- G2 `evidence` is a distinguishable bounded protocol value (e.g. a `g2:v1:` prefix followed by strictly validated JSON, not an untagged object). It names the completion id (same as `operation_id`), exact proven `logical_key`, action, **per-path image claims** and canonical verified backup paths. Never embed environment contents or credentials. Only named `State` methods parse/modify it. Unknown/malformed G2 evidence fails closed and produces a safe diagnostic.
- **Admission is keyed by proven logical service identity**, not image ID. The unique unresolved-`logical_key` constraint refuses a conflicting mutation of the same service. Different services may independently claim the *same image*; any guard claiming the image blocks image removal until all such guards resolve.
- CLI receives a random durable fence operation ID but **does not** create a web `operation_runs` row. Its lifecycle and crash evidence are the fence itself. Batch updates use one fence **per service**, all under the existing `update.lock`; a failed service must not permit batch housekeeping to purge its claims.
- A service with unprovable `logical_key` cannot start a G2-guarded mutation. Do not silently substitute image identity as a service key or skip admission.

## 3. Exact claims by operation path

| Path | When armed | Images retained while unresolved | Backup evidence |
| --- | --- | --- | --- |
| Ordinary update / pinned update (CLI or web) | Immediately before first possible image pull/tag/source mutation | Old running image, **plus any earlier recovery image whose independent unresolved owner exists** | Backup just created by `backup_files`; guard its exact canonical directory |
| CLI rollback | Before any source restoration/tag/recreate | Currently running image **and** selected rollback-target image | Selected update's source backup **and a new pre-rollback backup** of current sources (to be added by its slice), if available; refuse when required backup cannot be proven |
| Web rollback | After pre-rollback backup, before first source restoration/tag/recreate | Currently running image and selected rollback-target image | Selected update backup and the new pre-rollback recovery backup |
| Compose apply | Existing namespace/Compose lifecycle applies; do not silently replace it with G2 | Preserve all existing image/baseline claims | Preserve its existing recovery receipts/bundles; separately characterise publisher integration |

A successful History `record` may still invoke existing `INSERT OR REPLACE` on `protected_images`. S0 admission and the publication transaction must **explicitly protect against replacing unrelated NULL-history/manual recovery rows**. Refuse that conflict rather than discard another owner; `rollback_refs` and prior history protections remain intact. `INSERT OR IGNORE` is only a legacy compatibility belt, not the guard's authoritative claim.

## 4. Lifecycle and atomicity

1. **Before effects:** for web, record `completion_protocol=1` at `create_operation` (independently of fence write); CLI needs only its durable fence key. Perform preflight/backups first. Inside one short `BEGIN IMMEDIATE`, verify no conflicting logical fence or independent manual protection, insert typed `active` fence and optionally `INSERT OR IGNORE` the old image belt. No Docker/Compose/FS deletion happens inside SQLite. If fence commit is ambiguous, **read to prove it exists**; a failed read never authorises mutation.
2. **Boundary placement:** put the guard immediately before the earliest actual side-effect callback in the core operation path, shared by CLI/web. If a later pre-boundary check refuses after the fence committed, resolve it only when *all* no-effect predicates are proved; otherwise retain as `manual`. No guard is armed in a dry run.
3. **Workload outcome:** after verified successful Docker/Compose effects, one `State.record` transaction commits the matching factual History row, rollback ref/protection and `UPDATE compose_bootstrap_fences SET lifecycle='resolved'` **atomically**, conditional on exact guard id/type/logical key/claimed identities. If the write is ambiguous, P5 reconciliation reads both the History and fence state. No separate post-terminal fence-release write.
4. **Failure:** after an actual workload failure, guard resolution is permitted only in the **same transaction** as a truthful failure/blocked History row **and** proof that recovery/no-effect conditions hold. Otherwise retain `active/manual`; never treat a fallback FAILED row generated by a *successful* workload's SQLite publication failure as proof.
5. **Interruption:** an unresolved `active` fence is durable across CLI process death. Recovery under `update.lock` may classify it `manual` without Docker replay; it cannot mark an unproved completed mutation as a definite failure. Do not fabricate a CLI web operation row. Web recovery derives its terminal status from committed History plus the guard/protocol evidence; move that recovery into the **first web correctness slice (S1)**, not S4.
6. **Retention:** neither unresolved fences nor their exact image/backup claims may be aged away or pruned. `resolved` fences may be pruned only after ordinary audit/retention conditions.

**Activation constraint:** enabling writers without correcting the corresponding existing publication error handler could let a successful workload get a FALSE `FAILED` row. Do not activate G2 guards for a mutation kind before that path's outcome-safe publication handler is deployed in the **same atomic code slice**. S0 base primitives/enforcement may ship inert before activation.

## 5. Admission, cleanup and legacy compatibility

- Central service-level gate: `State.assert_service_unfenced` (and equivalent logical-key gate for paths not already calling it). Add checks to relevant `restart`, `remove`, `convert`, `restore-compose` and any other modifying entrypoint, including direct/internal callers; verify that namespace/bootstrap callers keep their historical semantics. No silent acceptance when service identity cannot be proven.
- Central image-removal gate: `retention._removal_blocker` or an equivalent named `State` predicate reused by `upt cleanup`, forced retention and `remove --images` immediately before removal. Refuse on ANY unresolved fence claiming that image. Existing manual/legacy/rollback-ref protections still apply; `remove --images` currently bypasses the shared R10 removal check and must be fixed.
- Central backup-deletion gate: validate an exact direct child of the allowed `backups/` root, no symlink/path traversal. Skip all guarded recovery paths in preview, automatic, forced and real cleanup and repeat eligibility immediately before deletion. Keep existing `compose-recoveries` semantics.
- **Concurrency:** all UPT mutating image removals and ordinary mutations must hold `update.lock` from final admission through Docker/FS effects. Test a guard publication racing each deletion point. `State` checks use short snapshots, no SQLite transactions across Docker.
- **Malformed row scope:** if a typed guard has an identifiable logical key but its evidence is corrupt, refuse that service's mutations; if its image/backup claim cannot be proved, refuse the affected destructive cleanup operation (possibly the global cleanup command), report a repairable operator error. Do not lock all unrelated service mutations merely because one guard cannot be decoded.
- **Web privacy:** fence evidence is never returned in `operation_status`, HTTP, SSE, logs or `operation_presentation`. Project a strict allowlist; negative tests cover image IDs/backup paths/fingerprints and malformed inputs.
- **Downgrade:** offline `state_transition` and release/deployment gates must reject any `active/manual` G2 fence. Existing support for namespace/bootstraps is preserved. Merely using the existing fence table is not sufficient to justify deploying an older binary.

## 6. Supported operator resolution (required before activation)

Do not permanently lock services with no remedy. Include a **minimal audited offline/admin reconciliation operation** in the activation plan (under `update.lock`; never a browser-supplied raw SQL endpoint):

- Identify one exact fence ID and verify its logical identity, claimed images, exact source backup(s), actual running image and Compose source bytes against trustworthy pre/post evidence.
- If a matching committed History exists, resolve the named guard in a controlled transaction only after verifying that the History's rollback protections exist and that no other guard claim is released.
- If History is absent, permit a corrective History publication **only** when image/source postconditions and action are independently provable; record provenance, original completion ID and recovery evidence in one transaction with guard resolution.
- Otherwise leave the fence in `manual` and report specifically what cannot be proved. No force-unlock, blind SQL edit, synthetic success, automatic Docker rollback or automatic mutation retry.
- Operator action, audit and failures must be deterministic, isolated and idempotent. Any unresolved case without a safe release path is explicitly documented for owner acceptance.

## 7. Slice and test gates

- **S0a:** SQLite before-/during-commit fault classification, per-call timeout and synthetic harness; behaviour-neutral.
- **S0b:** typed fence predicates, service/image/backup enforcement, cleanup and `state_transition` gates, redaction. No G2 writers enabled; test legacy namespace/bootstrap behaviour unchanged.
- **S0c:** guarded core publication primitive with atomic matching History/fence resolution, pre-boundary refusal handling and minimal audited reconciliation *contract*. Writers are activated **per mutation kind** together with the correct S1/S2/S3 outcome handler; no exposed half-enabled state.
- **S1:** ordinary CLI update + web adapter/history failure mapping and **web abandoned-operation recovery together** (D9 required for web). CLI-only R1 correctness may be independently reviewed before D9; no web correctness slice ships without post-restart recovery.
- **S2:** pinned update; **S3:** CLI/web rollback with required pre-rollback backup and eligibility checks; **S4:** Compose Apply integration/namespace characterisation and cross-path review.

Tests must exercise real State SQLite transactions, dry-run no writes, per-service batch retention, CLI-only interruption and subsequent safe recovery, shared image/multiple owners, original NULL manual protection unchanged, atomic success and genuine failure, after-commit ambiguity, refused post-fence/pre-effect boundary, operation status/API/SSE redaction, malformed guard scoping, `state_transition` refusal, guarded and unguarded backup TTL, direct `remove --images`, `restart`, `convert`, `restore-compose` and all force flags.

## Approval gate

Opus to independently validate these decisions and any unsafe assumptions about existing `compose_bootstrap_fences` consumers; if a condition fails, propose the smallest safe alternative (including schema 10). Independent ChatGPT review and explicit owner decisions D3/D3b/D3c/D8/D9/D10 are required before any implementation. PR #15 stays docs-only, draft, unmerged. Deployment freeze remains in force.
