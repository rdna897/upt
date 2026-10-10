# Frozen production schema-8 compatibility fixture

`production_schema8_state.py` contains verbatim top-level definitions and a
bounded selection of `State` methods from:

- Source: `src/docker_update_manager/state.py` at an earlier release baseline
  (the original repository and commit identifiers are omitted from this
  sanitised snapshot)

The selected methods are `__init__`, `_new_connection`, `_ensure_schema`,
`connect`, `read`, `_exec_schema`, `_migrate`,
`_migrate_scan_warnings_and_snapshot`, `_save_verification`,
`_prune_verifications`, `record`, `history`, `protected`, and
`prune_operations`.
Their decorators and bodies are unchanged. Unrelated State methods are omitted.
This freezes production's actual connection setup, migration/version refusal,
core history writes and rollback protection rather than simulating acceptance
with the new implementation or a manually repeated version check.

`test_state_rollback_compatibility.py` loads it in an independent module namespace
and exercises a temporary database through production creation, Phase 2A receipt
archival, binary rollback/core writes, and re-upgrade. Tests require neither Git
history nor network access. Keep this fixture frozen; a future production
baseline requires a deliberately separate fixture and compatibility decision.

The frozen top-level definitions are `LEGACY_SCHEMA`, `WEB_SCHEMA`,
`OPERATION_SCHEMA`, `RUNTIME_SCHEMA`, `VERIFICATION_SCHEMA`,
`COMPOSE_BASELINE_SCHEMA`, `VERIFICATION_IDENTITY_FIELDS`, `CORE_SCHEMA_VERSION`,
`CURRENT_SCHEMA_VERSION`, `OPERATION_EVENT_LIMIT`, `OPERATION_HISTORY_LIMIT`,
`OPERATION_TERMINAL_STATUSES`, `COMPOSE_BASELINE_COLUMNS`, `_utc_now`,
`_parse_timestamp`, and `verification_identity`, plus the listed `State` methods
and their original imports. Production's exact `prune_operations` was added for
the downgrade/re-upgrade unproven-artifact regression; no full-module copy is used.

Expected SHA-256 of the fixture bytes:
`cb8cbbb2868cf6d88ae6a547189122bc0491678448417eba5f6f6c1b9301320c`.
`test_frozen_production_fixture_integrity` pins this value. Editing the fixture
must fail that test until an explicit compatibility decision updates both the
expected hash and this provenance; do not regenerate the expectation at runtime.
