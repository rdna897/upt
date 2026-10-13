# UPT — Docker Update Manager

**Experimental — actively under development.**

UPT is an experimental tool for managing Docker and Docker Compose updates.

The project is under active development and is not yet considered production-ready. Features, behaviour and interfaces may change.

Use at your own risk.

`upt cleanup` requires an existing, versioned state database to verify rollback
protection. Its automatic retention pass checks the same database before each
recovery deletion, image removal and metadata mutation, including compaction;
verification failure stops the pass and preserves the remaining recovery evidence.
Unversioned legacy state must first be migrated through an ordinary UPT command.
Standalone `upt retention cleanup` retains its age-based expiry and explicit
forced-retention behaviour. Use `--dry-run` to preview either cleanup command.
