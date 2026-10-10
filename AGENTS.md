# UPT contributor and coding-agent guidance

This repository (`rdna897/upt`) is the canonical, public development source for UPT. Treat all repository contents, commits, CI logs, review comments and uploaded artefacts as publicly visible. Do not retrieve or copy unpublished code, private issues, internal plans, operational identifiers, credentials, production samples or runner configuration into this repository.

## Work boundaries

- **Production deployment is frozen.** A PR, passing CI, merge or release is not permission to install, rebuild, restart, migrate, update or otherwise alter a running UPT service. Production rollout requires separate, explicit operator approval.
- Do not execute live Docker/Compose mutations, change firewall or systemd configuration, remove images, modify SQLite/history/backups, or flush caches as part of development or tests.
- Work in a short-lived feature branch and open a PR to `main`. Do not force-push `main`, rewrite published history, bypass branch rules, or merge before review and exact-head full CI.
- Preserve existing state, rollback evidence, immutable update identity, privilege separation and fail-closed test boundaries. Be especially cautious around service and authentication code.
- Do not weaken, remove or silently bypass tests, the `merge-gate`, runner-smoke checks, workflow permissions or required validations to obtain a green result.
- Workflow, repository-policy, credential and release-related changes require explicit human attention even when automated checks pass. CODEOWNERS routes attention; whether approvals are enforced is controlled separately by branch rules.

## Public disclosure checks

Before pushing: inspect the complete diff, newly added files and test fixtures for private addresses, hostnames, internal paths, tokens, credentials, session data, CI runner identities, infrastructure details and unapproved third-party material. Use invented, generic synthetic examples. Review GitHub Actions logs, artefacts and job names as potential publication surfaces. Never assume content is safe merely because it previously existed in another repository.

## Testing and efficient CI

- Run repository test harnesses in their isolation mode; do not run tests against production Docker or live network resources. Keep test-created threads and subprocesses bounded, joined and cleaned up.
- Follow the checked-in workflow and scripts to select or verify tests. A draft PR's targeted tests do **not** prove merge readiness. Require full Python 3.10, Python 3.13 and Chromium validation with a passing `merge-gate` for the exact intended PR head.
- When using the GitHub CLI to follow a workflow run, prefer one blocking `gh run watch <run-id> --exit-status` instead of repeated `gh run view` polling; inspect the final outcome afterwards. Do not spawn additional agents just to wait for CI.
- Prefer minimal changes and targeted investigation rather than unnecessary subagents, broad rewrites or expensive exploratory runs.

See [development and deployment policy](docs/development-policy.md) before changing runtime, CI or release behaviour.
