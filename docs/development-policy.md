# Development, publication and deployment policy

## Canonical source and archived history

`rdna897/upt` is the sole active development repository. The former private source repository is an archived historical record, **not** a code source to synchronise automatically. The disposable hosted-CI rehearsal repository is also not canonical. Any proposed migration must be treated as new public code: independent technical review, line-by-line disclosure review, synthetic fixtures and a public PR. Do not copy private discussion, plans, commit metadata or operational traces.

## Deployment freeze

Production deployment remains **frozen** until the operator separately authorises a specific rollout. This applies regardless of publication status, CI success, merge, tag or release. During the freeze:

- No production installation, deployment, rebuilding, daemon/service restart, configuration write, credential rotation, database migration, Docker/Compose action, cleanup, cache flush or change to persisted UPT state.
- Development runs only in isolated fixtures and CI environments. No job may require private, production-connected self-hosted runners or access to production tokens.
- Approval to merge a code change is not approval to deploy it. Record separate preflight evidence, a rollback plan and explicit operator approval before any later deployment.

These restrictions do not prevent read-only review, documentation changes or isolated tests.

## Pull request and disclosure workflow

1. Start from the current public `main` and make a narrowly scoped branch.
2. Check the diff, test data, workflow changes, source comments, documentation and CI outputs for disclosure risks. Replace private samples with synthetic data; never expose a secret to demonstrate redaction.
3. Run isolated, relevant local tests where available, then open a PR. Do not bypass the runner/environment guards.
4. Before merge, obtain independent code review and the exact-head complete Python 3.10, Python 3.13 and Chromium CI suite. A passing required `merge-gate` is necessary, but is not a substitute for human scrutiny.
5. For changes under `.github/**`, `scripts/ci/**` or release/security configuration, explicitly review workflow permissions, dependency pinning, fork PR safety, hosted runner selection and attempts to bypass required checks.

## Review ownership and limitations

`.github/CODEOWNERS` designates review responsibility. The current public `main` ruleset may not require approving reviews or code-owner approval. Verify the live branch rules separately; do not represent CODEOWNERS as enforced protection. Enabling code-owner approval requires a separate GitHub repository ruleset change and at least one eligible reviewer other than the PR author. Never disable existing required status checks or relax the no-bypass policy to accommodate this.

## Local development transition

New worktrees should be created from `https://github.com/rdna897/upt.git`; do not repoint an old private checkout without first preserving unpushed work, confirming its provenance and reviewing its contents. Use a fresh clone for the simplest clean separation. Do not move production runtime directories, virtual environments or state as part of this transition.
