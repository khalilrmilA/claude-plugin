# CI/CD pipeline checklist (GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, Bitbucket)

- Secrets written in pipeline files instead of the CI secret store; secrets echoed to logs (`echo $TOKEN`, `set -x` with secrets, `printenv`).
- GitHub Actions script injection: `run: echo "${{ github.event.issue.title }}"` / `${{ github.head_ref }}` / PR body/branch names interpolated into shell. Safe: pass through `env:` and quote `"$VAR"`.
- `pull_request_target` or `workflow_run` workflows that check out and run PR code with secrets or a write token.
- Over-broad `permissions:` (`write-all`, missing `permissions:` with a permissive org default); `GITHUB_TOKEN` passed to third-party actions.
- Third-party actions pinned to a branch/tag instead of a full commit SHA (supply-chain risk; low/medium by context).
- Self-hosted runners on public repositories.
- `curl | bash` installers without checksum; disabling TLS verification (`-k`, `NODE_TLS_REJECT_UNAUTHORIZED=0`).
- GitLab: unprotected variables used in jobs any branch can run; `CI_JOB_TOKEN` scopes too wide.
- Jenkins: `sh "... ${params.X}"` (Groovy interpolation into shell), credentials printed, script approval bypasses.
- Deploy steps that skip tests/security scans for some branches, or allow manual overrides without audit.
