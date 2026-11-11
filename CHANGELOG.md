# Changelog

All notable changes to the `devsecops-reviewer` plugin. This project follows
[Semantic Versioning](https://semver.org): the `version` in
`plugins/devsecops-reviewer/.claude-plugin/plugin.json` is bumped on every
release so installed copies update.

## [0.3.0] — 2026-11-11

### Added
- **SARIF 2.1.0 export.** Each review writes `.security-review/reports/<id>.sarif`
  alongside the JSON/Markdown report, so findings plug into GitHub code scanning
  or any SARIF-aware tool. Severity maps to `error`/`warning`/`note`; rules carry
  the CWE help link and an OWASP-derived `security-severity`; secrets stay masked.
- **CI enforcement template** (`plugins/devsecops-reviewer/ci/security-review.yml`):
  runs the review headlessly on PR/push, uploads the SARIF to code scanning, and
  fails the job when the verdict is BLOCKED — the server-side guarantee a
  client-side git hook can't provide.

### Changed
- Honest metadata: real author/owner and an **MIT** license (was `UNLICENSED`).

## [0.2.0] — 2026-11-11

### Added
- **Deterministic review engine** (`scripts/review.py` + `review.sh`): merges and
  de-duplicates agent findings, applies the verifier's rulings, computes the
  verdict and writes the report — the mechanical work no longer depends on the
  model retyping JSON. A `SubagentStop` hook auto-captures each agent's envelope.
- `devsecops-review` subcommands: `surfaces`, `collect`, `verify`, `report`,
  `findings …`, `capture`.
- Committable team config: `.security-review/config.md` is kept out of the
  ignore rule so it can be version-controlled; repos touched by an older version
  are migrated automatically.

### Changed
- **OWASP Top 10:2025** (and OWASP LLM Top 10 for AI/LLM findings) across the
  schema and agents.
- Faster shell libraries (fork-free helpers, UTC via epoch arithmetic, batched
  logging).
- Step 8 of the review always asks the open questions in interactive mode.

## [0.1.0] — 2026-11-02

### Added
- Initial release: stack detection, deterministic scanners (gitleaks, semgrep,
  osv-scanner, ecosystem auditors), ten specialist read-only reviewer agents
  (injection, auth, logic, config/secrets, crypto, dependency, supply-chain,
  cloud, AI/LLM) plus an adversarial finding-verifier, guided fixes, a push gate
  (Claude Code hook + git pre-push hook), team config, JSONL telemetry, and an
  eval suite.
