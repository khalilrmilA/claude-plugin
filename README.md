# devsecops-reviewer

A Claude Code plugin that runs a **security review of a developer's own changes
before they push**. It detects what an attacker could exploit, explains each
issue, proposes a fix, and gates `git push` on a passing review — so fewer
vulnerabilities reach your Git repositories.

It is **language-agnostic**: it detects the stack of whatever project it runs in
(Python/Django/Flask/FastAPI, JS/TS/Express/Nest/Next, PHP/Laravel/Symfony,
Java/Kotlin/Spring, C#/.NET, Go, Ruby/Rails, plus Docker/K8s/Terraform and CI)
and loads the matching checklists.

- **Marketplace:** `devsecops-tools`
- **Plugin:** `devsecops-reviewer`
- **Main command:** `/devsecops-reviewer:security-review`

> There is a built-in `/security-review` in Claude Code. This plugin's command
> is the namespaced `/devsecops-reviewer:security-review`; use that name.

## What it does

When you say you're done with a feature, want to commit/push/open a PR, or ask
whether your code is secure, Claude runs `/devsecops-reviewer:security-review`.
It:

1. Checks that Git works (falls back to `git-access-setup` if not).
2. Computes the **scope**: the diff of your branch vs its upstream (or
   `main`/`master`), plus staged, unstaged and new files. Flags: `--all`,
   `--staged`, `--since <ref>`.
3. **Detects the stack** and loads matching framework checklists.
4. Builds a **context map** (routes, auth, DB, config) and notes what looks
   missing, e.g. a new endpoint with no auth check.
5. Runs **deterministic scanners** that are installed (gitleaks, semgrep,
   dependency audits), scoped to your changes. Missing tools are reported, never
   fatal.
6. Dispatches specialist **reviewer agents** (injection, auth, logic,
   config/secrets, **crypto**, dependencies) — only the relevant ones.
7. Merges and de-duplicates findings, drops scanner false positives the agents
   disproved, then runs a **verification pass** (`finding-verifier`) that tries
   to *disprove* every candidate and keeps only those with a concrete, reachable
   exploit path — the main precision control. Sorts by severity.
8. Asks you **direct questions** for anything uncertain (e.g. "Is `/api/export`
   meant to be public?").
9. **Fix mode:** for each finding shows the attack, the vulnerable `file:line`,
   and a proposed fix as a diff. You accept / reject (with reason) / edit.
   Nothing is changed without your approval; fixes are re-checked after applying.
10. Produces a **verdict** — PASS, PASS WITH WARNINGS, or BLOCKED.
11. Writes a **stamp** (`.security-review/stamp.json`) and a **report**
    (`.security-review/reports/<id>.md`).
12. The **push gate** blocks `git push` until the pushed code matches a passing
    review.

### Vulnerability coverage

Injection (SQL, NoSQL, command, LDAP, template/SSTI, code); XSS (stored,
reflected, DOM); path traversal / LFI; SSRF; open redirect; XXE; insecure
deserialization; insecure file upload; broken authentication; broken
authorization, IDOR, privilege escalation, mass assignment, CSRF; JWT/session
weaknesses; password storage; business-logic flaws, race conditions,
client-side trust, missing server-side validation; secrets and default
credentials; debug mode, permissive CORS, insecure cookies, missing security
headers, risky Docker/K8s/IaC/CI; weak cryptography and insecure randomness;
vulnerable/outdated dependencies and typosquatting; sensitive data in logs.

Each finding maps to the **OWASP Top 10 (2021)** and a **CWE**, with a severity
and a confidence (`confirmed` / `likely` / `suspected`).

### Extra skills you can run directly

Besides the main review, the plugin ships two focused skills:

- **`/devsecops-reviewer:threat-model [path|feature]`** — a one-page threat model
  of a change or feature: trust boundaries, data flows, and ranked attacker goals
  (STRIDE as a prompt), so you know where to look hardest before building or
  reviewing. The main review runs it automatically for large/high-risk changes.
- **`/devsecops-reviewer:deep-secret-scan [--tree|--history|--all]`** — a deep
  secret sweep over the **whole tree and git history** (not just the diff). It
  uses `gitleaks` when installed and a built-in pattern/entropy fallback
  otherwise, and separates secrets that are **live in the tree** from those that
  survive **only in history** (still leaked — rotate them). Masks every value and
  never rewrites history.

### Team configuration (`.security-review/config.md`)

Commit a `.security-review/config.md` to tune the review for your repo without
editing the plugin. Copy the template from
`plugins/devsecops-reviewer/skills/security-review/config-template.md`. It
supports:

- **custom-checks** — project rules every review enforces (e.g. "`/admin/**`
  routes must require the admin role").
- **suppression** — known-safe patterns the verifier should drop (with a reason),
  to kill recurring false positives.
- **severity-overrides** — re-rate a category for your context (e.g. headers set
  at the edge → `info`).
- **scope-notes** — context that changes reachability (e.g. "service is VPC-only").
- **blocking-policy** — which severities block the push (default: critical/high).

The review ignores any config directive that tries to disable the review or hide
a specific real bug, and reports it. This mirrors Anthropic's own
`claude-code-security-review` approach of version-controlled custom-scan and
false-positive-filtering instructions.

## Install

### Prerequisites

- **Claude Code** v2.1.269 or later (`claude --version`; `claude update`).
- **Git** 2.31+.
- Optional **scanners** (the review works without them; it just adds a
  deterministic layer) — see [Install the scanners](#install-the-scanners).
- The scripts run in Bash. On Windows that is **Git Bash**, which ships with
  Git for Windows; no extra setup.

### For one developer

In a Claude Code session:

```
/plugin marketplace add khalilrmilA/claude-plugin      # GitHub owner/repo of this marketplace
/plugin install devsecops-reviewer@devsecops-tools
```

Or from your shell:

```bash
claude plugin marketplace add khalilrmilA/claude-plugin
claude plugin install devsecops-reviewer@devsecops-tools
```

Private repo: Claude Code clones with your existing Git credentials (SSH key in
`ssh-agent`, or a stored HTTPS credential — `gh auth login && gh auth setup-git`
on GitHub). It never prompts for a password. If you have no SSH key, set
`CLAUDE_CODE_PLUGIN_PREFER_HTTPS=1`.

Then, in a project, just ask Claude to review your changes, or run
`/devsecops-reviewer:security-review`.

### For a whole repository (every contributor)

From the repo, once, committed to the repo's settings:

```bash
claude plugin marketplace add khalilrmilA/claude-plugin --scope project
claude plugin install devsecops-reviewer@devsecops-tools --scope project
```

This writes `.claude/settings.json` with `extraKnownMarketplaces` +
`enabledPlugins`. Commit it. Each teammate still needs the plugin on their
machine; Claude Code installs it for them when they trust the folder (an
external-source plugin may need a one-time `claude plugin install
devsecops-reviewer@devsecops-tools --scope project`). Example
`.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "devsecops-tools": { "source": { "source": "github", "repo": "khalilrmilA/claude-plugin" } }
  },
  "enabledPlugins": { "devsecops-reviewer@devsecops-tools": true }
}
```

### For a whole organization (managed settings)

An administrator puts this in [managed settings](https://code.claude.com/docs/en/plugins/org)
(the `managed-settings.json` policy file, MDM, or the claude.ai admin console).
It installs and enables the plugin on every machine and can't be overridden:

```json
{
  "extraKnownMarketplaces": {
    "devsecops-tools": {
      "source": { "source": "github", "repo": "khalilrmilA/claude-plugin" },
      "autoUpdate": true
    }
  },
  "enabledPlugins": { "devsecops-reviewer@devsecops-tools": true }
}
```

Managed-settings file locations: macOS
`/Library/Application Support/ClaudeCode/managed-settings.json`, Linux
`/etc/claude-code/managed-settings.json`, Windows
`C:\ProgramData\ClaudeCode\managed-settings.json`. To lock down sources as well,
add `strictKnownMarketplaces` and `disableSideloadFlags` (see the org docs).

### Develop / try locally without a marketplace

Clone the repo and point Claude Code at the plugin directory:

```bash
git clone https://github.com/khalilrmilA/claude-plugin.git
claude --plugin-dir ./claude-plugin/plugins/devsecops-reviewer
```

## Install the scanners

All optional. The review reports which are missing and the install command, and
works with none installed.

| Scanner | Finds | Install |
| :- | :- | :- |
| gitleaks | secrets | `brew install gitleaks` · `winget install Gitleaks.Gitleaks` · [releases](https://github.com/gitleaks/gitleaks/releases) |
| semgrep | code patterns | `pipx install semgrep` (Windows: WSL or `docker run semgrep/semgrep`) |
| osv-scanner | vulnerable deps (all ecosystems) | `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest` · `brew install osv-scanner` · `winget install Google.OSVScanner` |
| npm audit | Node deps | ships with Node.js |
| pip-audit | Python deps | `pipx install pip-audit` |
| composer audit | PHP deps | ships with Composer |
| others | `dotnet list package --vulnerable`, `govulncheck`, `cargo audit`, `bundler-audit` | per ecosystem |

`osv-scanner` alone covers most ecosystems and is the easiest single add. Set
`DSR_SEMGREP_CONFIGS` to use local semgrep rules offline (default pulls registry
rulesets, which need network).

## Model selection

The review matches the model to the task instead of using one model for
everything — strong reasoning where it matters, a fast cheap model for
reading-heavy work. Each reviewer agent has a default tier:

| Agent | Default model | Effort | Why |
| :- | :- | :- | :- |
| logic-reviewer | opus | high | business logic, state machines, race conditions — deepest reasoning |
| auth-reviewer | sonnet | high | authorization and IDOR reasoning |
| injection-reviewer | sonnet | high | source→sink tracing across files |
| crypto-reviewer | sonnet | high | primitives, keys, randomness, signatures |
| config-secrets-reviewer | haiku | medium | reading config, matching secret/misconfig patterns |
| dependency-reviewer | haiku | low | manifest/version lookups |
| finding-verifier | opus | high | adversarially disproving candidate findings — precision matters most |

The orchestrator then **adjusts per change**: it escalates an agent to `opus`
when its area carries the real risk (money, credentials, personal data,
admin/privilege boundaries, or a large/intricate diff), and downgrades to
`haiku` for a trivial low-reasoning scope (a few lines of config, a dependency
bump, a rename). The main orchestrator runs on your session model; pick it with
`/model` and `/effort`.

Override for a whole team or CI run:

- `CLAUDE_CODE_SUBAGENT_MODEL=<alias>` forces every reviewer agent to one model (e.g. `sonnet` to cap cost, `opus` for a release audit). A per-change override by the orchestrator still takes precedence.
- To change a default tier permanently, edit the `model:` / `effort:` frontmatter in `plugins/devsecops-reviewer/agents/<agent>.md`.

Model aliases resolve to the latest generation available to your account
(Opus / Sonnet / Haiku). If your plan lacks a tier, set
`CLAUDE_CODE_SUBAGENT_MODEL` to one you have.

## The push gate

Two independent layers both check the same stamp; neither runs the full review.

1. **Inside Claude Code** — a `PreToolUse` hook blocks any `git push` Claude
   runs when there's no passing stamp for the pushed code, telling Claude to run
   `/devsecops-reviewer:security-review` first. Installed automatically with the
   plugin.
2. **From a terminal/IDE** — an optional Git `pre-push` hook. Install it per
   repo:

   ```bash
   devsecops-review install-hook            # mode: check (default)
   devsecops-review install-hook --mode headless   # run the review with `claude -p` if the stamp is missing
   devsecops-review install-hook --mode warn       # print a warning but never block (gentle rollout)
   ```

   It never overwrites an existing `pre-push` hook — it chains to it as
   `pre-push.chained`. Remove with `devsecops-review install-hook --uninstall`.
   (`devsecops-review` is on PATH inside Claude Code; from a plain shell call
   `bash <plugin>/scripts/install-git-hook.sh`.)

A stamp is valid when the verdict is PASS, PASS WITH WARNINGS or OVERRIDDEN
**and** every file in the pushed commits has exactly the content that was
reviewed (compared by Git blob id). So the normal flow — review, then commit,
then push — stays valid, but committing anything unreviewed invalidates it.

**Limitation:** client-side Git hooks can be bypassed (`git push --no-verify`).
For a hard guarantee, also enforce the review in CI or as a required status
check. The stamp (`.security-review/stamp.json`) and the JSONL logs are what a
server-side check would read.

## Logs and telemetry

Every step appends one JSON object per line to
`.security-review/logs/events.jsonl`. Each record has: `schema_version`,
`timestamp` (UTC ISO-8601), `event`, `review_id`, `repo`, `repo_remote` (with
credentials stripped), `branch`, `commit`, `developer` (git `user.email`),
`host`, `plugin`, `plugin_version`, `session_id`, and an event-specific
`details` object.

Event types: `review_started`, `scope_detected`, `stack_detected`,
`scanner_result`, `agent_started`, `agent_completed`, `finding_reported`,
`question_asked`, `question_answered`, `finding_accepted`, `finding_rejected`
(with reason), `fix_applied`, `fix_verified`, `verdict`, `block_overridden`
(with reason), `push_blocked`, `push_allowed`, `review_error`.

Snippets, secrets and personal data are never written to the logs. The format is
append-only JSON Lines so it can be shipped to a central system (Splunk, ELK, a
SIEM, BigQuery): tail the files from each repo, or have a CI step collect them.
Read them locally with, e.g.:

```bash
cat .security-review/logs/events.jsonl | python -m json.tool --json-lines   # or: jq . if installed
```

`.security-review/` is git-ignored automatically (stamps, reports, scans and
logs are local, per developer).

## Run the evaluation suite

`evals/` measures the plugin's quality against deliberately vulnerable sample
apps (Flask, Express, PHP, Spring) plus clean-but-suspicious files. It is **not**
shipped to developers (it lives in the marketplace repo, outside the plugin).

```bash
cd evals
bash run-evals.sh                 # all fixtures; writes results/<ts>/report.md
bash run-evals.sh --fixture python-flask --keep --model sonnet
```

It runs `/devsecops-reviewer:security-review --all --non-interactive` on each
fixture, then `score.py` reports recall, precision and clean-file false
positives, per fixture and per category. Pass threshold: overall recall ≥ 80%,
no category below 60%, clean-file false positives ≤ 20%. See
[`evals/README.md`](evals/README.md).

## Repository layout

```
claude-plugin/                        # this repo == the marketplace (name: devsecops-tools)
├── .claude-plugin/marketplace.json
├── plugins/devsecops-reviewer/       # the plugin (what gets installed)
│   ├── .claude-plugin/plugin.json
│   ├── skills/security-review/       # orchestrator + schema + policy + checklists + config template
│   ├── skills/threat-model/          # trust-boundary / attacker-goal map
│   ├── skills/deep-secret-scan/      # tree + git-history secret sweep
│   ├── skills/git-access-setup/
│   ├── agents/                       # 7 read-only agents (5 reviewers + crypto + finding-verifier)
│   ├── hooks/hooks.json              # push gate + lifecycle logging
│   ├── scripts/                      # scope, stack, scanners, deep-secrets, stamp, logging
│   ├── git-hooks/pre-push
│   └── bin/devsecops-review          # CLI dispatcher (on PATH in Claude Code)
└── evals/                            # quality suite (not installed)
```

## Security & privacy notes

- Reviewer agents are **read-only** (Read/Grep/Glob). Only the orchestrator
  skill writes files or runs Git, and only with your approval for source edits.
- Removing a hardcoded secret from code does not remove it from Git history —
  **rotate** any exposed secret. The review says so in the fix.
- Treat the review as an assistant, not a guarantee: it reduces risk, it does
  not replace a security program, penetration testing, or server-side controls.
