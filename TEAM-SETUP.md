# DevSecOps Reviewer — Team Setup

A Claude Code plugin that security-reviews a developer's own changes **before they
push** — it finds exploitable vulnerabilities, explains each one, proposes a fix,
exports **SARIF** for GitHub code scanning, and gates `git push` on a passing
review.

- **Marketplace:** `devsecops-tools` (GitHub repo `khalilrmilA/claude-plugin`)
- **Plugin:** `devsecops-reviewer`
- **Command:** `/devsecops-reviewer:security-review`

---

## Prerequisites

- **Claude Code** v2.1.269+ (`claude --version`; `claude update`).
- **Git** 2.31+.
- **Python 3** (the review engine uses it; `python --version`). Git Bash on
  Windows finds it automatically.
- **Node.js** (gives the built-in `npm audit`). Optional extra scanners:
  `gitleaks`, `semgrep`, `osv-scanner`.

---

## For team members — install via git

Run these once (any terminal):

```bash
# 1. Add the marketplace from GitHub
claude plugin marketplace add khalilrmilA/claude-plugin

# 2. Install the plugin
claude plugin install devsecops-reviewer@devsecops-tools

# 3. Verify, then restart Claude Code
claude plugin list        # shows: devsecops-reviewer@devsecops-tools  ✔ enabled
```

> **Restart Claude Code** after installing or updating, or the slash command
> won't appear yet.

Private repo? Claude Code clones with your existing Git credentials (SSH key in
`ssh-agent`, or a stored HTTPS credential — `gh auth login && gh auth setup-git`
on GitHub). If you have no SSH key, set `CLAUDE_CODE_PLUGIN_PREFER_HTTPS=1`.

### Enable it for a whole repository (optional)

Commit this to the repo's `.claude/settings.json` so every contributor gets it:

```json
{
  "extraKnownMarketplaces": {
    "devsecops-tools": { "source": { "source": "github", "repo": "khalilrmilA/claude-plugin" } }
  },
  "enabledPlugins": { "devsecops-reviewer@devsecops-tools": true }
}
```

Or install it project-scoped from the repo once:

```bash
claude plugin marketplace add khalilrmilA/claude-plugin --scope project
claude plugin install devsecops-reviewer@devsecops-tools --scope project
```

---

## Run a review

Open your project in Claude Code (plugin enabled), then:

```
/devsecops-reviewer:security-review            # reviews your changes vs main/upstream
/devsecops-reviewer:security-review --all      # full audit of the whole repo
```

Tip: if your working tree is clean (nothing to diff against `main`), use `--all`.

You get: findings mapped to **OWASP Top 10:2025 + CWE** with a severity and
confidence, an attack scenario and a proposed fix for each, a **verdict**
(PASS / PASS WITH WARNINGS / BLOCKED), a human report and a **SARIF** file under
`.security-review/reports/`, and the **push gate** — `git push` is blocked until
the review passes.

---

## Update to a new version

Claude Code pins installed plugins by their `version`, so you only get a new
build when the maintainer bumps it. To pull the latest:

```bash
claude plugin marketplace update devsecops-tools          # re-read the marketplace (git pull)
claude plugin update devsecops-reviewer@devsecops-tools   # install the new version
# then restart Claude Code
```

Check your version anytime with `claude plugin list`.

---

## Team config (shared tuning)

Commit a `.security-review/config.md` to a repo to tune the review for that repo
without editing the plugin — custom checks, suppressions (known-safe patterns),
severity overrides, scope notes, and the blocking policy. The plugin keeps this
one file tracked (the rest of `.security-review/` stays ignored). It **refuses**
any rule that would switch the review off or hide a real bug.

---

## CI enforcement (required status check)

Client-side git hooks can be bypassed (`git push --no-verify`); CI is the wall.
Copy `plugins/devsecops-reviewer/ci/security-review.yml` into your repo at
`.github/workflows/security-review.yml`, and add an **`ANTHROPIC_API_KEY`** repo
secret. On every PR/push it runs the review headlessly, uploads findings to
GitHub **code scanning** (Security tab + inline PR annotations), and **fails the
job when the verdict is BLOCKED**. Make it a required status check to block
merges. (Each run calls the Claude API and costs tokens.)

---

## For the maintainer — releasing a new version via git

Consumers only get changes you've **pushed and version-bumped**. Release flow:

```bash
# 1. Bump the version (SemVer) so installs detect the update
#    edit plugins/devsecops-reviewer/.claude-plugin/plugin.json  ->  "version": "0.3.1"
# 2. Note the change
#    edit CHANGELOG.md
# 3. Validate
claude plugin validate plugins/devsecops-reviewer --strict
claude plugin validate .
# 4. Commit + tag + push
git add -A
git commit -m "feat: <what changed> (v0.3.1)"
git tag -a v0.3.1 -m "v0.3.1"
git push origin main --follow-tags
```

Teammates then run the two **Update** commands above.

> **Rule of thumb:** every change to the plugin needs a `version` bump, or
> `plugin update` sees nothing new.

---

## Developer mode (contributing to the plugin itself)

While changing the plugin, skip install/update/restart and load the source live:

```bash
claude --plugin-dir "<path>/claude-plugin/plugins/devsecops-reviewer"
```

`--plugin-dir` always reads the current source — no version bump, no update.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `/devsecops-reviewer:...` not listed | Restart Claude Code; confirm `claude plugin list` shows it **enabled**. |
| Still on the old version after an update | Run both update commands, then **restart**; check the version bumped on the maintainer side. |
| `devsecops-review: command not found` inside a review | The plugin's `bin/` is on PATH only while enabled; the skill falls back to `bash "${CLAUDE_PLUGIN_ROOT}/scripts/<name>.sh"`. |
| Review says Python is missing | Install Python 3; the deterministic engine needs it (reviews still run, with a manual fallback). |
| Windows | Use **Git Bash** (ships with Git for Windows) — the plugin's scripts run in bash. |
