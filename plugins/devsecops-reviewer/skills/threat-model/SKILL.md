---
name: threat-model
description: Lightweight threat model of a code change or a feature - maps trust boundaries, data flows, entry points and assets, then lists what an attacker would try (STRIDE-style) and which existing controls stop them, so a security review (or a design discussion) knows where to look hardest. Use when the developer asks "what could go wrong with this", wants a threat model or data-flow/trust-boundary map before building or reviewing a feature, or when the security-review skill wants to focus its agents. Produces a short Markdown model; changes no code.
argument-hint: "[path or feature description] [--scope <branch|all|staged>]"
allowed-tools: Bash(git status *) Bash(git diff *) Bash(git log *) Bash(git ls-files *) Bash(git rev-parse *) Read Grep Glob
---

# Threat model

You produce a **focused, practical** threat model for a change or a feature, not
an exhaustive STRIDE matrix. The goal is to point attention at the parts of the
system where a mistake would hurt most. You write one Markdown file and change no
code.

Arguments: `$ARGUMENTS` — an optional path/feature description and `--scope`.

## When the security-review skill calls you

The orchestrator may run you right after its context map to sharpen agent
dispatch. In that case, read `.security-review/context-map.md` and
`.security-review/scope/files.txt` instead of re-deriving scope, and write your
output to `.security-review/threat-model.md` so the orchestrator can feed the
"attacker goals" and "trust boundaries" into each agent's prompt.

## Steps

1. **Scope the subject.** If given a path or feature, focus there. Otherwise use
   the change: `git diff --stat` against the upstream/main (or the `--scope`
   given). List the entry points touched (routes, handlers, CLI, jobs, message
   consumers, webhooks, public functions).

2. **Identify assets.** What is worth attacking here: credentials and sessions,
   personal/financial/health data, money movement, admin capability, the host
   itself, other users' data, integrity of important records.

3. **Map trust boundaries and data flow.** For each entry point, trace where
   untrusted input enters, which boundary it crosses (internet → app, app →
   database, app → internal service, user → other user's data, low-privilege →
   high-privilege), and where it ends up (sink). Note where validation,
   authentication, authorization and encoding sit — and where they are missing.

4. **Enumerate attacker goals (STRIDE as a prompt, not a form).** For the assets
   and boundaries above, list concrete things an attacker would try:
   - **Spoofing / auth** — act as another user or service; bypass login/MFA.
   - **Tampering** — change data, parameters, prices, roles, files in transit or at rest.
   - **Repudiation** — act without a trace (missing/forgeable audit logs).
   - **Information disclosure** — read data they shouldn't (IDOR, verbose errors, logs, SSRF).
   - **Denial of service** — only note it if it is cheap and high-impact; otherwise skip (it is out of scope for the review's verdict).
   - **Elevation of privilege** — reach admin/other-tenant capability; injection to code execution.
   Keep each as one line: *goal → the path that would allow it → the control that should stop it (and whether it is present)*.

5. **Rank.** Put the 3–7 highest-risk paths first: reachable by the least-trusted
   actor, touching the most valuable asset, with the weakest control.

## Output

Write `threat-model.md` (to `.security-review/threat-model.md` when called by the
review, else to a path you tell the developer):

```markdown
# Threat model — <subject> (<date>)
## Assets
- <asset>: <why it matters>
## Entry points & trust boundaries
| Entry point | Least-trusted caller | Boundary crossed | Reaches (asset/sink) | Control present? |
|---|---|---|---|---|
| POST /api/orders | any logged-in user | user → other users' orders | orders table | auth yes / ownership check **no** |
## Attacker goals (ranked)
1. **[EoP] Low-priv user reaches admin export** — GET /api/export has no role check → reads all tenants' data. Control: missing. → review auth here first.
2. ...
## Where the review should look hardest
- <file/area>: <why>
## Assumptions & open questions
- <anything whose answer changes the model>
```

Keep it to one page. End your chat reply with the top 3 risks in plain language
and the file path you wrote. If the developer asked only for a threat model
(not a full review), suggest running `/devsecops-reviewer:security-review` to
act on it, but do not start a review yourself.
