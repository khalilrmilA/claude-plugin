# Finding schema

Every reviewer agent returns its findings in this structure, and the final
report (`.security-review/reports/<review_id>.json`) uses it unchanged. Keep
field names exactly as written; the eval scorer and log shippers parse them.

## Agent output envelope

An agent's final message ends with exactly one fenced `json` block:

```json
{
  "agent": "injection-reviewer",
  "files_reviewed": ["src/routes/users.js", "src/db.js"],
  "coverage_notes": "Traced 6 request parameters to 4 sinks; templates auto-escape.",
  "findings": [ { "...": "finding objects, see below" } ],
  "disproved_scanner_findings": [
    { "tool": "semgrep", "rule": "javascript.express.security.audit.xss", "file": "src/views/a.js", "line": 12,
      "reason": "Value is a server-side constant, not user input." }
  ],
  "questions": [
    { "id": "Q1", "finding_ids": ["AUTH-002"], "question": "Is GET /api/export meant to be public?" }
  ]
}
```

`findings: []` is a valid and expected answer when nothing exploitable is found.

## Finding object

| Field | Type | Required | Meaning |
| :- | :- | :- | :- |
| `id` | string | yes | Agent prefix + number: `AUTH-001`, `INJ-001`, `LOGIC-001`, `CFG-001`, `DEP-001`, `SCAN-001` (scanner-only) |
| `title` | string | yes | One line, e.g. "SQL injection in user search" |
| `category.key` | enum | yes | One key from the table below |
| `category.owasp` | string | yes | OWASP Top 10:2025 id and name, e.g. `A05:2025-Injection` (AI/LLM findings may use the OWASP LLM Top 10, e.g. `LLM01:2025-Prompt Injection`) |
| `category.cwe` | string | yes | Most specific CWE, e.g. `CWE-89` |
| `severity` | enum | yes | `critical`, `high`, `medium`, `low`, `info` (see severity-policy.md) |
| `confidence` | enum | yes | `confirmed`, `likely`, `suspected`, `needs_validation` (definitions below) |
| `file` | string | yes | Repo-relative path, forward slashes |
| `line_start`, `line_end` | integer | yes | 1-based inclusive range of the vulnerable code |
| `snippet` | string | yes | The vulnerable lines, verbatim, max ~10 lines. Mask secrets: keep at most 4 leading characters, then `****` |
| `source` | string | when applicable | Untrusted input: `req.query.q`, `request.files['f']`, header, env, DB field written by users... |
| `sink` | string | when applicable | Dangerous operation reached: `cursor.execute(f-string)`, `child_process.exec`, `innerHTML`... |
| `attack_scenario` | string | yes | How an attacker exploits it, concretely, in 1-3 sentences, with an example input |
| `impact` | string | yes | What the attacker gains |
| `proposed_fix.diff` | string | yes* | Unified diff against the current file (`--- a/path` / `+++ b/path` / `@@`). *May be empty only for findings that need a design decision; then explain in `proposed_fix.explanation` |
| `proposed_fix.explanation` | string | yes | Why the fix removes the vulnerability (not just what it changes) |
| `questions` | array of strings | no | Questions for the developer that would confirm or dismiss the finding |
| `references` | array of strings | no | CWE/OWASP/framework doc URLs |
| `detected_by` | array of strings | yes | `"<agent>"` and/or `"<tool>:<rule-id>"` |
| `status` | enum | set by orchestrator | `open`, `fixed`, `false_positive`, `accepted_risk`, `will_fix_later` |
| `resolution_note` | string | set by orchestrator | Developer's reason for a rejection, or verification note for a fix |

### Confidence

- **confirmed**: you traced a concrete path from an untrusted source to the sink (or the secret/config is literally present), and no control on the path stops it. You can write the exploit input.
- **likely**: the dangerous pattern is present and input appears attacker-controlled, but part of the path is outside what you could read (e.g. a helper in an unreviewed package), or a control exists but looks bypassable.
- **suspected**: depends on intent or context you could not see (e.g. "should this route require admin?"). A suspected finding **must** carry at least one entry in `questions`.
- **needs_validation**: the exploit path probably exists, but confirming it needs a deployment/provider/hosted-service fact not visible in source (branch-protection rules, CI runner trust, registry defaults, cloud-account policy, model/provider behavior). State the exact missing fact in `questions`. Mostly set by the verifier and the supply-chain / cloud / AI-LLM reviewers; it is not a weaker `suspected`. A `needs_validation` finding does not block the push gate on its own unless its underlying severity is critical/high (see severity-policy.md).

Never raise confidence to look useful. Never report a pattern as a vulnerability when the input is a constant, already validated, or provably safe (parameterized query, auto-escaped template, allowlisted value); mention it in `coverage_notes` instead.

## Category keys

Use the most specific key. The eval scorer treats keys in the same group as matching.

OWASP ids below are the **OWASP Top 10:2025** categories. (Notable moves from
2021: Injection is now A05 and absorbs XSS; SSRF folded into A01 Broken Access
Control; Cryptographic Failures is A04; Security Misconfiguration is A02 and
absorbs XXE; Vulnerable/Outdated Components became A03 Software Supply Chain
Failures; Insecure Design is A06.)

| Key | Group | OWASP 2025 | Typical CWE |
| :- | :- | :- | :- |
| `sqli` | injection | A05 Injection | CWE-89 |
| `nosqli` | injection | A05 Injection | CWE-943 |
| `command-injection` | injection | A05 Injection | CWE-78 |
| `ldap-injection` | injection | A05 Injection | CWE-90 |
| `template-injection` | injection | A05 Injection | CWE-1336 |
| `code-injection` | injection | A05 Injection | CWE-94, CWE-95 |
| `xss` | xss | A05 Injection | CWE-79 |
| `path-traversal` | path-traversal | A01 Broken Access Control | CWE-22, CWE-98 (LFI) |
| `ssrf` | ssrf | A01 Broken Access Control | CWE-918 |
| `open-redirect` | open-redirect | A01 Broken Access Control | CWE-601 |
| `xxe` | xxe | A02 Security Misconfiguration | CWE-611 |
| `deserialization` | deserialization | A08 Software or Data Integrity Failures | CWE-502 |
| `file-upload` | file-upload | A06 Insecure Design | CWE-434 |
| `authn` | authn | A07 Authentication Failures | CWE-287, CWE-306, CWE-307 |
| `session-jwt` | authn | A07 Authentication Failures | CWE-347, CWE-384, CWE-613 |
| `password-storage` | crypto | A04 Cryptographic Failures | CWE-916, CWE-256 |
| `authz` | authz | A01 Broken Access Control | CWE-862, CWE-863 |
| `idor` | authz | A01 Broken Access Control | CWE-639 |
| `privilege-escalation` | authz | A01 Broken Access Control | CWE-269 |
| `mass-assignment` | authz | A08 Software or Data Integrity Failures | CWE-915 |
| `csrf` | authz | A01 Broken Access Control | CWE-352 |
| `business-logic` | logic | A06 Insecure Design | CWE-840, CWE-841 |
| `race-condition` | logic | A06 Insecure Design | CWE-362, CWE-367 |
| `client-trust` | logic | A06 Insecure Design | CWE-602, CWE-472 |
| `input-validation` | logic | A06 Insecure Design | CWE-20, CWE-1284 |
| `debug-mode` | misconfiguration | A02 Security Misconfiguration | CWE-489, CWE-215 |
| `cors` | misconfiguration | A02 Security Misconfiguration | CWE-942 |
| `cookies` | misconfiguration | A02 Security Misconfiguration | CWE-614, CWE-1004, CWE-1275 |
| `security-headers` | misconfiguration | A02 Security Misconfiguration | CWE-693, CWE-1021 |
| `default-credentials` | misconfiguration | A07 Authentication Failures | CWE-1392, CWE-798 |
| `misconfiguration` | misconfiguration | A02 Security Misconfiguration | CWE-16 |
| `secrets` | secrets | A07 / A04 | CWE-798, CWE-259, CWE-321 |
| `vulnerable-dependency` | dependency | A03 Software Supply Chain Failures | CWE-1104, CWE-1395 |
| `typosquatting` | dependency | A03 Software Supply Chain Failures | CWE-1357 |
| `weak-crypto` | crypto | A04 Cryptographic Failures | CWE-327, CWE-328, CWE-330, CWE-338 |
| `sensitive-logging` | logging | A09 Security Logging and Alerting Failures | CWE-532 |
| `info-exposure` | logging | A01 / A06 | CWE-200, CWE-209 |
| `other` | other | best fit | best fit |

The three newest agents (supply-chain, cloud, AI/LLM) use the closest key above
and set `category.owasp` themselves — supply-chain/CI → A03 Software Supply Chain
Failures; cloud/IaC → A01 or A02; AI/LLM → the OWASP LLM Top 10 (e.g.
`LLM01:2025-Prompt Injection`, `LLM05:2025-Improper Output Handling`,
`LLM06:2025-Excessive Agency`).

## Example finding

```json
{
  "id": "INJ-001",
  "title": "SQL injection in product search",
  "category": { "key": "sqli", "owasp": "A05:2025-Injection", "cwe": "CWE-89" },
  "severity": "critical",
  "confidence": "confirmed",
  "file": "app/routes/products.py",
  "line_start": 41,
  "line_end": 42,
  "snippet": "q = request.args.get('q')\ncur.execute(f\"SELECT * FROM products WHERE name LIKE '%{q}%'\")",
  "source": "request.args['q'] (unauthenticated GET /products/search)",
  "sink": "sqlite3 cursor.execute with an f-string",
  "attack_scenario": "GET /products/search?q=%27%20UNION%20SELECT%20username,password_hash,1%20FROM%20users--  returns every user's password hash.",
  "impact": "Read any table, including credentials; on some drivers, modify data.",
  "proposed_fix": {
    "diff": "--- a/app/routes/products.py\n+++ b/app/routes/products.py\n@@ -41,2 +41,2 @@\n q = request.args.get('q')\n-cur.execute(f\"SELECT * FROM products WHERE name LIKE '%{q}%'\")\n+cur.execute(\"SELECT * FROM products WHERE name LIKE ?\", (f\"%{q}%\",))\n",
    "explanation": "The driver sends q as a bound parameter, so it is always treated as data and can never change the SQL statement's structure."
  },
  "questions": [],
  "references": ["https://cwe.mitre.org/data/definitions/89.html"],
  "detected_by": ["injection-reviewer", "semgrep:python.lang.security.audit.formatted-sql-query"],
  "status": "open"
}
```
