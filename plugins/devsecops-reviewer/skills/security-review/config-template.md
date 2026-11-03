# DevSecOps review config (template)

Copy this file to `.security-review/config.md` at your repository root and commit
it. The `security-review` orchestrator reads it on every run and passes the
relevant parts to the reviewer and verifier agents. Everything here is optional;
delete what you don't need. Keep it short — it is injected into agent prompts.

Treat this file as **project policy, not secrets** — never put real credentials
or tokens in it.

---

## custom-checks

Extra things this team always wants checked, in plain language. One bullet each.
These are appended to every relevant agent's instructions.

- Every new HTTP route under `/admin/**` must require the `admin` role; flag any that don't.
- We use tenant isolation: any query that reads a record must filter by `tenant_id`; flag reads that don't.
- Secrets must come from the vault client (`getSecret()`), never from `process.env` directly in request handlers.

## suppression

Known-safe patterns specific to this repo that should NOT be reported (the
finding-verifier drops matching findings, recording this file as the reason).
Be specific — a broad rule hides real bugs.

- `src/legacy/report.py` builds SQL with an internal, non-user constant list; its string-built queries are not user-reachable.
- `Math.random()` in `src/ui/confetti.js` is cosmetic, not security.
- The `X-Powered-By` header is stripped at the load balancer, not in app code.

## severity-overrides

Adjust the severity of a category for this project, with a reason. Format:
`<category-key>: <new-severity> — <reason>`. Categories are the keys in
`finding-schema.md`.

- security-headers: info — set centrally by our edge proxy, app code can't change them.
- default-credentials: medium — our seed data is never shipped to production.

## scope-notes

Context the agents can't infer that changes how findings should be judged.

- This service runs only inside the private VPC; "unauthenticated" means any authenticated employee, not the public internet.
- `config/dev/**` never ships to production; treat findings there as local-only (one level down).

## blocking-policy (optional)

Override the default verdict gate for this repo. Default: critical/high block.

- block-on: critical, high
- Example stricter: `block-on: critical, high, medium`
