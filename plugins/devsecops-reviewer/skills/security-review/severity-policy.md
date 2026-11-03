# Severity and verdict policy

## Severity levels

Rate by what a realistic attacker gains, given who can reach the code
(unauthenticated internet user, any logged-in user, admin only, local only).

| Severity | Meaning | Examples |
| :- | :- | :- |
| **critical** | Remote, little or no precondition, leads to full compromise of data, accounts or the host | Unauthenticated SQL/command injection, RCE via deserialization, hardcoded production cloud/DB credential, authentication bypass, any user reaching admin functions |
| **high** | Serious compromise with a modest precondition (a normal account, a user click, a reachable internal service) | IDOR exposing other users' data, stored XSS, SSRF to internal network/metadata, path traversal reading arbitrary files, JWT accepted without signature check, price/quantity manipulation that loses money, XXE, plaintext/weakly hashed passwords |
| **medium** | Real weakness with limited impact or significant preconditions | Reflected XSS needing a crafted link, open redirect, missing rate limit on login, permissive CORS without credentials, debug mode in a non-production config that could ship, missing CSRF protection on a low-value action, verbose errors leaking internals |
| **low** | Defense-in-depth gap, hard to exploit alone | Missing security headers, cookie without `SameSite`, weak but non-security random usage, outdated dependency without a known reachable vulnerability |
| **info** | Worth knowing, no direct risk | Hardening suggestion, a TODO about security, code that is safe but fragile |

Adjust one level down when the code is provably reachable only by trusted
administrators or only in local development, and one level up when the
affected data is credentials, payments, health or personal data at scale. Say
why in `impact` whenever you adjust.

## Noise and exclusions (reduce false positives)

A review that reports low-value noise gets ignored, which is itself a security
failure. **Do not report** the following unless the specific instance has a
demonstrated, reachable exploit path (then report it at the severity its impact
earns, and say in `attack_scenario` why this instance is real):

- **Denial of service / resource exhaustion** as a category of its own (unbounded
  loops, large-input CPU/memory, ReDoS) — out of scope for the verdict. Exception:
  a trivial unauthenticated input that reliably takes the service down.
- **Rate limiting / brute-force hardening** as a standalone finding — note it as
  `info` at most unless it guards a credential or payment endpoint reachable
  unauthenticated.
- **Generic "missing input validation"** with no concrete dangerous sink behind
  it. Validation matters only where the unvalidated value reaches injection,
  auth, path, or logic sinks — report *that*, not the missing validation.
- **Self-XSS**, best-practice headers on an API with no browser surface,
  verbose errors in a local-only/dev-only path, and `TODO`/commented-out code.
- **Weaknesses with a genuinely non-security use** — a weak hash used purely as a
  non-security cache key, randomness used for a cosmetic (non-security) value.
  This is about the *use*, not the *codebase*: do **not** treat a real security
  bug as "theoretical" just because the surrounding repo is a stub, a skeleton,
  or lacks the consumer/backend that completes the exploit. Rate such a bug at
  its inherent severity as deployed (see the verifier's calibration rule).

An **open redirect** where an attacker controls the destination is a real finding
(default **medium**, phishing/token-leak); only rate it `low`/`info` when the
redirect target is same-origin-restricted or not attacker-controlled. It is *not*
on this exclusion list.

This is a floor, not a gag: a real, reachable bug in any of these areas is still
a finding. The finding-verifier pass applies this list when ruling on candidate
findings, and teams can extend it via the `suppression` rules in their
`.security-review/config.md` (see the orchestrator skill).

## Resolution states

| State | Who sets it | Resolves a critical/high? |
| :- | :- | :- |
| `fixed` | Orchestrator, after applying an accepted fix **and** re-checking the changed code | Yes |
| `false_positive` | Developer, with a reason | Yes |
| `accepted_risk` | Developer, with a reason | No: needs a block override |
| `will_fix_later` | Developer, with a reason | No: needs a block override |
| `open` | Default | No |

A `suspected` finding whose question the developer answered "this is
intended / safe" becomes `false_positive` with the answer as the reason. If the
answer confirms the concern, raise confidence to `likely` or `confirmed`.

## Verdict

Compute after questions are answered and fixes are applied and re-checked:

1. **BLOCKED**: at least one `critical` or `high` finding is not `fixed` or `false_positive`.
   In `--non-interactive` mode, unanswered questions leave findings `open`, so a
   suspected critical/high blocks (fail closed).
2. **PASS WITH WARNINGS**: no unresolved critical/high, but at least one
   `medium` or `low` finding is not `fixed` or `false_positive`.
3. **PASS**: nothing unresolved except `info`.

Scanner results that agents disproved don't count. Scanners that didn't run
don't change the verdict, but the report must list them as "not run".

## Overriding a block

Only the developer can override, and only with a written reason:

1. Show the blocking findings again and ask whether they want to override.
2. Require a reason in their own words (at least one full sentence; the stamp
   script rejects fewer than 15 characters). "ok", "later", "n/a" are not reasons:
   ask again.
3. Record it with `devsecops-review finalize --verdict BLOCKED --override-reason "<reason>"`.
   The verdict becomes `OVERRIDDEN`, the push gate opens, and a
   `block_overridden` event with the reason and the blocking counts is logged.
4. Never suggest an override yourself, and never override in `--non-interactive` mode.
