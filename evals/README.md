# devsecops-reviewer evaluation suite

Measures how well the plugin finds the vulnerabilities it should, and how well
it leaves safe code alone. **Not shipped to developers** — it lives in the
marketplace repo, outside `plugins/devsecops-reviewer/`, so the deliberately
vulnerable fixtures never reach anyone's machine on install.

> ⚠️ **Every file under `fixtures/` is deliberately insecure test code. Never
> deploy, serve, or run it against real data.** All "secrets" are fake strings.

## Layout

```
evals/
├── fixtures/          deliberately vulnerable sample apps + clean lookalikes
│   ├── python-flask/     Flask: SQLi, cmd inj, SSTI, path traversal, pickle,
│   │                     open redirect, md5 pw, secret key, debug, missing authz
│   ├── node-express/     Express: XSS, NoSQLi, cmd inj, JWT-not-verified, IDOR,
│   │                     mass assignment, open redirect, CORS, logic (price), deps
│   ├── php-app/          PHP: SQLi, LFI, XSS, cmd inj, unserialize, md5, upload,
│   │                     secrets, default creds, debug
│   └── java-spring/      Spring: SQLi, path traversal, SSRF, XXE, deserialization,
│                         missing authz, secrets, actuator exposure, deps
├── expected/          <fixture>.json: the findings each fixture should yield
├── results/           <timestamp>/report.md + actual/ + transcripts/ (git-ignored)
├── run-evals.sh       runs the review on each fixture, then scores
└── score.py          matches actual vs expected; recall/precision/false positives
```

Each fixture also contains **clean files** (`safe.*`) that look risky but are
safe (parameterized queries, escaped output, allowlisted commands). A finding on
a clean file is a false positive.

## Run

```bash
bash run-evals.sh                                  # all fixtures
bash run-evals.sh --fixture python-flask --keep    # one fixture, keep its work dir
bash run-evals.sh --model sonnet                   # pick the model for the review
```

Requires `claude`, `git` and `python3`. For each fixture the script copies it to
a throwaway git repo under `results/<ts>/work/`, runs
`/devsecops-reviewer:security-review --all --non-interactive` with only this
plugin loaded, copies the produced `.security-review/reports/<id>.json` to
`results/<ts>/actual/<fixture>.json`, and finally runs `score.py`.

A full cold run is slow (each fixture is a fresh multi-agent review, ~5–10 min).

## Scoring

`score.py` pairs a reported finding with an expected one when: **same file**,
**overlapping line range**, **same category group** (e.g. `idor` counts for
`authz`; see `GROUPS` in the script / the groups in
`skills/security-review/finding-schema.md`), and **reported severity ≥ the
expected `min_severity`**. It reports, per fixture and per category:

- **recall** = expected findings found / expected findings
- **precision** = reported findings that matched an expected / reported findings (informational)
- **clean-file false positives** = findings on `safe.*` files

### Pass threshold

- overall recall **≥ 80%**, and
- no category group below **60%**, and
- clean-file false positives **≤ 20%** of reported findings.

`score.py` exits non-zero if any threshold fails, so CI can gate on it.
Dependency findings depend on a dependency scanner being installed; when none
is, `run-evals.sh` passes `--no-scanners` and those expected findings are
excluded from scoring.

## Adding a fixture

1. Create `fixtures/<name>/` with the vulnerable files and at least one
   `safe.*` clean file. Add the big **do-not-deploy** warning to its README.
2. Keep each vulnerability on a stable, identifiable line; after writing, read
   the file back and note the line numbers.
3. Write `expected/<name>.json`: `fixture`, `clean_files`, and an `expected`
   array of `{name, file, line_start, line_end, category, min_severity, notes}`.
   Mark dependency entries with `"scanner_dependent": true`.
4. Use category keys from `skills/security-review/finding-schema.md`.

Do **not** put expectation hints (e.g. `# VULN here`) in fixture code — the
reviewer agents read it, and that would contaminate the measurement.
