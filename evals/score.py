#!/usr/bin/env python3
"""Score devsecops-reviewer eval runs: match reported findings against expected
findings and report recall, precision and clean-file false positives.

A reported finding MATCHES an expected finding when all hold:
  - same file (repo-relative path),
  - line ranges overlap (inclusive),
  - same category group (see GROUPS; so `idor` matches `authz`, etc.),
  - reported severity >= the expected `min_severity`.

Usage:
  score.py --expected <dir> --actual <dir> [--out <report.md>] [--no-scanners]
           [--recall-threshold 0.8] [--category-floor 0.6] [--fp-threshold 0.2]

<actual> holds one <fixture>.json per fixture: either the plugin's report
(an object with a "findings" array) or a bare array of findings. Exit 0 if the
suite passes the thresholds, 1 otherwise, 2 on a usage/IO error.
"""
import argparse
import glob
import json
import os
import sys

# Keep output portable on the Windows console (cp1252 can't encode some chars).
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Category groups: a reported finding counts for an expected one in the same
# group. Mirrors finding-schema.md.
GROUPS = {
    "sqli": "injection", "nosqli": "injection", "command-injection": "injection",
    "ldap-injection": "injection", "template-injection": "injection", "code-injection": "injection",
    "xss": "xss",
    "path-traversal": "path-traversal",
    "ssrf": "ssrf",
    "open-redirect": "open-redirect",
    "xxe": "xxe",
    "deserialization": "deserialization",
    "file-upload": "file-upload",
    "authn": "authn", "session-jwt": "authn",
    "password-storage": "crypto", "weak-crypto": "crypto",
    "authz": "authz", "idor": "authz", "privilege-escalation": "authz",
    "mass-assignment": "authz", "csrf": "authz",
    "business-logic": "logic", "race-condition": "logic", "client-trust": "logic",
    "input-validation": "logic",
    "debug-mode": "misconfiguration", "cors": "misconfiguration", "cookies": "misconfiguration",
    "security-headers": "misconfiguration", "default-credentials": "misconfiguration",
    "misconfiguration": "misconfiguration",
    "secrets": "secrets",
    "vulnerable-dependency": "dependency", "typosquatting": "dependency",
    "sensitive-logging": "logging", "info-exposure": "logging",
    "other": "other",
}


def group(cat):
    return GROUPS.get((cat or "").strip().lower(), (cat or "").strip().lower())


def norm_path(p):
    return (p or "").replace("\\", "/").lstrip("./").strip()


def sev_rank(s):
    return SEV.get((s or "").strip().lower(), 0)


def overlaps(a0, a1, b0, b1):
    try:
        return int(a0) <= int(b1) and int(b0) <= int(a1)
    except (TypeError, ValueError):
        return False


def load_findings(obj):
    """Accept a plugin report object or a bare findings array."""
    if isinstance(obj, dict):
        items = obj.get("findings", [])
    elif isinstance(obj, list):
        items = obj
    else:
        items = []
    out = []
    for f in items:
        if not isinstance(f, dict):
            continue
        cat = f.get("category")
        if isinstance(cat, dict):
            cat = cat.get("key")
        out.append({
            "file": norm_path(f.get("file")),
            "l0": f.get("line_start", f.get("line", 0)),
            "l1": f.get("line_end", f.get("line_start", f.get("line", 0))),
            "cat": cat,
            "group": group(cat),
            "sev": (f.get("severity") or "").lower(),
            "id": f.get("id", ""),
        })
    return out


# Which dependency scanner covers each ecosystem. osv-scanner covers all of
# them; the others are ecosystem-specific. A scanner_dependent expected finding
# is only graded when a scanner that could actually find it is installed.
_ECOSYSTEM_SCANNER = {
    "js": "npm", "python": "pip-audit", "php": "composer",
    # maven/gradle/go/rust/ruby have no stand-alone scanner in the runner's
    # probe list, so they are only reachable via osv-scanner.
}


def ecosystem_of(path):
    p = path.lower()
    base = p.rsplit("/", 1)[-1]
    if base in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
        return "js"
    if base in ("requirements.txt", "pipfile", "pipfile.lock", "pyproject.toml",
                "poetry.lock") or base.startswith("requirements"):
        return "python"
    if base in ("composer.json", "composer.lock"):
        return "php"
    if base in ("pom.xml", "build.gradle", "build.gradle.kts"):
        return "maven"
    if base in ("go.mod", "go.sum"):
        return "go"
    if base in ("cargo.toml", "cargo.lock"):
        return "rust"
    if base in ("gemfile", "gemfile.lock"):
        return "ruby"
    return "unknown"


def scanner_dependent_scorable(path, installed):
    """True if a scanner that could find a dep issue in this file is installed."""
    if "osv-scanner" in installed:
        return True
    eco = ecosystem_of(path)
    needed = _ECOSYSTEM_SCANNER.get(eco)
    return bool(needed and needed in installed)


def score_fixture(expected, reported, installed):
    exp = expected.get("expected", [])
    exp = [e for e in exp
           if not e.get("scanner_dependent")
           or scanner_dependent_scorable(e.get("file", ""), installed)]
    clean = {norm_path(c) for c in expected.get("clean_files", [])}

    matched_exp = []
    used = set()
    for e in exp:
        ef, e0, e1 = norm_path(e["file"]), e["line_start"], e["line_end"]
        eg = group(e["category"])
        floor = sev_rank(e.get("min_severity", "low"))
        hit = None
        for i, r in enumerate(reported):
            if i in used:
                continue
            if r["file"] == ef and r["group"] == eg and \
               overlaps(e0, e1, r["l0"], r["l1"]) and sev_rank(r["sev"]) >= floor:
                hit = i
                break
        if hit is not None:
            used.add(hit)
        matched_exp.append((e, hit is not None))

    # Precision: reported findings (>= low) that matched an expected.
    considered = [r for r in reported if sev_rank(r["sev"]) >= 1]
    correct = len(used)
    precision = correct / len(considered) if considered else 1.0

    # False positives on clean files (any reported finding >= low on a clean file).
    fp_clean = [r for r in considered if r["file"] in clean]

    # Per-category recall.
    per_cat = {}
    for e, ok in matched_exp:
        g = group(e["category"])
        per_cat.setdefault(g, [0, 0])
        per_cat[g][1] += 1
        if ok:
            per_cat[g][0] += 1

    found = sum(1 for _, ok in matched_exp if ok)
    return {
        "expected": len(exp),
        "found": found,
        "recall": found / len(exp) if exp else 1.0,
        "reported": len(considered),
        "precision": precision,
        "fp_clean": len(fp_clean),
        "fp_clean_detail": [(r["file"], r["cat"], r["sev"], r["id"]) for r in fp_clean],
        "per_cat": per_cat,
        "misses": [e for e, ok in matched_exp if not ok],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--expected", required=True)
    ap.add_argument("--actual", required=True)
    ap.add_argument("--out")
    ap.add_argument("--no-scanners", action="store_true",
                    help="no dependency scanner installed: ignore all scanner_dependent findings")
    ap.add_argument("--installed-scanners", default="",
                    help="comma list of installed dependency scanners (osv-scanner,npm,pip-audit,composer). "
                         "A scanner_dependent finding is graded only when a scanner covering its ecosystem is present.")
    ap.add_argument("--recall-threshold", type=float, default=0.8)
    ap.add_argument("--category-floor", type=float, default=0.6)
    ap.add_argument("--fp-threshold", type=float, default=0.2)
    args = ap.parse_args()

    installed = set() if args.no_scanners else {
        s.strip() for s in args.installed_scanners.split(",") if s.strip()
    }

    results = {}
    for ef in sorted(glob.glob(os.path.join(args.expected, "*.json"))):
        name = os.path.splitext(os.path.basename(ef))[0]
        with open(ef, encoding="utf-8") as fh:
            expected = json.load(fh)
        af = os.path.join(args.actual, name + ".json")
        if not os.path.exists(af):
            results[name] = {"error": "no actual output", "expected": len(expected.get("expected", [])),
                             "found": 0, "recall": 0.0, "reported": 0, "precision": 0.0,
                             "fp_clean": 0, "fp_clean_detail": [], "per_cat": {}, "misses": expected.get("expected", [])}
            continue
        try:
            with open(af, encoding="utf-8") as fh:
                reported = load_findings(json.load(fh))
        except (ValueError, OSError) as e:
            results[name] = {"error": "unreadable actual: %s" % e, "expected": len(expected.get("expected", [])),
                             "found": 0, "recall": 0.0, "reported": 0, "precision": 0.0,
                             "fp_clean": 0, "fp_clean_detail": [], "per_cat": {}, "misses": []}
            continue
        results[name] = score_fixture(expected, reported, installed)

    # Aggregate.
    tot_exp = sum(r["expected"] for r in results.values())
    tot_found = sum(r["found"] for r in results.values())
    tot_rep = sum(r["reported"] for r in results.values())
    tot_correct = sum(round(r["precision"] * r["reported"]) for r in results.values())
    tot_fp = sum(r["fp_clean"] for r in results.values())
    overall_recall = tot_found / tot_exp if tot_exp else 0.0
    overall_prec = tot_correct / tot_rep if tot_rep else 1.0
    fp_rate = tot_fp / tot_rep if tot_rep else 0.0

    cat_agg = {}
    for r in results.values():
        for g, (f, e) in r.get("per_cat", {}).items():
            cat_agg.setdefault(g, [0, 0])
            cat_agg[g][0] += f
            cat_agg[g][1] += e
    worst_cat = min((f / e for f, e in cat_agg.values() if e), default=1.0)

    passed = (overall_recall >= args.recall_threshold and
              worst_cat >= args.category_floor and
              fp_rate <= args.fp_threshold)

    lines = []
    lines.append("# devsecops-reviewer eval results")
    lines.append("")
    lines.append("Verdict: **%s**" % ("PASS" if passed else "FAIL"))
    lines.append("")
    lines.append("| Metric | Value | Threshold |")
    lines.append("| :- | :- | :- |")
    lines.append("| Overall recall | %.0f%% (%d/%d) | >= %.0f%% |" % (overall_recall * 100, tot_found, tot_exp, args.recall_threshold * 100))
    lines.append("| Worst category recall | %.0f%% | >= %.0f%% |" % (worst_cat * 100, args.category_floor * 100))
    lines.append("| Clean-file false positives | %.0f%% (%d/%d) | <= %.0f%% |" % (fp_rate * 100, tot_fp, tot_rep, args.fp_threshold * 100))
    lines.append("| Overall precision (informational) | %.0f%% | - |" % (overall_prec * 100))
    if args.no_scanners or not installed:
        lines.append("")
        lines.append("_Scanner-dependent dependency findings excluded: no dependency scanner installed._")
    else:
        lines.append("")
        lines.append("_Installed dependency scanners: %s. Scanner-dependent findings are graded only for ecosystems these cover (osv-scanner covers all)._" % ", ".join(sorted(installed)))
    lines.append("")
    lines.append("## Per fixture")
    lines.append("")
    lines.append("| Fixture | Recall | Precision | Clean FPs | Notes |")
    lines.append("| :- | :- | :- | :- | :- |")
    for name, r in results.items():
        note = r.get("error", "")
        lines.append("| %s | %.0f%% (%d/%d) | %.0f%% | %d | %s |" % (
            name, r["recall"] * 100, r["found"], r["expected"], r["precision"] * 100, r["fp_clean"], note))
    lines.append("")
    lines.append("## Per category (recall)")
    lines.append("")
    lines.append("| Category group | Recall |")
    lines.append("| :- | :- |")
    for g in sorted(cat_agg):
        f, e = cat_agg[g]
        flag = "" if e and f / e < args.category_floor else ""
        lines.append("| %s | %.0f%% (%d/%d)%s |" % (g, (f / e * 100) if e else 100, f, e, flag))
    lines.append("")
    # Misses and false positives for debugging.
    for name, r in results.items():
        if r.get("misses") or r.get("fp_clean_detail"):
            lines.append("### %s" % name)
            for m in r.get("misses", []):
                lines.append("- MISSED: %s %s %s:%s-%s (min %s)" % (
                    m.get("name", ""), m["category"], m["file"], m["line_start"], m["line_end"], m.get("min_severity")))
            for f, c, s, i in r.get("fp_clean_detail", []):
                lines.append("- FALSE POSITIVE on clean file: %s [%s/%s] %s" % (f, c, s, i))
            lines.append("")

    report = "\n".join(lines)
    print(report)
    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        sys.stderr.write("\nWrote %s\n" % args.out)

    return 0 if passed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
