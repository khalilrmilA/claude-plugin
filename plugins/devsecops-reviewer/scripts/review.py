#!/usr/bin/env python3
"""Deterministic half of the devsecops-reviewer security review.

The orchestrator skill and the reviewer agents do the judgement. This script
does the bookkeeping that should not depend on a model retyping JSON: capturing
agent output, merging findings, applying verifier rulings, computing the
verdict and rendering the report.

Run it through `devsecops-review` (scripts/review.sh), which changes to the
repository root first; every path here is relative to that root.
Standard library only, Python 3.8+.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys

for _stream in (sys.stdout, sys.stderr):
    try:  # the Windows console defaults to cp1252, which can't print everything
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

PLUGIN = "devsecops-reviewer"
STATE = ".security-review"
P_SCOPE = STATE + "/scope/scope.json"
P_FILES = STATE + "/scope/files.txt"
P_STACK = STATE + "/stack.json"
P_SCANS = STATE + "/scans/summary.json"
P_AGENTS = STATE + "/agents"
P_FINDINGS = STATE + "/findings.json"
P_VERIFICATION = STATE + "/verification.json"
P_SURFACES = STATE + "/surfaces.json"
P_LEDGER = STATE + "/coverage-ledger.md"
P_CONTEXT = STATE + "/context-map.md"
P_REPORTS = STATE + "/reports"
P_RESULT = STATE + "/report-result.txt"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CONFIDENCES = ["confirmed", "likely", "needs_validation", "suspected"]
STATUSES = ["open", "fixed", "false_positive", "accepted_risk", "will_fix_later"]
RESOLVED = ("fixed", "false_positive")
VERIFIER = "finding-verifier"

# category key -> (group, OWASP reference, default CWE). The group is what the
# eval scorer and the duplicate check compare; evals/score.py mirrors it.
CATEGORIES = {
    "sqli": ("injection", "A05:2025-Injection", "CWE-89"),
    "nosqli": ("injection", "A05:2025-Injection", "CWE-943"),
    "command-injection": ("injection", "A05:2025-Injection", "CWE-78"),
    "ldap-injection": ("injection", "A05:2025-Injection", "CWE-90"),
    "template-injection": ("injection", "A05:2025-Injection", "CWE-1336"),
    "code-injection": ("injection", "A05:2025-Injection", "CWE-94"),
    "xss": ("xss", "A05:2025-Injection", "CWE-79"),
    "path-traversal": ("path-traversal", "A01:2025-Broken Access Control", "CWE-22"),
    "ssrf": ("ssrf", "A01:2025-Broken Access Control", "CWE-918"),
    "open-redirect": ("open-redirect", "A01:2025-Broken Access Control", "CWE-601"),
    "xxe": ("xxe", "A02:2025-Security Misconfiguration", "CWE-611"),
    "deserialization": ("deserialization", "A08:2025-Software or Data Integrity Failures", "CWE-502"),
    "file-upload": ("file-upload", "A06:2025-Insecure Design", "CWE-434"),
    "authn": ("authn", "A07:2025-Authentication Failures", "CWE-287"),
    "session-jwt": ("authn", "A07:2025-Authentication Failures", "CWE-347"),
    "password-storage": ("crypto", "A04:2025-Cryptographic Failures", "CWE-916"),
    "weak-crypto": ("crypto", "A04:2025-Cryptographic Failures", "CWE-327"),
    "authz": ("authz", "A01:2025-Broken Access Control", "CWE-862"),
    "idor": ("authz", "A01:2025-Broken Access Control", "CWE-639"),
    "privilege-escalation": ("authz", "A01:2025-Broken Access Control", "CWE-269"),
    "mass-assignment": ("authz", "A08:2025-Software or Data Integrity Failures", "CWE-915"),
    "csrf": ("authz", "A01:2025-Broken Access Control", "CWE-352"),
    "business-logic": ("logic", "A06:2025-Insecure Design", "CWE-840"),
    "race-condition": ("logic", "A06:2025-Insecure Design", "CWE-362"),
    "client-trust": ("logic", "A06:2025-Insecure Design", "CWE-602"),
    "input-validation": ("logic", "A06:2025-Insecure Design", "CWE-20"),
    "error-handling": ("logic", "A10:2025-Mishandling of Exceptional Conditions", "CWE-636"),
    "debug-mode": ("misconfiguration", "A02:2025-Security Misconfiguration", "CWE-489"),
    "cors": ("misconfiguration", "A02:2025-Security Misconfiguration", "CWE-942"),
    "cookies": ("misconfiguration", "A02:2025-Security Misconfiguration", "CWE-614"),
    "security-headers": ("misconfiguration", "A02:2025-Security Misconfiguration", "CWE-693"),
    "default-credentials": ("misconfiguration", "A07:2025-Authentication Failures", "CWE-1392"),
    "misconfiguration": ("misconfiguration", "A02:2025-Security Misconfiguration", "CWE-16"),
    "secrets": ("secrets", "A07:2025-Authentication Failures", "CWE-798"),
    "vulnerable-dependency": ("dependency", "A03:2025-Software Supply Chain Failures", "CWE-1395"),
    "typosquatting": ("dependency", "A03:2025-Software Supply Chain Failures", "CWE-1357"),
    "dependency-confusion": ("dependency", "A03:2025-Software Supply Chain Failures", "CWE-427"),
    "ci-workflow": ("supply-chain", "A03:2025-Software Supply Chain Failures", "CWE-829"),
    "build-integrity": ("supply-chain", "A08:2025-Software or Data Integrity Failures", "CWE-494"),
    "iam": ("cloud", "A01:2025-Broken Access Control", "CWE-732"),
    "network-exposure": ("cloud", "A02:2025-Security Misconfiguration", "CWE-668"),
    "container-security": ("cloud", "A02:2025-Security Misconfiguration", "CWE-250"),
    "prompt-injection": ("ai", "LLM01:2025-Prompt Injection", "CWE-1427"),
    "insecure-output-handling": ("ai", "LLM05:2025-Improper Output Handling", "CWE-1426"),
    "excessive-agency": ("ai", "LLM06:2025-Excessive Agency", "CWE-441"),
    "context-leak": ("ai", "LLM02:2025-Sensitive Information Disclosure", "CWE-200"),
    "sensitive-logging": ("logging", "A09:2025-Security Logging and Alerting Failures", "CWE-532"),
    "info-exposure": ("logging", "A01:2025-Broken Access Control", "CWE-200"),
    "other": ("other", "", ""),
}

AGENT_PREFIX = {
    "injection-reviewer": "INJ",
    "auth-reviewer": "AUTH",
    "logic-reviewer": "LOGIC",
    "config-secrets-reviewer": "CFG",
    "crypto-reviewer": "CRYPTO",
    "dependency-reviewer": "DEP",
    "supply-chain-reviewer": "SUP",
    "cloud-reviewer": "CLOUD",
    "ai-llm-reviewer": "AI",
}

# Token shapes that are secrets with near certainty. A safety net behind the
# agents' own masking: nothing matching these reaches a report unmasked.
SECRET_PATTERNS = [re.compile(p) for p in (
    r"A[KS]IA[0-9A-Z]{16}",
    r"gh[pousr]_[0-9A-Za-z]{30,}",
    r"github_pat_[0-9A-Za-z_]{40,}",
    r"glpat-[0-9A-Za-z_-]{20,}",
    r"AIza[0-9A-Za-z_-]{30,}",
    r"xox[baprs]-[0-9A-Za-z-]{10,}",
    r"[sr]k_live_[0-9A-Za-z]{16,}",
    r"sk-ant-[0-9A-Za-z_-]{20,}",
    r"sk-(?:proj-)?[0-9A-Za-z_-]{32,}",
    r"npm_[0-9A-Za-z]{30,}",
    r"pypi-[0-9A-Za-z_-]{40,}",
    r"SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}",
    r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
)]
PRIVATE_KEY_RE = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)")


class Fail(Exception):
    """A user-facing error: message on stderr, non-zero exit, no traceback."""

    def __init__(self, message, code=2):
        Exception.__init__(self, message)
        self.code = code


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_text(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return default


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.load(fh, strict=False)
    except (OSError, ValueError):
        return default


def write_text(path, text):
    """Write through a temp file so a crash never leaves a half-written file."""
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)


def write_json(path, obj):
    write_text(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def as_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def as_int(value, default=0):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def norm_path(path):
    """Repo-relative path with forward slashes."""
    p = as_text(path).strip().strip("`'\"").replace("\\", "/")
    root = os.getcwd().replace("\\", "/").rstrip("/")
    if p.lower().startswith(root.lower() + "/"):
        p = p[len(root) + 1:]
    while p.startswith("./"):
        p = p[2:]
    return p


def mask_secrets(text):
    if not text or not isinstance(text, str):
        return text
    text = PRIVATE_KEY_RE.sub(lambda m: m.group(1) + " **** (masked)", text)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m: m.group(0)[:4] + "****", text)
    return text


def sev_rank(sev):
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def conf_rank(conf):
    return CONFIDENCES.index(conf) if conf in CONFIDENCES else len(CONFIDENCES)


def category_of(finding):
    cat = finding.get("category")
    if isinstance(cat, dict):
        return as_text(cat.get("key"))
    return as_text(cat)


def group_of(key):
    return CATEGORIES.get(key, (key, "", ""))[0]


def sort_key(finding):
    resolved = 1 if finding.get("status") in RESOLVED else 0
    return (resolved, sev_rank(finding.get("severity")), conf_rank(finding.get("confidence")),
            finding.get("file", ""), as_int(finding.get("line_start")))


def location(finding):
    start, end = as_int(finding.get("line_start")), as_int(finding.get("line_end"))
    path = finding.get("file", "")
    if start and end and end != start:
        return "%s:%d-%d" % (path, start, end)
    if start:
        return "%s:%d" % (path, start)
    return path


def short_agent(name):
    name = as_text(name).strip()
    if name.startswith(PLUGIN + ":"):
        name = name[len(PLUGIN) + 1:]
    return name


def clip(text, limit):
    text = " ".join(as_text(text).split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


# --------------------------------------------------------------------------
# telemetry: lines for scripts/log-event.sh --batch, written by the wrapper
# --------------------------------------------------------------------------

_EVENTS = []


def event(name, **fields):
    parts = [name]
    for key, value in fields.items():
        if value is None:
            continue
        if isinstance(value, bool):
            parts.append("%s:=%s" % (key, "true" if value else "false"))
        elif isinstance(value, int):
            parts.append("%s:=%d" % (key, value))
        else:
            text = " ".join(as_text(value).split())
            parts.append("%s=%s" % (key, text[:300]))
    _EVENTS.append("\t".join(parts))


def flush_events():
    target = os.environ.get("DSR_EVENTS_OUT")
    if target and _EVENTS:
        try:
            with open(target, "a", encoding="utf-8", newline="\n") as fh:
                fh.write("\n".join(_EVENTS) + "\n")
        except OSError:
            pass  # telemetry must never fail the review
    del _EVENTS[:]


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

def load_scope():
    scope = read_json(P_SCOPE)
    if not isinstance(scope, dict):
        raise Fail("no review in progress here: run `devsecops-review prepare` first", 3)
    return scope


def new_doc(review_id):
    return {
        "schema_version": 2,
        "review_id": review_id,
        "updated_at": now_iso(),
        "agents": [],
        "expected_agents": [],
        "missing_agents": [],
        "findings": [],
        "merged_duplicates": [],
        "questions": [],
        "disproved_scanner_findings": [],
        "unreviewed_files": [],
        "coverage_gaps": [],
        "verification": {"applied_files": [], "kept": 0, "dropped": 0, "adjusted": 0,
                         "observations": []},
    }


def load_doc(required=True):
    scope = load_scope()
    doc = read_json(P_FINDINGS)
    if not isinstance(doc, dict) or doc.get("review_id") != scope.get("review_id"):
        if required:
            raise Fail("no findings collected for this review yet: run "
                       "`devsecops-review findings collect` first", 3)
        doc = new_doc(scope.get("review_id", ""))
    base = new_doc(doc.get("review_id", ""))
    for key, value in base.items():
        doc.setdefault(key, value)
    return doc


def save_doc(doc):
    doc["updated_at"] = now_iso()
    write_json(P_FINDINGS, doc)


def find_finding(doc, finding_id):
    wanted = finding_id.strip().upper()
    for finding in doc["findings"]:
        if finding.get("id", "").upper() == wanted:
            return finding
    for merged in doc.get("merged_duplicates", []):
        if merged.get("id", "").upper() == wanted:
            raise Fail("%s was merged into %s as a duplicate; use that id" %
                       (finding_id, merged.get("into")))
    raise Fail("no finding with id %s (see `devsecops-review findings list`)" % finding_id)


def parse_kv(items):
    """Split ['A-1', 'B-2', 'k=v', ...] into (ids, {k: v})."""
    ids, fields = [], {}
    for item in items:
        if "=" in item and re.match(r"^[A-Za-z_][A-Za-z0-9_-]*=", item):
            key, value = item.split("=", 1)
            fields[key.strip().lower().replace("-", "_")] = value.strip()
        else:
            ids.append(item)
    return ids, fields


def add_note(finding, note):
    note = mask_secrets(" ".join(as_text(note).split()))
    if not note:
        return
    current = finding.get("resolution_note", "")
    finding["resolution_note"] = (current + " | " + note) if current else note


# --------------------------------------------------------------------------
# envelopes: extract, validate, load
# --------------------------------------------------------------------------

FENCE_RE = re.compile(r"```[ \t]*(?:json|JSON)?[ \t]*\r?\n(.*?)\r?\n[ \t]*```", re.S)


def _is_envelope(obj):
    return isinstance(obj, dict) and ("findings" in obj or "verifications" in obj)


def extract_envelope(text):
    """Return (envelope, error). Takes the last fenced json block that parses
    into an envelope; falls back to the outermost braces."""
    text = as_text(text)
    errors = []
    candidates = [m.group(1) for m in FENCE_RE.finditer(text)]
    marker = max(text.rfind("```json"), text.rfind("```JSON"))
    if marker != -1:
        start, end = text.find("{", marker), text.rfind("}")
        if start != -1 and end > start:
            candidates.insert(0, text[start:end + 1])  # tried last
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        candidates.insert(0, text[start:end + 1])
    for raw in reversed(candidates):
        try:
            obj = json.loads(raw, strict=False)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if _is_envelope(obj):
            return obj, None
        errors.append("the JSON block has no \"findings\" (or \"verifications\") array")
    if not candidates:
        return None, "no JSON block found in the reply"
    return None, errors[0] if errors else "no JSON envelope found"


def validate_envelope(env):
    """Problems worth one corrective round trip. Empty list = good enough."""
    problems = []
    if "verifications" in env and "findings" not in env:
        rulings = env.get("verifications")
        if not isinstance(rulings, list):
            return ["\"verifications\" must be an array"]
        for i, ruling in enumerate(rulings, 1):
            if not isinstance(ruling, dict):
                problems.append("verifications[%d] is not an object" % i)
                continue
            who = as_text(ruling.get("id")) or "verifications[%d]" % i
            if not ruling.get("id"):
                problems.append("%s: missing id" % who)
            if as_text(ruling.get("verdict")).strip().lower() not in ("keep", "drop", "adjust"):
                problems.append("%s: verdict must be keep, drop or adjust" % who)
            for field, allowed in (("severity_out", SEVERITIES), ("confidence_out", CONFIDENCES)):
                value = as_text(ruling.get(field)).strip().lower()
                if value and value not in allowed:
                    problems.append("%s: %s '%s' is not one of %s" %
                                    (who, field, value, "|".join(allowed)))
        return problems
    findings = env.get("findings")
    if not isinstance(findings, list):
        return ["\"findings\" must be an array (use [] when there is nothing to report)"]
    for i, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            problems.append("findings[%d] is not an object" % i)
            continue
        who = as_text(finding.get("id")) or "findings[%d]" % i
        if not as_text(finding.get("title")).strip():
            problems.append("%s: missing title" % who)
        if as_text(finding.get("severity")).strip().lower() not in SEVERITIES:
            problems.append("%s: severity must be one of %s" % (who, "|".join(SEVERITIES)))
        if as_text(finding.get("confidence")).strip().lower() not in CONFIDENCES:
            problems.append("%s: confidence must be one of %s" % (who, "|".join(CONFIDENCES)))
        if not category_of(finding).strip():
            problems.append("%s: missing category.key" % who)
        if not as_text(finding.get("file")).strip():
            problems.append("%s: missing file" % who)
        if as_int(finding.get("line_start")) < 1:
            problems.append("%s: line_start must be a line number from the file" % who)
        if not as_text(finding.get("attack_scenario")).strip():
            problems.append("%s: missing attack_scenario" % who)
    return problems


def load_envelopes():
    """Every envelope saved under agents/: hook captures and hand-saved files."""
    out = []
    try:
        names = sorted(os.listdir(P_AGENTS))
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json"):
            continue
        data = read_json(os.path.join(P_AGENTS, name))
        if not isinstance(data, dict):
            out.append({"file": name, "error": "not valid JSON"})
            continue
        if isinstance(data.get("envelope"), dict):
            env, agent = data["envelope"], data.get("agent")
            agent_id, source = data.get("agent_id", ""), data.get("source", "hook")
        else:
            env, agent, agent_id, source = data, None, "", "manual"
        if not _is_envelope(env):
            out.append({"file": name, "error": "no findings or verifications array"})
            continue
        agent = short_agent(agent or env.get("agent") or name.split("--")[0].replace(".json", ""))
        out.append({"file": name, "agent": agent, "agent_id": agent_id,
                    "source": source, "envelope": env})
    return out


# --------------------------------------------------------------------------
# capture: called from the SubagentStop / SubagentHandback hooks
# --------------------------------------------------------------------------

RETRY_HELP = (
    "Your reply could not be used as it stands: %s. End your reply with exactly one "
    "fenced ```json block holding the envelope from your instructions (valid JSON: "
    "double-quoted keys and strings, newlines inside strings written as \\n, no "
    "trailing commas). Send the corrected block now; you do not need to repeat the "
    "analysis.")


def cmd_capture(_args):
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8", "replace"), strict=False)
    except ValueError:
        return 0
    if not isinstance(payload, dict):
        return 0
    agent_type = as_text(payload.get("agent_type"))
    if not agent_type.startswith(PLUGIN + ":"):
        return 0
    hook = payload.get("hook_event_name")
    if hook == "SubagentStop":
        message = as_text(payload.get("last_assistant_message"))
    elif payload.get("tool_name") == "SubagentHandback":
        message = as_text((payload.get("tool_input") or {}).get("message"))
    else:
        return 0
    scope = read_json(P_SCOPE)
    if not isinstance(scope, dict):
        return 0  # no review in progress in this repository

    agent = short_agent(agent_type)
    agent_id = re.sub(r"[^A-Za-z0-9_-]", "", as_text(payload.get("agent_id")))[:48] or "x"
    dest = "%s/%s--%s.json" % (P_AGENTS, agent, agent_id)
    raw_dest = "%s/%s--%s.raw.md" % (P_AGENTS, agent, agent_id)
    had_capture = os.path.exists(dest)

    env, error = extract_envelope(message) if message.strip() else (None, "the reply was empty")
    problems = validate_envelope(env) if env is not None else [error]
    if env is not None:
        write_json(dest, {"source": "hook", "agent": agent, "agent_id": agent_id,
                          "review_id": scope.get("review_id", ""), "captured_at": now_iso(),
                          "problems": problems, "envelope": env})
        if os.path.exists(raw_dest):
            os.remove(raw_dest)
    elif not had_capture and message.strip():
        write_text(raw_dest, message)

    # Telemetry (agent_completed) is handled by hook-log.sh; capture only saves
    # the envelope and, at most once, asks a specialist to resend malformed JSON.
    # The retry is guarded by stop_hook_active so it can never loop.
    if hook == "SubagentStop" and problems and not payload.get("stop_hook_active") \
            and not (had_capture and env is None):
        shown = "; ".join(problems[:6]) + ("; ..." if len(problems) > 6 else "")
        sys.stdout.write(json.dumps({"decision": "block", "reason": RETRY_HELP % shown}))
    return 0


# --------------------------------------------------------------------------
# surfaces: classify the scope and suggest agents (the coverage ledger)
# --------------------------------------------------------------------------

BINARY_EXT = set("""png jpg jpeg gif bmp ico webp avif tiff pdf zip gz tgz bz2 xz 7z rar tar jar war
ear class exe dll so dylib a o obj lib bin dat db sqlite woff woff2 ttf otf eot mp3 mp4 mov avi mkv
wav flac ogg webm pyc pyo wasm iso dmg apk aab ipa psd ai sketch fig keystore jks p12 pfx""".split())
GENERATED_DIRS = set("""node_modules vendor bower_components dist build out target .next .nuxt
.venv venv env __pycache__ .terraform coverage .gradle .mvn .idea .vscode generated gen
third_party third-party .yarn .pnpm-store""".split())
LOCK_NAMES = set("""package-lock.json yarn.lock pnpm-lock.yaml poetry.lock pipfile.lock composer.lock
go.sum gemfile.lock cargo.lock packages.lock.json bun.lockb bun.lock uv.lock""".split())
MANIFEST_NAMES = LOCK_NAMES | set("""package.json pyproject.toml pipfile setup.py setup.cfg
composer.json pom.xml build.gradle build.gradle.kts settings.gradle settings.gradle.kts go.mod
gemfile cargo.toml packages.config directory.packages.props deno.json""".split())
CI_NAMES = set(""".gitlab-ci.yml jenkinsfile azure-pipelines.yml azure-pipelines.yaml
bitbucket-pipelines.yml .travis.yml .drone.yml appveyor.yml cloudbuild.yaml cloudbuild.yml
buildspec.yml buildspec.yaml""".split())
BUILD_NAMES = set("""makefile gnumakefile .dockerignore taskfile.yml taskfile.yaml justfile
.npmrc .yarnrc .yarnrc.yml .pypirc pip.conf nuget.config .gemrc .goreleaser.yml
.goreleaser.yaml""".split())
IAC_NAMES = set("""serverless.yml serverless.yaml pulumi.yaml chart.yaml values.yaml
kustomization.yaml kustomization.yml skaffold.yaml template.yaml template.yml samconfig.toml
cdk.json main.bicep""".split())
IAC_DIRS = set("""k8s kubernetes helm charts manifests deploy deployment deployments infra
infrastructure terraform cloudformation cdk pulumi ansible iac ops""".split())
TEMPLATE_EXT = set("""html htm xhtml jinja jinja2 j2 twig hbs handlebars mustache ejs pug jade erb
haml slim cshtml razor jsp jspx ftl vm vue svelte astro liquid njk""".split())
CLIENT_EXT = {"jsx", "tsx"}
CLIENT_DIRS = set("""public static assets frontend client web ui components pages views
www""".split())
CONFIG_EXT = set("""env ini cfg conf config properties toml yaml yml json xml plist
tfvars""".split())
CONFIG_NAMES = set("""settings.py config.php web.config nginx.conf .htaccess httpd.conf
application.properties application.yml application.yaml""".split())
DOC_EXT = set("""md mdx rst txt adoc csv tsv svg css scss sass less license notice""".split())
SOURCE_EXT = set("""py js mjs cjs ts mts cts php phtml java kt kts scala groovy cs fs vb go rb rs
c cc cpp cxx h hpp hh swift m mm ex exs erl clj cljs lua pl pm sh bash zsh ps1 psm1 sql graphql
gql proto dart r jl""".split())
TEST_DIRS = set("""test tests __tests__ spec specs e2e fixtures testdata mocks __mocks__
__snapshots__ cypress playwright""".split())
TEST_NAME_RE = re.compile(
    r"(^test_.*\.py$|_test\.(go|py|rb)$|\.(test|spec)\.[cm]?[jt]sx?$|tests?\.(java|kt|cs)$|_spec\.rb$)",
    re.I)

FLAG_PATTERNS = {
    "ai-llm": re.compile(
        r"\b(anthropic|openai|langchain|langgraph|llama[_-]?index|litellm|ollama|cohere|mistralai|"
        r"generativeai|google\.genai|vertexai|bedrock[-_]?runtime|invoke_?model|semantic[_-]kernel|"
        r"autogen|crewai|haystack|huggingface_hub|modelcontextprotocol|fastmcp|mcp\.server|"
        r"@ai-sdk|pinecone|weaviate|chromadb|qdrant|pgvector|chat\.completions|messages\.create|"
        r"tool_use|tool_calls|function_call|system_prompt|prompt_template)\b", re.I),
    "crypto": re.compile(
        r"\b(hashlib|bcrypt|scrypt|argon2|pbkdf2|hmac|md5|sha1|createhash|createcipher\w*|"
        r"createhmac|randombytes|crypto\.subtle|messagedigest|cipher\.getinstance|securerandom|"
        r"javax\.crypto|openssl_\w+|password_hash|jsonwebtoken|pyjwt|jwt\.\w+|x509|"
        r"insecureskipverify|rejectunauthorized|verify\s*=\s*false|math\.random|mt_rand|uniqid|"
        r"os\.urandom|crypto/rand|math/rand|aes|rsa|ecdsa|ed25519)\b", re.I),
    "logic": re.compile(
        r"\b(price|amount|total|balance|quantity|qty|coupon|discount|voucher|payment|checkout|"
        r"refund|transfer|invoice|credit|wallet|stock|inventory|subscription|cart|purchase|charge|"
        r"payout|withdraw\w*|deposit|quota|redeem\w*)\b", re.I),
    "k8s": re.compile(r"^\s*apiVersion\s*:", re.M),
    "iam-policy": re.compile(r"AWSTemplateFormatVersion|\"Statement\"\s*:|\bStatement\s*:\s*$", re.M),
}
REVIEWABLE = ("server-code", "client-code", "template", "config", "ci", "build", "iac",
              "dependency-manifest")
SURFACE_AGENTS = [
    ("server-code", ["injection-reviewer", "auth-reviewer"]),
    ("client-code", ["injection-reviewer"]),
    ("template", ["injection-reviewer"]),
    ("config", ["config-secrets-reviewer"]),
    ("dependency-manifest", ["dependency-reviewer"]),
    ("ci", ["supply-chain-reviewer"]),
    ("build", ["supply-chain-reviewer"]),
    ("iac", ["cloud-reviewer"]),
    ("test", ["config-secrets-reviewer"]),
    ("docs/assets", ["config-secrets-reviewer"]),
    ("other", ["config-secrets-reviewer"]),
]
FLAG_AGENTS = [("ai-llm", "ai-llm-reviewer"), ("crypto", "crypto-reviewer"),
               ("logic", "logic-reviewer")]


def classify(path):
    low = path.lower()
    parts = low.split("/")
    name = parts[-1]
    folders = set(parts[:-1])
    ext = name.rsplit(".", 1)[1] if "." in name[1:] else ""
    if ext in BINARY_EXT:
        return "binary"
    if folders & GENERATED_DIRS or name.endswith((".min.js", ".min.css", ".map")):
        return "generated"
    if name in MANIFEST_NAMES or re.match(r"^requirements[^/]*\.(txt|in)$", name) \
            or ext in ("csproj", "fsproj", "vbproj"):
        return "dependency-manifest"
    if low.startswith((".github/workflows/", ".github/actions/", ".circleci/", ".buildkite/",
                       ".gitlab/ci/")) or name in CI_NAMES:
        return "ci"
    if name.startswith("dockerfile") or name.endswith(".dockerfile") or name in BUILD_NAMES \
            or re.match(r"^(docker-)?compose[^/]*\.ya?ml$", name):
        return "build"
    if ext in ("tf", "hcl", "bicep") or name in IAC_NAMES or name.endswith(".tf.json") \
            or (folders & IAC_DIRS and ext in ("yaml", "yml", "json", "tpl")):
        return "iac"
    if folders & TEST_DIRS or TEST_NAME_RE.search(name):
        return "test"
    if ext in TEMPLATE_EXT or name.endswith(".blade.php"):
        return "template"
    if ext in CLIENT_EXT or (ext in ("js", "ts", "mjs") and folders & CLIENT_DIRS):
        return "client-code"
    if ext in SOURCE_EXT:
        return "server-code"
    if ext in CONFIG_EXT or name.startswith(".env") or name in CONFIG_NAMES:
        return "config"
    if ext in DOC_EXT or name in ("license", "notice", "authors", "codeowners", ".gitignore",
                                  ".gitattributes", ".editorconfig"):
        return "docs/assets"
    return "other"


def scope_files():
    """[(status, path)] from scope/files.txt."""
    out = []
    for line in read_text(P_FILES).splitlines():
        if "\t" in line:
            status, path = line.split("\t", 1)
            out.append((status.strip(), norm_path(path)))
        elif line.strip():
            out.append(("M", norm_path(line)))
    return out


def sniff(path, limit=400000):
    try:
        if os.path.getsize(path) > limit:
            return ""
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def build_surfaces(scope):
    files = []
    sniffed = 0
    for status, path in scope_files():
        cls = classify(path)
        flags = []
        if status != "D" and cls in ("server-code", "client-code", "template", "config", "iac",
                                     "test", "other") and sniffed < 4000:
            sniffed += 1
            text = sniff(path)
            if text:
                if cls in ("config", "other") and FLAG_PATTERNS["k8s"].search(text) \
                        and re.search(r"^\s*kind\s*:", text, re.M):
                    cls = "iac"
                elif cls == "config" and FLAG_PATTERNS["iam-policy"].search(text):
                    cls = "iac"
                for flag in ("ai-llm", "crypto", "logic"):
                    if flag == "logic" and cls != "server-code":
                        continue
                    if cls in ("server-code", "client-code", "template", "config") \
                            and FLAG_PATTERNS[flag].search(text):
                        flags.append(flag)
        files.append({"path": path, "status": status, "class": cls, "flags": flags})

    live = [f for f in files if f["status"] != "D"]
    counts = {}
    for item in live:
        counts[item["class"]] = counts.get(item["class"], 0) + 1
    suggested = {}

    def suggest(agent, reason):
        suggested.setdefault(agent, [])
        if reason not in suggested[agent]:
            suggested[agent].append(reason)

    for surface, agents in SURFACE_AGENTS:
        if counts.get(surface):
            for agent in agents:
                suggest(agent, "%d %s file(s)" % (counts[surface], surface))
    if any(f["class"] == "build" and "docker" in f["path"].lower() or
           re.search(r"compose[^/]*\.ya?ml$", f["path"].lower()) for f in live):
        suggest("cloud-reviewer", "Dockerfile / compose file(s)")
    for flag, agent in FLAG_AGENTS:
        hits = [f["path"] for f in live if flag in f["flags"]]
        if hits:
            suggest(agent, "%d file(s) with %s signals, e.g. %s" % (len(hits), flag, hits[0]))
    if scope.get("mode") == "all" and counts.get("dependency-manifest", 0) == 0 and live:
        pass  # nothing to hand the dependency reviewer
    return {"review_id": scope.get("review_id", ""), "generated_at": now_iso(),
            "files": files, "surfaces": counts, "suggested_agents": suggested}


def render_ledger(surfaces, doc=None):
    """Markdown coverage ledger; with a findings doc it shows what actually ran."""
    counts = surfaces.get("surfaces", {})
    suggested = surfaces.get("suggested_agents", {})
    ran = {}
    missing = []
    if doc:
        for agent in doc.get("agents", []):
            ran[agent["agent"]] = ran.get(agent["agent"], 0) + as_int(agent.get("findings"))
        missing = doc.get("missing_agents", [])
    lines = ["# Coverage ledger (%s)" % surfaces.get("review_id", ""), "",
             "| Surface | Files | Suggested agents |", "| :- | -: | :- |"]
    by_surface = dict(SURFACE_AGENTS)
    order = [s for s, _ in SURFACE_AGENTS] + ["generated", "binary"]
    for surface in order:
        if not counts.get(surface):
            continue
        if surface in ("generated", "binary"):
            agents = "none (not assigned to reviewers; secret scanners still cover them)"
        else:
            agents = ", ".join(by_surface.get(surface, []))
        lines.append("| %s | %d | %s |" % (surface, counts[surface], agents))
    lines += ["", "## Agents", "", "| Agent | Why | Status |", "| :- | :- | :- |"]
    names = list(suggested)
    for name in list(ran) + list(missing):
        if name not in names:
            names.append(name)
    for name in names:
        why = "; ".join(suggested.get(name, [])) or "dispatched by the orchestrator"
        if name in missing:
            status = "MISSING: dispatched but returned no usable result"
        elif name in ran:
            status = "done (%d finding(s))" % ran[name]
        elif doc:
            status = "not dispatched"
        else:
            status = "suggested"
        lines.append("| %s | %s | %s |" % (name, why, status))
    if doc:
        gaps = coverage_gaps(doc)
        lines += ["", "## Coverage gaps", ""]
        lines += ["- " + gap for gap in gaps] or ["None recorded."]
        unreviewed = doc.get("unreviewed_files", [])
        if unreviewed:
            lines += ["", "## Files no reviewer listed as reviewed (%d)" % len(unreviewed), ""]
            lines += ["- `%s`" % path for path in unreviewed[:60]]
            if len(unreviewed) > 60:
                lines.append("- … and %d more" % (len(unreviewed) - 60))
    return "\n".join(lines) + "\n"


def cmd_surfaces(_args):
    scope = load_scope()
    surfaces = build_surfaces(scope)
    write_json(P_SURFACES, surfaces)
    write_text(P_LEDGER, render_ledger(surfaces))
    counts = surfaces["surfaces"]
    if not counts:
        print("Surfaces: no files in scope.")
        return 0
    print("Surfaces in scope:")
    for surface in [s for s, _ in SURFACE_AGENTS] + ["generated", "binary"]:
        if counts.get(surface):
            print("  %-20s %d" % (surface, counts[surface]))
    print("Suggested agents (a starting point; the context map decides):")
    for agent, reasons in surfaces["suggested_agents"].items():
        print("  %-26s %s" % (agent, "; ".join(reasons)))
    skipped = counts.get("generated", 0) + counts.get("binary", 0)
    if skipped:
        print("Not for reviewer agents: %d generated/vendored/binary file(s)." % skipped)
    print("Ledger: %s" % P_LEDGER)
    event("coverage_ledger_updated", surfaces=len(counts), agents=len(surfaces["suggested_agents"]),
          gaps=0)
    return 0


# --------------------------------------------------------------------------
# findings: collect, list, show, set, merge, add, fixed, reject, answer
# --------------------------------------------------------------------------

_LINE_COUNTS = {}


def line_count(path):
    if path not in _LINE_COUNTS:
        try:
            with open(path, "rb") as fh:
                _LINE_COUNTS[path] = fh.read().count(b"\n") + 1
        except OSError:
            _LINE_COUNTS[path] = -1
    return _LINE_COUNTS[path]


def normalize_finding(raw, agent, warnings):
    """A finding in canonical shape, or None when it carries nothing usable."""
    if not isinstance(raw, dict):
        return None
    origin = as_text(raw.get("id")).strip()
    who = origin or as_text(raw.get("title"))[:40] or "finding"
    title = mask_secrets(" ".join(as_text(raw.get("title")).split()))
    if not title and not as_text(raw.get("file")).strip():
        warnings.append("%s (%s): no title and no file; dropped" % (who, agent))
        return None

    key = category_of(raw).strip().lower().replace("_", "-").replace(" ", "-")
    cat = raw.get("category") if isinstance(raw.get("category"), dict) else {}
    if key in CATEGORIES:
        _, owasp, default_cwe = CATEGORIES[key]
        cwe = as_text(cat.get("cwe")).strip() or default_cwe
        if key == "other":
            owasp = as_text(cat.get("owasp")).strip()
    else:
        warnings.append("%s: unknown category key '%s' (fix with `findings set %s category=<key>`)"
                        % (who, key or "(empty)", who))
        owasp, cwe = as_text(cat.get("owasp")).strip(), as_text(cat.get("cwe")).strip()
        key = key or "other"

    severity = as_text(raw.get("severity")).strip().lower()
    if severity not in SEVERITIES:
        warnings.append("%s: severity '%s' is not valid; set to medium" % (who, severity))
        severity = "medium"
    confidence = as_text(raw.get("confidence")).strip().lower().replace(" ", "_").replace("-", "_")
    if confidence not in CONFIDENCES:
        warnings.append("%s: confidence '%s' is not valid; set to likely" % (who, confidence))
        confidence = "likely"

    path = norm_path(raw.get("file"))
    start = as_int(raw.get("line_start", raw.get("line")))
    end = as_int(raw.get("line_end", start)) or start
    if end < start:
        start, end = end, start
    if path and not os.path.exists(path):
        warnings.append("%s: file '%s' does not exist in the repository" % (who, path))
    elif path and os.path.isfile(path):
        total = line_count(path)
        if 0 < total < start:
            warnings.append("%s: line %d is past the end of %s (%d lines)" % (who, start, path, total))

    fix = raw.get("proposed_fix")
    if isinstance(fix, str):
        fix = {"diff": fix, "explanation": ""}
    if not isinstance(fix, dict):
        fix = {}
    detected = [as_text(d).strip() for d in as_list(raw.get("detected_by")) if as_text(d).strip()]
    if agent and agent not in detected:
        detected.insert(0, agent)
    questions = [mask_secrets(" ".join(as_text(q).split()))
                 for q in as_list(raw.get("questions")) if as_text(q).strip()]
    if confidence in ("suspected", "needs_validation") and not questions:
        warnings.append("%s: %s finding without a question for the developer" % (who, confidence))

    return {
        "id": origin,
        "origin_id": origin,
        "agent": agent,
        "title": title or "(untitled finding)",
        "category": {"key": key, "owasp": owasp, "cwe": cwe},
        "severity": severity,
        "confidence": confidence,
        "file": path,
        "line_start": start,
        "line_end": end,
        "snippet": mask_secrets(as_text(raw.get("snippet"))),
        "source": mask_secrets(as_text(raw.get("source"))),
        "sink": mask_secrets(as_text(raw.get("sink"))),
        "attack_scenario": mask_secrets(as_text(raw.get("attack_scenario"))),
        "impact": mask_secrets(as_text(raw.get("impact"))),
        "proposed_fix": {"diff": mask_secrets(as_text(fix.get("diff"))),
                         "explanation": mask_secrets(as_text(fix.get("explanation")))},
        "questions": questions,
        "references": [as_text(r) for r in as_list(raw.get("references")) if as_text(r).strip()],
        "detected_by": detected,
        "status": "open",
        "resolution_note": "",
    }


def assign_id(finding, used, agent):
    """Keep the agent's id when it is well formed and free; otherwise number one."""
    wanted = finding.get("id", "").upper()
    if re.match(r"^[A-Z][A-Z0-9]*-\d+$", wanted) and wanted not in used:
        finding["id"] = wanted
    else:
        prefix = AGENT_PREFIX.get(agent)
        if not prefix:
            match = re.match(r"^([A-Z][A-Z0-9]*)-", wanted)
            prefix = match.group(1) if match else "SCAN"
        number = 1
        while "%s-%03d" % (prefix, number) in used:
            number += 1
        finding["id"] = "%s-%03d" % (prefix, number)
    used.add(finding["id"])
    return finding["id"]


def overlaps(a, b):
    return a["file"] == b["file"] and a["line_start"] <= b["line_end"] \
        and b["line_start"] <= a["line_end"]


def better(a, b):
    """True when a should survive a merge with b."""
    ka = (sev_rank(a["severity"]), conf_rank(a["confidence"]), -len(a.get("attack_scenario", "")))
    kb = (sev_rank(b["severity"]), conf_rank(b["confidence"]), -len(b.get("attack_scenario", "")))
    return ka <= kb


def absorb(doc, winner, loser):
    for name in loser.get("detected_by", []):
        if name not in winner["detected_by"]:
            winner["detected_by"].append(name)
    for question in loser.get("questions", []):
        if question not in winner["questions"]:
            winner["questions"].append(question)
    winner.setdefault("merged_from", [])
    winner["merged_from"] += [loser["id"]] + loser.get("merged_from", [])
    doc["merged_duplicates"].append({"id": loser["id"], "into": winner["id"],
                                     "agent": loser.get("agent", ""), "title": loser["title"]})
    for merged in doc["merged_duplicates"]:
        if merged["into"] == loser["id"]:
            merged["into"] = winner["id"]
    for question in doc["questions"]:
        question["finding_ids"] = [winner["id"] if i == loser["id"] else i
                                   for i in question.get("finding_ids", [])]


def merge_exact_duplicates(doc):
    """Same file, same category key, overlapping lines: one bug reported twice."""
    kept = []
    for finding in doc["findings"]:
        twin = None
        if finding["status"] == "open":
            for other in kept:
                if other["status"] == "open" and category_of(other) == category_of(finding) \
                        and overlaps(other, finding):
                    twin = other
                    break
        if twin is None:
            kept.append(finding)
        elif better(twin, finding):
            absorb(doc, twin, finding)
        else:
            absorb(doc, finding, twin)
            kept[kept.index(twin)] = finding
    doc["findings"] = kept


def near_duplicates(doc):
    """Same file and overlapping lines in the same category group, different key."""
    pairs = []
    open_findings = [f for f in doc["findings"] if f["status"] == "open"]
    for i, first in enumerate(open_findings):
        for second in open_findings[i + 1:]:
            if overlaps(first, second) and category_of(first) != category_of(second) \
                    and group_of(category_of(first)) == group_of(category_of(second)):
                pairs.append((first["id"], second["id"]))
    return pairs


def add_question(doc, text, finding_ids, agent):
    text = mask_secrets(" ".join(as_text(text).split()))
    if not text:
        return
    for question in doc["questions"]:
        if question["question"] == text:
            for finding_id in finding_ids:
                if finding_id not in question["finding_ids"]:
                    question["finding_ids"].append(finding_id)
            return
    doc["questions"].append({"id": "Q%d" % (len(doc["questions"]) + 1), "finding_ids": finding_ids,
                             "question": text, "agent": agent, "status": "open", "answer": ""})


def coverage_gaps(doc):
    gaps = ["%s was dispatched but returned no usable result, so its area was not reviewed"
            % agent for agent in doc.get("missing_agents", [])]
    return gaps + list(doc.get("coverage_gaps", []))


def update_coverage(doc):
    surfaces = read_json(P_SURFACES)
    reviewed = set()
    for agent in doc["agents"]:
        for path in agent.get("files_reviewed_list", []):
            reviewed.add(norm_path(path).lower())
    unreviewed = []
    if isinstance(surfaces, dict):
        for item in surfaces.get("files", []):
            if item.get("status") == "D" or item.get("class") not in REVIEWABLE:
                continue
            low = item["path"].lower()
            if low in reviewed or any(r.endswith("/" + low) for r in reviewed):
                continue
            unreviewed.append(item["path"])
        doc["unreviewed_files"] = unreviewed
        write_text(P_LEDGER, render_ledger(surfaces, doc))
    else:
        doc["unreviewed_files"] = []


def counts_of(findings):
    counts = {s: 0 for s in SEVERITIES}
    for finding in findings:
        if finding.get("status") not in RESOLVED and finding.get("severity") in counts:
            counts[finding["severity"]] += 1
    return counts


def counts_line(counts):
    return " · ".join("%d %s" % (counts[s], s) for s in SEVERITIES)


def table(findings):
    rows = [("ID", "SEVERITY", "CONFIDENCE", "CATEGORY", "LOCATION", "STATUS", "TITLE")]
    for finding in sorted(findings, key=sort_key):
        rows.append((finding["id"], finding["severity"], finding["confidence"],
                     category_of(finding), location(finding), finding["status"],
                     clip(finding["title"], 70)))
    widths = [max(len(row[i]) for row in rows) for i in range(6)]
    out = []
    for row in rows:
        out.append("  ".join(row[i].ljust(widths[i]) for i in range(6)) + "  " + row[6])
    return "\n".join(out)


def cmd_collect(args):
    scope = load_scope()
    doc = new_doc(scope.get("review_id", "")) if args.rebuild else load_doc(required=False)
    expected = [short_agent(a) for a in re.split(r"[,\s]+", args.expect or "") if a.strip()]
    for name in expected:
        if name not in doc["expected_agents"] and name != VERIFIER:
            doc["expected_agents"].append(name)

    seen = {agent["file"] for agent in doc["agents"]}
    used = {f["id"] for f in doc["findings"]} | {m["id"] for m in doc["merged_duplicates"]}
    warnings, new_findings, bad_files = [], [], []
    for item in load_envelopes():
        if "error" in item:
            bad_files.append("%s (%s)" % (item["file"], item["error"]))
            continue
        env, agent = item["envelope"], item["agent"]
        if "verifications" in env and "findings" not in env:
            continue  # the verifier's rulings: `findings verify` reads those
        if item["file"] in seen:
            continue
        id_map = {}
        added = 0
        for raw in as_list(env.get("findings")):
            finding = normalize_finding(raw, agent, warnings)
            if finding is None:
                continue
            origin = finding["origin_id"]
            id_map[origin.upper()] = assign_id(finding, used, agent)
            doc["findings"].append(finding)
            new_findings.append(finding)
            added += 1
            for question in finding["questions"]:
                add_question(doc, question, [finding["id"]], agent)
        for question in as_list(env.get("questions")):
            if isinstance(question, dict):
                ids = [id_map.get(as_text(i).upper(), as_text(i))
                       for i in as_list(question.get("finding_ids"))]
                add_question(doc, question.get("question"), ids, agent)
            else:
                add_question(doc, question, [], agent)
        for disproved in as_list(env.get("disproved_scanner_findings")):
            if isinstance(disproved, dict):
                disproved = dict(disproved, agent=agent)
                doc["disproved_scanner_findings"].append(disproved)
        reviewed = [norm_path(p) for p in as_list(env.get("files_reviewed")) if as_text(p).strip()]
        doc["agents"].append({"file": item["file"], "agent": agent, "agent_id": item["agent_id"],
                              "source": item["source"], "findings": added,
                              "files_reviewed": len(reviewed), "files_reviewed_list": reviewed,
                              "coverage_notes": mask_secrets(as_text(env.get("coverage_notes")))})

    before = len(doc["merged_duplicates"])
    merge_exact_duplicates(doc)
    merged_now = doc["merged_duplicates"][before:]
    surviving = {f["id"] for f in doc["findings"]}
    received = {agent["agent"] for agent in doc["agents"]}
    doc["missing_agents"] = [a for a in doc["expected_agents"] if a not in received]
    update_coverage(doc)
    save_doc(doc)

    for finding in new_findings:
        if finding["id"] in surviving:
            event("finding_reported", id=finding["id"], severity=finding["severity"],
                  confidence=finding["confidence"], category=category_of(finding),
                  file=finding["file"], line=finding["line_start"])
    event("coverage_ledger_updated", surfaces=len((read_json(P_SURFACES) or {}).get("surfaces", {})),
          agents=len(received), gaps=len(coverage_gaps(doc)))

    summary = ", ".join("%s (%d)" % (a["agent"], a["findings"]) for a in doc["agents"]) or "none"
    print("Envelopes collected: %s" % summary)
    if doc["missing_agents"]:
        print("MISSING: %s. Nothing usable was captured for these agents. If you have the "
              "agent's reply, save its JSON block to %s/<agent>.json and run collect again; "
              "otherwise dispatch the agent once more. A gap that remains keeps the verdict "
              "from being a clean PASS." % (", ".join(doc["missing_agents"]), P_AGENTS))
    if bad_files:
        print("Unreadable envelope files: %s" % "; ".join(bad_files))
    open_findings = [f for f in doc["findings"] if f["status"] == "open"]
    print("Findings: %d open (%s)" % (len(open_findings), counts_line(counts_of(doc["findings"]))))
    if doc["findings"]:
        print(table(doc["findings"]))
    if merged_now:
        print("Merged as the same bug reported twice: %s" %
              ", ".join("%s into %s" % (m["id"], m["into"]) for m in merged_now))
    pairs = near_duplicates(doc)
    if pairs:
        print("Possibly the same bug under two categories (merge with `findings merge <keep> "
              "<duplicate>` if so): %s" % ", ".join("%s ~ %s" % pair for pair in pairs))
    if warnings:
        print("Warnings:")
        for warning in warnings:
            print("  - " + warning)
    open_questions = [q for q in doc["questions"] if q["status"] == "open"]
    if open_questions:
        print("Questions raised (%d):" % len(open_questions))
        for question in open_questions:
            print("  %s [%s] %s" % (question["id"], ", ".join(question["finding_ids"]) or "general",
                                    question["question"]))
    if doc["disproved_scanner_findings"]:
        print("Scanner hits the agents disproved (do not add these as findings): %d" %
              len(doc["disproved_scanner_findings"]))
        for item in doc["disproved_scanner_findings"][:20]:
            print("  - %s %s %s:%s: %s" % (item.get("tool", ""), item.get("rule", ""),
                                           item.get("file", ""), item.get("line", ""),
                                           clip(item.get("reason", ""), 120)))
    if doc["unreviewed_files"]:
        shown = ", ".join(doc["unreviewed_files"][:12])
        more = len(doc["unreviewed_files"]) - 12
        print("In scope but not listed as reviewed by any agent (%d): %s%s" %
              (len(doc["unreviewed_files"]), shown, " … +%d more" % more if more > 0 else ""))
    print("Saved: %s" % P_FINDINGS)
    return 0


def cmd_list(args):
    doc = load_doc()
    findings = doc["findings"]
    if not args.all:
        findings = [f for f in findings if f["status"] not in RESOLVED]
    if args.json:
        print(json.dumps(sorted(findings, key=sort_key), indent=2, ensure_ascii=False))
        return 0
    print("Unresolved: %s" % counts_line(counts_of(doc["findings"])))
    print(table(findings) if findings else "(no findings)")
    return 0


def fence(text, lang=""):
    ticks = "```"
    while ticks in text:
        ticks += "`"
    return "%s%s\n%s\n%s" % (ticks, lang, text.rstrip("\n"), ticks)


LANG_BY_EXT = {"py": "python", "js": "js", "mjs": "js", "cjs": "js", "jsx": "jsx", "ts": "ts",
               "tsx": "tsx", "php": "php", "java": "java", "kt": "kotlin", "cs": "csharp",
               "go": "go", "rb": "ruby", "rs": "rust", "sh": "bash", "yml": "yaml", "yaml": "yaml",
               "json": "json", "xml": "xml", "html": "html", "tf": "hcl", "sql": "sql",
               "properties": "properties", "toml": "toml", "ini": "ini", "c": "c", "cpp": "cpp"}


def render_finding(finding, heading="###"):
    cat = finding["category"]
    labels = [x for x in ("`%s`" % cat.get("key", ""), cat.get("owasp", ""), cat.get("cwe", "")) if x
              and x != "``"]
    name = finding["file"].rsplit("/", 1)[-1].lower()
    ext = name.rsplit(".", 1)[1] if "." in name else ""
    lang = "dockerfile" if name.startswith("dockerfile") else LANG_BY_EXT.get(ext, "")
    out = ["%s %s — %s (%s · %s)" % (heading, finding["id"], finding["title"],
                                     finding["severity"], finding["confidence"]), "",
           " · ".join(labels), "", "**Where:** `%s`" % location(finding)]
    if finding.get("snippet", "").strip():
        out += ["", fence(finding["snippet"], lang)]
    if finding.get("source") or finding.get("sink"):
        flow = " → ".join(x for x in (finding.get("source", ""), finding.get("sink", "")) if x)
        out += ["", "**Data flow:** " + flow]
    if finding.get("attack_scenario"):
        out += ["", "**Attack:** " + finding["attack_scenario"]]
    if finding.get("impact"):
        out += ["", "**Impact:** " + finding["impact"]]
    fix = finding.get("proposed_fix", {})
    if fix.get("diff", "").strip():
        out += ["", "**Proposed fix:**", "", fence(fix["diff"], "diff")]
    if fix.get("explanation", "").strip():
        out += ["", "**Why it works:** " + fix["explanation"]]
    if finding.get("questions"):
        out += ["", "**Open questions:**"] + ["- " + q for q in finding["questions"]]
    if finding.get("references"):
        out += ["", "**References:** " + ", ".join(finding["references"])]
    tail = "**Status:** %s" % finding["status"]
    if finding.get("resolution_note"):
        tail += " — " + finding["resolution_note"]
    tail += "  \n**Detected by:** " + ", ".join(finding.get("detected_by", []))
    if finding.get("merged_from"):
        tail += " (also reported as %s)" % ", ".join(finding["merged_from"])
    out += ["", tail]
    return "\n".join(out)


def cmd_show(args):
    doc = load_doc()
    for finding_id in args.ids:
        print(render_finding(find_finding(doc, finding_id), heading="##"))
        print()
    return 0


def apply_fields(finding, fields):
    changed = []
    for key, value in fields.items():
        if key == "severity":
            value = value.lower()
            if value not in SEVERITIES:
                raise Fail("severity must be one of %s" % ", ".join(SEVERITIES))
        elif key == "confidence":
            value = value.lower().replace("-", "_")
            if value not in CONFIDENCES:
                raise Fail("confidence must be one of %s" % ", ".join(CONFIDENCES))
        elif key == "status":
            value = value.lower().replace("-", "_")
            if value not in STATUSES:
                raise Fail("status must be one of %s" % ", ".join(STATUSES))
        elif key == "category":
            value = value.lower()
            if value not in CATEGORIES:
                raise Fail("unknown category key '%s'; see finding-schema.md" % value)
            _, owasp, cwe = CATEGORIES[value]
            finding["category"] = {"key": value, "owasp": owasp, "cwe": cwe}
            changed.append("category=%s" % value)
            continue
        elif key == "note":
            add_note(finding, value)
            changed.append("note")
            continue
        elif key in ("line_start", "line_end"):
            value = as_int(value)
        elif key == "file":
            value = norm_path(value)
        elif key == "title":
            value = mask_secrets(value)
        else:
            raise Fail("can't set '%s'; settable: severity, confidence, status, category, "
                       "title, file, line_start, line_end, note" % key)
        if finding.get(key) != value:
            changed.append("%s: %s -> %s" % (key, finding.get(key), value))
            finding[key] = value
    return changed


def cmd_set(args):
    ids, fields = parse_kv(args.items)
    if not ids or not fields:
        raise Fail("usage: findings set <ID> [<ID>...] key=value [key=value...]")
    doc = load_doc()
    for finding_id in ids:
        finding = find_finding(doc, finding_id)
        changed = apply_fields(finding, fields)
        print("%s: %s" % (finding["id"], "; ".join(changed) or "unchanged"))
    save_doc(doc)
    return 0


def cmd_merge(args):
    if len(args.ids) < 2:
        raise Fail("usage: findings merge <KEEP_ID> <DUPLICATE_ID> [<DUPLICATE_ID>...]")
    doc = load_doc()
    winner = find_finding(doc, args.ids[0])
    for finding_id in args.ids[1:]:
        loser = find_finding(doc, finding_id)
        if loser is winner:
            continue
        if sev_rank(loser["severity"]) < sev_rank(winner["severity"]):
            winner["severity"] = loser["severity"]
        if conf_rank(loser["confidence"]) < conf_rank(winner["confidence"]):
            winner["confidence"] = loser["confidence"]
        absorb(doc, winner, loser)
        doc["findings"].remove(loser)
        print("%s merged into %s" % (loser["id"], winner["id"]))
    save_doc(doc)
    return 0


def cmd_add(args):
    scope = load_scope()
    doc = load_doc(required=False)
    data = read_json(args.file)
    if data is None:
        raise Fail("%s is not readable JSON" % args.file)
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    used = {f["id"] for f in doc["findings"]} | {m["id"] for m in doc["merged_duplicates"]}
    warnings, added = [], []
    for raw in as_list(data):
        finding = normalize_finding(raw, "", warnings)
        if finding is None:
            continue
        finding["agent"] = "orchestrator"
        if not finding["detected_by"]:
            finding["detected_by"] = ["orchestrator"]
        assign_id(finding, used, "")
        doc["findings"].append(finding)
        added.append(finding)
        event("finding_reported", id=finding["id"], severity=finding["severity"],
              confidence=finding["confidence"], category=category_of(finding),
              file=finding["file"], line=finding["line_start"])
    merge_exact_duplicates(doc)
    doc["review_id"] = scope.get("review_id", doc.get("review_id", ""))
    save_doc(doc)
    print("Added: %s" % (", ".join(f["id"] for f in added) or "nothing"))
    for warning in warnings:
        print("  - " + warning)
    return 0


def cmd_fixed(args):
    ids, fields = parse_kv(args.items)
    if not ids:
        raise Fail("usage: findings fixed <ID> [<ID>...] [note=\"...\"] [edited=true]")
    doc = load_doc()
    for finding_id in ids:
        finding = find_finding(doc, finding_id)
        finding["status"] = "fixed"
        add_note(finding, fields.get("note") or "fix applied and re-checked")
        edited = fields.get("edited", "").lower() in ("1", "true", "yes")
        event("finding_accepted", id=finding["id"])
        event("fix_applied", id=finding["id"], file=finding["file"], edited=edited)
        event("fix_verified", id=finding["id"], result="ok")
        print("%s: fixed" % finding["id"])
    save_doc(doc)
    return 0


def cmd_reject(args):
    ids, fields = parse_kv(args.items)
    reason = fields.get("reason", "").lower().replace("-", "_")
    note = fields.get("note", "")
    if not ids or reason not in ("false_positive", "accepted_risk", "will_fix_later"):
        raise Fail("usage: findings reject <ID> [<ID>...] "
                   "reason=<false_positive|accepted_risk|will_fix_later> note=\"<their sentence>\"")
    if len(note.strip()) < 3:
        raise Fail("a rejection needs the developer's reason: add note=\"...\"")
    doc = load_doc()
    for finding_id in ids:
        finding = find_finding(doc, finding_id)
        finding["status"] = reason
        add_note(finding, "developer: " + note)
        event("finding_rejected", id=finding["id"], reason=reason, note=note)
        print("%s: %s" % (finding["id"], reason))
    save_doc(doc)
    return 0


def cmd_answer(args):
    ids, fields = parse_kv(args.items)
    outcome = fields.get("outcome", "").lower()
    if len(ids) != 1 or outcome not in ("confirmed", "dismissed", "unclear"):
        raise Fail("usage: findings answer <Q-ID> outcome=<confirmed|dismissed|unclear> "
                   "note=\"<the developer's answer>\"")
    doc = load_doc()
    wanted = ids[0].upper()
    question = next((q for q in doc["questions"] if q["id"].upper() == wanted), None)
    if question is None:
        raise Fail("no question with id %s" % ids[0])
    note = fields.get("note", "")
    question["status"], question["answer"], question["outcome"] = "answered", note, outcome
    first = question["finding_ids"][0] if question["finding_ids"] else ""
    event("question_asked", id=question["id"], finding=first)
    event("question_answered", id=question["id"], finding=first, outcome=outcome)
    for finding_id in question["finding_ids"]:
        try:
            finding = find_finding(doc, finding_id)
        except Fail:
            continue
        if finding["status"] in RESOLVED:
            continue
        if outcome == "dismissed":
            finding["status"] = "false_positive"
            add_note(finding, "developer answered %s: %s" % (question["id"], note or "intended"))
            event("finding_rejected", id=finding["id"], reason="false_positive", note=note)
            print("%s: false_positive (dismissed by the developer's answer)" % finding["id"])
        elif outcome == "confirmed":
            if finding["confidence"] in ("suspected", "needs_validation"):
                finding["confidence"] = "likely"
            add_note(finding, "developer confirmed %s: %s" % (question["id"], note))
            print("%s: confidence %s (confirmed by the developer's answer)" %
                  (finding["id"], finding["confidence"]))
    save_doc(doc)
    print("%s recorded as %s" % (question["id"], outcome))
    return 0


# --------------------------------------------------------------------------
# verify: apply the finding-verifier's rulings
# --------------------------------------------------------------------------

def cmd_verify(args):
    doc = load_doc()
    applied = doc["verification"].setdefault("applied_files", [])
    sources = []
    if args.file:
        data = read_json(args.file)
        if not isinstance(data, dict):
            text = read_text(args.file)
            data, _ = extract_envelope(text)
        if not isinstance(data, dict):
            raise Fail("%s holds no verifications JSON" % args.file)
        sources.append((args.file, data.get("envelope", data)))
    else:
        for item in load_envelopes():
            if "error" in item or "verifications" not in item["envelope"]:
                continue
            if item["file"] not in applied:
                sources.append((item["file"], item["envelope"]))
        if not sources and os.path.exists(P_VERIFICATION) and P_VERIFICATION not in applied:
            data = read_json(P_VERIFICATION)
            if isinstance(data, dict):
                sources.append((P_VERIFICATION, data.get("envelope", data)))
    if not sources:
        raise Fail("no verifier rulings found. They are captured automatically when the "
                   "finding-verifier agent finishes; if that did not happen, save its JSON "
                   "block to %s and run this again." % P_VERIFICATION, 3)

    by_id = {f["id"].upper(): f for f in doc["findings"]}
    merged = {m["id"].upper(): m["into"].upper() for m in doc["merged_duplicates"]}
    changes, attention, unknown, skipped = [], [], [], []
    stats = {"keep": 0, "drop": 0, "adjust": 0}
    ruled = set()
    for name, env in sources:
        for ruling in as_list(env.get("verifications")):
            if not isinstance(ruling, dict):
                continue
            finding_id = as_text(ruling.get("id")).strip().upper()
            finding = by_id.get(merged.get(finding_id, finding_id))
            if finding is None:
                unknown.append(finding_id or "(no id)")
                continue
            if finding["status"] != "open":
                skipped.append(finding["id"])
                continue
            verdict = as_text(ruling.get("verdict")).strip().lower()
            reason = mask_secrets(" ".join(as_text(ruling.get("reason")).split()))
            path = mask_secrets(" ".join(as_text(ruling.get("exploit_path")).split()))
            sev_out = as_text(ruling.get("severity_out")).strip().lower()
            conf_out = as_text(ruling.get("confidence_out")).strip().lower().replace("-", "_")
            old_sev, old_conf = finding["severity"], finding["confidence"]
            serious = old_sev in ("critical", "high")
            if verdict == "drop":
                finding["status"] = "false_positive"
                add_note(finding, "verifier: " + (reason or "no reachable exploit path"))
                changes.append("%s dropped: %s" % (finding["id"], clip(reason, 160)))
                if serious:
                    attention.append("%s (%s, %s) was DROPPED: %s" %
                                     (finding["id"], old_sev, clip(finding["title"], 60),
                                      clip(reason, 200)))
            elif verdict in ("keep", "adjust"):
                if sev_out in SEVERITIES and sev_out != old_sev:
                    finding["severity"] = sev_out
                if conf_out in CONFIDENCES and conf_out != old_conf:
                    finding["confidence"] = conf_out
                moved = finding["severity"] != old_sev or finding["confidence"] != old_conf
                if moved:
                    verdict = "adjust"
                    add_note(finding, "verifier: %s/%s -> %s/%s. %s" %
                             (old_sev, old_conf, finding["severity"], finding["confidence"], reason))
                    changes.append("%s %s/%s -> %s/%s: %s" %
                                   (finding["id"], old_sev, old_conf, finding["severity"],
                                    finding["confidence"], clip(reason, 160)))
                    if serious and finding["severity"] not in ("critical", "high"):
                        attention.append("%s (%s) was DOWNGRADED from %s to %s: %s" %
                                         (finding["id"], clip(finding["title"], 60), old_sev,
                                          finding["severity"], clip(reason, 200)))
                else:
                    verdict = "keep"
                    if reason or path:
                        finding["verifier_note"] = path or reason
                question = " ".join(as_text(ruling.get("question")).split())
                if question:
                    if question not in finding["questions"]:
                        finding["questions"].append(mask_secrets(question))
                    add_question(doc, question, [finding["id"]], VERIFIER)
                elif finding["confidence"] in ("suspected", "needs_validation") \
                        and not finding["questions"]:
                    changes.append("%s is %s but the verifier gave no question to ask" %
                                   (finding["id"], finding["confidence"]))
            else:
                unknown.append("%s (verdict '%s')" % (finding["id"], verdict))
                continue
            finding["verified"] = verdict
            stats[verdict] += 1
            ruled.add(finding["id"])
            event("finding_verified", id=finding["id"], verdict=verdict,
                  severity=finding["severity"], confidence=finding["confidence"])
        for note in as_list(env.get("observations")):
            if as_text(note).strip():
                doc["verification"]["observations"].append(mask_secrets(as_text(note)))
        applied.append(name)

    doc["verification"]["kept"] += stats["keep"]
    doc["verification"]["dropped"] += stats["drop"]
    doc["verification"]["adjusted"] += stats["adjust"]
    doc["verification"]["applied_at"] = now_iso()
    update_coverage(doc)
    save_doc(doc)

    print("Verifier rulings applied: %d kept, %d adjusted, %d dropped." %
          (stats["keep"], stats["adjust"], stats["drop"]))
    for change in changes:
        print("  - " + change)
    unruled = [f["id"] for f in doc["findings"] if f["status"] == "open" and not f.get("verified")]
    if unruled:
        print("Not ruled on (still open, unverified): %s" % ", ".join(unruled))
    if unknown:
        print("Rulings for ids that don't exist: %s" % ", ".join(unknown))
    if skipped:
        print("Rulings ignored for already resolved findings: %s" % ", ".join(sorted(set(skipped))))
    if attention:
        print("CHECK THESE: the verifier removed or downgraded critical/high findings. If you "
              "are sure one is real and reachable, restore it with `findings set <ID> status=open "
              "severity=<level> note=\"kept despite verifier: <why>\"`:")
        for line in attention:
            print("  ! " + line)
    if doc["verification"]["observations"]:
        print("Verifier observations (not findings unless you confirm them):")
        for note in doc["verification"]["observations"][-8:]:
            print("  - " + clip(note, 220))
    print("Unresolved now: %s" % counts_line(counts_of(doc["findings"])))
    print(table([f for f in doc["findings"] if f["status"] not in RESOLVED]) or "(none)")
    return 0


# --------------------------------------------------------------------------
# report: verdict, JSON + Markdown, summary
# --------------------------------------------------------------------------

BLOCK_TOKENS = ("critical", "high", "medium", "low", "coverage-gap")


def parse_block_on(text):
    tokens = [t.strip().lower() for t in re.split(r"[,\s]+", text or "") if t.strip()]
    if not tokens:
        return ["critical", "high"]
    for token in tokens:
        if token not in BLOCK_TOKENS:
            raise Fail("--block-on accepts %s (got '%s')" % (", ".join(BLOCK_TOKENS), token))
    if "critical" not in tokens:
        raise Fail("--block-on must include critical: the team config can tune the gate, "
                   "not switch it off")
    return [t for t in BLOCK_TOKENS if t in tokens]


def compute_verdict(findings, gaps, block_on):
    unresolved = [f for f in findings if f.get("status") not in RESOLVED]
    blocking = [f for f in unresolved if f.get("severity") in block_on]
    if blocking or ("coverage-gap" in block_on and gaps):
        return "BLOCKED", blocking
    if any(f.get("severity") != "info" for f in unresolved) or gaps:
        return "PASS_WITH_WARNINGS", []
    return "PASS", []


def context_summary():
    text = read_text(P_CONTEXT)
    match = re.search(r"^##\s+Summary of the change\s*$(.*?)(?=^##\s|\Z)", text, re.M | re.S)
    return match.group(1).strip() if match else ""


def render_report(report, doc):
    verdict = report["verdict"]
    counts = report["counts"]
    findings = report["findings"]
    live = [f for f in findings if f["status"] not in RESOLVED]
    fixed = [f for f in findings if f["status"] == "fixed"]
    dismissed = [f for f in findings if f["status"] == "false_positive"]
    out = ["# Security review %s" % report["review_id"], "",
           "**Verdict: %s**" % verdict.replace("_", " ")]
    if report.get("override_reason"):
        out += ["", "Overridden by the developer: %s" % report["override_reason"]]
    out += ["", "| critical | high | medium | low | info |", "| :-: | :-: | :-: | :-: | :-: |",
            "| %d | %d | %d | %d | %d |" % tuple(counts[s] for s in SEVERITIES), "",
            "Unresolved findings by severity. %d fixed during the review, %d dismissed as false "
            "positives, %d duplicates merged." % (len(fixed), len(dismissed),
                                                  len(report.get("merged_duplicates", []))), "",
            "Scope: `%s` against `%s` · branch `%s` · head `%s` · generated %s" %
            (report.get("mode", ""), report.get("base_ref", ""), report.get("branch", ""),
             as_text(report.get("head"))[:12], report["generated_at"])]

    out += ["", "## Why this verdict", ""]
    block_on = ", ".join(report["block_on"])
    blocking = [f for f in live if f["severity"] in report["block_on"]]
    if verdict in ("BLOCKED", "OVERRIDDEN"):
        out.append("This repository blocks a push on: %s. These unresolved findings block:" % block_on)
        out += ["- **%s** %s (%s, %s)" % (f["id"], f["title"], f["severity"], f["confidence"])
                for f in sorted(blocking, key=sort_key)]
        if "coverage-gap" in report["block_on"] and report["coverage_gaps"]:
            out.append("- a coverage gap (see Coverage)")
        if verdict == "OVERRIDDEN":
            out += ["", "The developer overrode the block with the reason above; the push gate is open."]
    elif verdict == "PASS_WITH_WARNINGS":
        out.append("Nothing unresolved at a blocking severity (%s), but warnings remain: fix "
                   "them when you can." % block_on)
    else:
        out.append("Nothing unresolved above `info`.")

    summary = context_summary()
    if summary:
        out += ["", "## Summary of the change", "", summary]

    out += ["", "## Findings", ""]
    if findings:
        out += ["| ID | Severity | Confidence | Category | Location | Status |",
                "| :- | :- | :- | :- | :- | :- |"]
        out += ["| %s | %s | %s | %s | `%s` | %s |" %
                (f["id"], f["severity"], f["confidence"], category_of(f), location(f), f["status"])
                for f in sorted(findings, key=sort_key)]
        for finding in sorted(live + fixed, key=sort_key):
            out += ["", "---", "", render_finding(finding)]
    else:
        out.append("No findings.")

    if dismissed:
        out += ["", "## Dismissed as false positives", ""]
        out += ["- **%s** %s (`%s`): %s" % (f["id"], f["title"], location(f),
                                            f.get("resolution_note") or "no note")
                for f in sorted(dismissed, key=sort_key)]
    if report.get("merged_duplicates"):
        out += ["", "## Duplicates merged", ""]
        out += ["- %s (%s) is the same bug as **%s**" % (m["id"], m.get("agent", ""), m["into"])
                for m in report["merged_duplicates"]]

    out += ["", "## Open questions", ""]
    if report["open_questions"]:
        out += ["- **%s** [%s] %s" % (q["id"], ", ".join(q["finding_ids"]) or "general",
                                      q["question"]) for q in report["open_questions"]]
    else:
        out.append("None.")

    out += ["", "## Coverage", "", "| Agent | Files reviewed | Findings |", "| :- | -: | -: |"]
    out += ["| %s | %s | %s |" % (a["agent"], a["files_reviewed"], a["findings"])
            for a in report["agents"]] or ["| (none) | 0 | 0 |"]
    out.append("")
    if report["coverage_gaps"]:
        out += ["**Coverage gaps:**"] + ["- " + gap for gap in report["coverage_gaps"]]
    else:
        out.append("No coverage gaps recorded.")
    if report.get("unreviewed_files"):
        files = report["unreviewed_files"]
        out += ["", "Files in scope that no reviewer listed as reviewed (%d): %s%s" %
                (len(files), ", ".join("`%s`" % f for f in files[:25]),
                 " and %d more" % (len(files) - 25) if len(files) > 25 else "")]
    verification = doc.get("verification", {})
    if verification.get("applied_files"):
        out += ["", "Verification pass: %d kept, %d adjusted, %d dropped." %
                (verification.get("kept", 0), verification.get("adjusted", 0),
                 verification.get("dropped", 0))]
    else:
        out += ["", "Verification pass: not run."]

    out += ["", "## Scanners", "", "| Tool | Status | Hits | Note |", "| :- | :- | -: | :- |"]
    scans = read_json(P_SCANS, {}) or {}
    installs = {m.get("tool"): m.get("install", "") for m in as_list(scans.get("not_installed"))}
    for scanner in report["scanners"]:
        note = scanner.get("note", "")
        if scanner["status"] == "not_installed" and installs.get(scanner["tool"]):
            note = "install: " + installs[scanner["tool"]]
        hits = "" if scanner.get("findings") is None else scanner["findings"]
        out.append("| %s | %s | %s | %s |" % (scanner["tool"], scanner["status"], hits,
                                              note.replace("|", "/")))
    if not report["scanners"]:
        out.append("| (none ran) | | | |")
    out += ["", "A scanner that did not run found nothing because it did not look."]
    return "\n".join(out) + "\n"


# SARIF 2.1.0 — the standard static-analysis format. GitHub code scanning reads
# `level` for the alert bucket and the rule's `security-severity` for the score.
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SARIF_SECSEV = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
PLUGIN_URL = "https://github.com/khalilrmilA/claude-plugin"


def plugin_version():
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                            ".claude-plugin", "plugin.json")
        with open(path, encoding="utf-8") as fh:
            return as_text(json.load(fh).get("version")) or "0"
    except (OSError, ValueError):
        return "0"


def render_sarif(report):
    """A SARIF 2.1.0 run over the unresolved findings, for CI code scanning."""
    findings = [f for f in report["findings"] if f.get("status") not in RESOLVED]
    rules, rule_index, results = [], {}, []
    for finding in findings:
        cat = finding.get("category") if isinstance(finding.get("category"), dict) else {}
        key = (cat.get("key") or "other").strip() or "other"
        _, owasp_default, cwe_default = CATEGORIES.get(key, (key, "", ""))
        owasp = as_text(cat.get("owasp")).strip() or owasp_default
        cwe = as_text(cat.get("cwe")).strip() or cwe_default
        sev = finding.get("severity", "info")
        secsev = SARIF_SECSEV.get(sev, "1.0")
        if key not in rule_index:
            cwe_num = re.sub(r"\D", "", cwe.split(",")[0]) if cwe else ""
            rule_index[key] = len(rules)
            rules.append({
                "id": key,
                "name": "".join(w.capitalize() for w in re.split(r"[-_ ]", key)),
                "shortDescription": {"text": key.replace("-", " ")},
                "fullDescription": {"text": " / ".join(x for x in (owasp, cwe) if x) or key},
                "helpUri": ("https://cwe.mitre.org/data/definitions/%s.html" % cwe_num)
                           if cwe_num else "https://owasp.org/Top10/",
                "properties": {"tags": ["security"] + ([owasp.split(":")[0]] if ":" in owasp else []),
                               "security-severity": secsev},
            })
        else:  # keep the rule's score at the most severe instance
            prop = rules[rule_index[key]]["properties"]
            if float(secsev) > float(prop["security-severity"]):
                prop["security-severity"] = secsev
        parts = [finding.get("title", "").strip()]
        for label, field in (("Attack", "attack_scenario"), ("Impact", "impact")):
            if finding.get(field):
                parts.append("%s: %s" % (label, finding[field]))
        fix = finding.get("proposed_fix", {}).get("explanation", "")
        if fix:
            parts.append("Fix: " + fix)
        start = as_int(finding.get("line_start")) or 1
        end = max(as_int(finding.get("line_end")) or start, start)
        fingerprint = hashlib.sha1(
            ("%s|%s|%s" % (key, finding.get("file", ""), finding.get("title", "")))
            .encode("utf-8")).hexdigest()[:20]
        results.append({
            "ruleId": key,
            "ruleIndex": rule_index[key],
            "level": SARIF_LEVEL.get(sev, "note"),
            "message": {"text": mask_secrets(" — ".join(p for p in parts if p)) or key},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": finding.get("file", "")},
                "region": {"startLine": start, "endLine": end}}}],
            "partialFingerprints": {"devsecopsReviewer/v1": fingerprint},
            "properties": {k: finding.get(k) for k in ("id", "severity", "confidence", "status")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "devsecops-reviewer",
                "informationUri": PLUGIN_URL,
                "version": plugin_version(),
                "rules": rules,
            }},
            "results": results,
            "properties": {"verdict": report.get("verdict"), "review_id": report.get("review_id")},
        }],
    }


def cmd_report(args):
    scope = load_scope()
    doc = load_doc(required=False)
    block_on = parse_block_on(args.block_on)
    for gap in args.gap or []:
        gap = " ".join(gap.split())
        if gap and gap not in doc["coverage_gaps"]:
            doc["coverage_gaps"].append(gap)
    gaps = coverage_gaps(doc)
    findings = sorted(doc["findings"], key=sort_key)
    computed, blocking = compute_verdict(findings, gaps, block_on)
    override = " ".join((args.override_reason or "").split())
    verdict = computed
    if override:
        if computed != "BLOCKED":
            raise Fail("--override-reason only applies to a BLOCKED verdict (this one is %s)"
                       % computed)
        if len(re.sub(r"\s", "", override)) < 15:
            raise Fail("an override needs a real written reason (at least 15 characters)")
        verdict = "OVERRIDDEN"

    stack = read_json(P_STACK, {}) or {}
    scans = read_json(P_SCANS, {}) or {}
    counts = counts_of(findings)
    review_id = scope.get("review_id", "")
    report = {
        "review_id": review_id,
        "generated_at": now_iso(),
        "mode": scope.get("mode", ""),
        "base_ref": scope.get("base_ref", ""),
        "head": scope.get("head", ""),
        "branch": scope.get("branch", ""),
        "verdict": verdict,
        "original_verdict": computed,
        "override_reason": override,
        "block_on": block_on,
        "stack": {"languages": [l.get("name") if isinstance(l, dict) else l
                                for l in as_list(stack.get("languages"))],
                  "frameworks": as_list(stack.get("frameworks"))},
        "scanners": [{"tool": r.get("tool", ""), "status": r.get("status", ""),
                      "findings": r.get("findings"), "note": r.get("note", "")}
                     for r in as_list(scans.get("results")) if isinstance(r, dict)],
        "agents": [{"agent": a["agent"], "files_reviewed": a.get("files_reviewed", 0),
                    "findings": a.get("findings", 0)} for a in doc["agents"]],
        "coverage_gaps": gaps,
        "unreviewed_files": doc.get("unreviewed_files", []),
        "counts": counts,
        "resolved": {"fixed": sum(1 for f in findings if f["status"] == "fixed"),
                     "false_positive": sum(1 for f in findings if f["status"] == "false_positive")},
        "findings": findings,
        "merged_duplicates": doc.get("merged_duplicates", []),
        "open_questions": [{"id": q["id"], "finding_ids": q["finding_ids"],
                            "question": q["question"]}
                           for q in doc["questions"] if q.get("status") == "open"],
    }
    json_path = "%s/%s.json" % (P_REPORTS, review_id)
    md_path = "%s/%s.md" % (P_REPORTS, review_id)
    sarif_path = "%s/%s.sarif" % (P_REPORTS, review_id)
    write_json(json_path, report)
    write_text(md_path, render_report(report, doc))
    write_json(sarif_path, render_sarif(report))
    save_doc(doc)
    write_text(P_RESULT, "verdict=%s\ncounts=%s\nreport=%s\nsarif=%s\n" %
               (computed, ",".join(str(counts[s]) for s in SEVERITIES), md_path, sarif_path))

    not_run = [s["tool"] for s in report["scanners"] if s["status"] != "ran"]
    print("Security review %s: %s" % (review_id, verdict.replace("_", " ")))
    print("%s  (%d fixed, %d dismissed)" % (counts_line(counts), report["resolved"]["fixed"],
                                            report["resolved"]["false_positive"]))
    if blocking:
        print("Blocking (%s):" % ", ".join(block_on))
        for finding in sorted(blocking, key=sort_key):
            print("  - %s %s (%s, %s)" % (finding["id"], finding["title"], finding["severity"],
                                          location(finding)))
    else:
        print("Blocking: none")
    for gap in gaps:
        print("Coverage gap: %s" % gap)
    if report["open_questions"]:
        print("Open questions: %d (listed in the report)" % len(report["open_questions"]))
    if not_run:
        print("Scanners not run: %s (install commands are in the report)" % ", ".join(not_run))
    print("Report: %s" % md_path)
    print("SARIF (for CI code scanning): %s" % sarif_path)
    return 0


def cmd_implied_verdict(args):
    report = read_json(args.report)
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise Fail("%s is not a review report" % args.report)
    verdict, _ = compute_verdict(report["findings"], as_list(report.get("coverage_gaps")),
                                 parse_block_on(args.block_on))
    print(verdict)
    return 0


# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(prog="devsecops-review", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("capture")
    sub.add_parser("surfaces")
    p = sub.add_parser("collect")
    p.add_argument("--expect", default="")
    p.add_argument("--rebuild", action="store_true")
    p = sub.add_parser("list")
    p.add_argument("--all", action="store_true")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("show")
    p.add_argument("ids", nargs="+")
    for name in ("set", "fixed", "reject", "answer"):
        p = sub.add_parser(name)
        p.add_argument("items", nargs="*")
    p = sub.add_parser("merge")
    p.add_argument("ids", nargs="*")
    p = sub.add_parser("add")
    p.add_argument("file")
    p = sub.add_parser("verify")
    p.add_argument("file", nargs="?")
    p = sub.add_parser("report")
    p.add_argument("--block-on", default="")
    p.add_argument("--override-reason", default="")
    p.add_argument("--gap", action="append")
    p = sub.add_parser("implied-verdict")
    p.add_argument("report")
    p.add_argument("--block-on", default="")
    return parser


COMMANDS = {
    "capture": cmd_capture, "surfaces": cmd_surfaces, "collect": cmd_collect, "list": cmd_list,
    "show": cmd_show, "set": cmd_set, "merge": cmd_merge, "add": cmd_add, "fixed": cmd_fixed,
    "reject": cmd_reject, "answer": cmd_answer, "verify": cmd_verify, "report": cmd_report,
    "implied-verdict": cmd_implied_verdict,
}


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.command:
        build_parser().print_help()
        return 2
    try:
        return COMMANDS[args.command](args) or 0
    except Fail as exc:
        sys.stderr.write("devsecops-review: %s\n" % exc)
        return exc.code
    finally:
        flush_events()


if __name__ == "__main__":
    sys.exit(main())
