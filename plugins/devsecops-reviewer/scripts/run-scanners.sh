#!/usr/bin/env bash
# Run the deterministic scanners that are installed, limited to the review scope.
#
# Usage: run-scanners.sh [--files <list>] [--all] [--only gitleaks,semgrep,...] [--timeout <sec>]
#
#   --files <list>  newline-separated paths to scan (default: .security-review/scope/files.txt)
#   --all           scan the whole repository instead of a file list
#   --only          comma-separated subset of scanners to run
#
# Results go to .security-review/scans/<tool>.json, and a summary to
# .security-review/scans/summary.json (also printed). A missing scanner is
# recorded as "not_installed" with its install command; it never fails the run.
#
# Env overrides:
#   DSR_SEMGREP_CONFIGS  space-separated semgrep --config values
#                        (default: "p/security-audit p/secrets p/owasp-top-ten")
#   DSR_SCANNER_TIMEOUT  per-scanner timeout in seconds (default 300)
set -u

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

files_list=""
scan_all="false"
only=""
timeout_s=${DSR_SCANNER_TIMEOUT:-300}
while [ $# -gt 0 ]; do
  case "$1" in
    --files) files_list=${2:-}; shift 2;;
    --all) scan_all="true"; shift;;
    --only) only=${2:-}; shift 2;;
    --timeout) timeout_s=${2:-300}; shift 2;;
    -h|--help) dsr_usage "$0"; exit 0;;
    *) echo "run-scanners: unknown argument '$1'" >&2; exit 2;;
  esac
done

dsr_is_git_repo || { echo '{"error":"not_a_git_repo"}'; exit 3; }
root=$(dsr_repo_root)
cd "$root" || exit 3
state="$root/$DSR_STATE_DIR"
scans="$state/scans"
mkdir -p "$scans"
rm -f "$scans"/*.json "$scans"/*.log 2>/dev/null

if [ "$scan_all" = "false" ]; then
  [ -n "$files_list" ] || files_list="$state/scope/files.txt"
  if [ ! -f "$files_list" ]; then
    echo "run-scanners: no file list at $files_list (run get-scope.sh first or pass --all)" >&2
    exit 2
  fi
fi

# Existing (non-deleted) files in scope, one per line.
targets="$scans/targets.txt"
if [ "$scan_all" = "true" ]; then
  { git ls-files; git ls-files --others --exclude-standard; } | grep -v "^$DSR_STATE_DIR/" >"$targets"
else
  awk -F'\t' 'NF==2 && $1!="D" {print $2} NF==1 {print $1}' "$files_list" >"$targets"
fi
tmp_targets=$(mktemp); while IFS= read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done <"$targets" >"$tmp_targets"; mv "$tmp_targets" "$targets"
target_count=$(wc -l <"$targets" | tr -d ' ')

run_with_timeout() {
  if dsr_have timeout; then timeout "$timeout_s" "$@"; else "$@"; fi
}

wanted() { [ -z "$only" ] && return 0; case ",$only," in *",$1,"*) return 0;; esac; return 1; }

results=()
missing=()
record() { # tool status output_file findings note install_hint
  results+=("{\"tool\":\"$1\",\"status\":\"$2\",\"output\":\"$(dsr_json_escape "$3")\",\"findings\":${4:-null},\"note\":\"$(dsr_json_escape "${5:-}")\"}")
  if [ "$2" = "not_installed" ]; then
    missing+=("{\"tool\":\"$1\",\"install\":\"$(dsr_json_escape "${6:-}")\"}")
    printf '  %-14s NOT RUN (not installed)  install: %s\n' "$1" "${6:-}" >&2
  else
    printf '  %-14s %-14s %s %s\n' "$1" "$2" "${4:-}" "${5:-}" >&2
  fi
}

# Count JSON findings: python if possible, else a rough grep.
count_json() { # file key-path ("results" | "matches" | "" for top-level array)
  local f=$1 key=$2 py
  [ -s "$f" ] || { echo 0; return; }
  if dsr_have_python; then py=$DSR_PY
    { "$py" - "$f" "$key" 2>/dev/null || echo null; } <<'PY' | tr -d '\r'
import json, sys
path, key = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8", errors="replace") as fh:
    data = json.load(fh)
def walk(d, k):
    for part in [p for p in k.split(".") if p]:
        d = d.get(part, []) if isinstance(d, dict) else []
    return d
d = walk(data, key)
if key == "osv":
    n = sum(len(p.get("vulnerabilities", [])) for r in data.get("results", []) for p in r.get("packages", []))
elif key == "npm":
    n = len(data.get("vulnerabilities", {})) if isinstance(data.get("vulnerabilities"), dict) else len(data.get("advisories", {}))
elif key == "composer":
    adv = data.get("advisories", {})
    n = sum(len(v) for v in adv.values()) if isinstance(adv, dict) else len(adv)
elif key == "pip":
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    n = sum(len(x.get("vulns", [])) for x in deps)
else:
    n = len(d) if isinstance(d, (list, dict)) else 0
print(n)
PY
  else
    echo null
  fi
}

echo "Scanners (scope: $( [ "$scan_all" = true ] && echo 'whole repo' || echo "$target_count files")):" >&2

# --- gitleaks (secrets) ------------------------------------------------------
if wanted gitleaks; then
  if dsr_have gitleaks; then
    out="$scans/gitleaks.json"
    if [ "$scan_all" = "true" ]; then src="$root"; else
      # Copy just the scoped files to a temp tree so reported paths stay repo-relative.
      src=$(mktemp -d)
      while IFS= read -r f; do mkdir -p "$src/$(dirname "$f")" && cp "$f" "$src/$f"; done <"$targets"
    fi
    if (cd "$src" && run_with_timeout gitleaks dir . --no-banner --redact --exit-code 0 \
          --report-format json --report-path "$out" >"$scans/gitleaks.log" 2>&1) ||
       (cd "$src" && run_with_timeout gitleaks detect --no-git --source . --no-banner --redact --exit-code 0 \
          --report-format json --report-path "$out" >>"$scans/gitleaks.log" 2>&1); then
      record gitleaks ran "$DSR_STATE_DIR/scans/gitleaks.json" "$(count_json "$out" "")"
    else
      record gitleaks error "$DSR_STATE_DIR/scans/gitleaks.log" null "see log"
    fi
    [ "$scan_all" = "true" ] || rm -rf "$src"
  else
    record gitleaks not_installed "" null "" "brew install gitleaks | winget install Gitleaks.Gitleaks | https://github.com/gitleaks/gitleaks/releases"
  fi
fi

# --- semgrep (code patterns) -------------------------------------------------
if wanted semgrep; then
  if dsr_have semgrep; then
    out="$scans/semgrep.json"
    cfg_args=()
    for c in ${DSR_SEMGREP_CONFIGS:-p/security-audit p/secrets p/owasp-top-ten}; do cfg_args+=(--config "$c"); done
    if [ "$target_count" -eq 0 ] && [ "$scan_all" = "false" ]; then
      record semgrep skipped "" 0 "no files in scope"
    else
      if [ "$scan_all" = "true" ]; then set -- .; else set --; while IFS= read -r f; do set -- "$@" "$f"; done <"$targets"; fi
      if run_with_timeout semgrep scan "${cfg_args[@]}" --json --output "$out" --metrics=off --quiet "$@" \
           >"$scans/semgrep.log" 2>&1 || [ -s "$out" ]; then
        record semgrep ran "$DSR_STATE_DIR/scans/semgrep.json" "$(count_json "$out" results)"
      else
        record semgrep error "$DSR_STATE_DIR/scans/semgrep.log" null "see log (registry rules need network; set DSR_SEMGREP_CONFIGS to local rules offline)"
      fi
    fi
  else
    record semgrep not_installed "" null "" "pipx install semgrep | brew install semgrep (Windows: use WSL or Docker semgrep/semgrep)"
  fi
fi

# --- dependency audits ----------------------------------------------------------
# These audit the lockfiles of the whole repo: a vulnerable transitive version
# can be introduced without touching any file in the diff.
if wanted osv-scanner; then
  if dsr_have osv-scanner; then
    out="$scans/osv-scanner.json"
    if run_with_timeout osv-scanner scan source -r --format json --output "$out" . >"$scans/osv-scanner.log" 2>&1 || [ -s "$out" ] ||
       run_with_timeout osv-scanner --format json --output "$out" -r . >>"$scans/osv-scanner.log" 2>&1 || [ -s "$out" ]; then
      record osv-scanner ran "$DSR_STATE_DIR/scans/osv-scanner.json" "$(count_json "$out" osv)" "all lockfiles in repo"
    else
      record osv-scanner error "$DSR_STATE_DIR/scans/osv-scanner.log" null "see log"
    fi
  else
    record osv-scanner not_installed "" null "" "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest | brew install osv-scanner | winget install Google.OSVScanner"
  fi
fi

if wanted npm-audit && [ -f package-lock.json ]; then
  if dsr_have npm; then
    out="$scans/npm-audit.json"
    run_with_timeout npm audit --json --package-lock-only >"$out" 2>"$scans/npm-audit.log" || true
    if [ -s "$out" ]; then record npm-audit ran "$DSR_STATE_DIR/scans/npm-audit.json" "$(count_json "$out" npm)"
    else record npm-audit error "$DSR_STATE_DIR/scans/npm-audit.log" null "see log (needs network)"; fi
  else
    record npm-audit not_installed "" null "" "install Node.js (includes npm): https://nodejs.org"
  fi
elif wanted npm-audit && [ -f package.json ]; then
  record npm-audit skipped "" null "package.json without package-lock.json; osv-scanner or a lockfile is needed for exact versions"
fi

req_files=$(ls requirements*.txt 2>/dev/null | head -n 5)
if wanted pip-audit && [ -n "$req_files" ]; then
  if dsr_have pip-audit; then
    out="$scans/pip-audit.json"
    set --; for r in $req_files; do set -- "$@" -r "$r"; done
    run_with_timeout pip-audit "$@" --progress-spinner off -f json -o "$out" >"$scans/pip-audit.log" 2>&1 || true
    if [ -s "$out" ]; then record pip-audit ran "$DSR_STATE_DIR/scans/pip-audit.json" "$(count_json "$out" pip)"
    else record pip-audit error "$DSR_STATE_DIR/scans/pip-audit.log" null "see log"; fi
  else
    record pip-audit not_installed "" null "" "pipx install pip-audit"
  fi
fi

if wanted composer-audit && [ -f composer.lock ]; then
  if dsr_have composer; then
    out="$scans/composer-audit.json"
    run_with_timeout composer audit --format=json --locked --no-interaction >"$out" 2>"$scans/composer-audit.log" || true
    if [ -s "$out" ]; then record composer-audit ran "$DSR_STATE_DIR/scans/composer-audit.json" "$(count_json "$out" composer)"
    else record composer-audit error "$DSR_STATE_DIR/scans/composer-audit.log" null "see log"; fi
  else
    record composer-audit not_installed "" null "" "https://getcomposer.org/download/"
  fi
fi

if wanted dotnet-vulnerable && ls ./*.sln ./*.csproj >/dev/null 2>&1; then
  if dsr_have dotnet; then
    out="$scans/dotnet-vulnerable.json"
    run_with_timeout dotnet list package --vulnerable --include-transitive --format json >"$out" 2>"$scans/dotnet.log" || true
    if [ -s "$out" ]; then record dotnet-vulnerable ran "$DSR_STATE_DIR/scans/dotnet-vulnerable.json" null "needs restored packages"
    else record dotnet-vulnerable error "$DSR_STATE_DIR/scans/dotnet.log" null "see log (run dotnet restore first)"; fi
  else
    record dotnet-vulnerable not_installed "" null "" "https://dotnet.microsoft.com/download"
  fi
fi

if wanted govulncheck && [ -f go.mod ]; then
  if dsr_have govulncheck; then
    out="$scans/govulncheck.json"
    run_with_timeout govulncheck -json ./... >"$out" 2>"$scans/govulncheck.log" || true
    record govulncheck ran "$DSR_STATE_DIR/scans/govulncheck.json" null "stream JSON; look for \"finding\" objects"
  else
    record govulncheck not_installed "" null "" "go install golang.org/x/vuln/cmd/govulncheck@latest"
  fi
fi

if wanted cargo-audit && [ -f Cargo.lock ]; then
  if dsr_have cargo-audit; then
    out="$scans/cargo-audit.json"
    run_with_timeout cargo-audit audit --json >"$out" 2>"$scans/cargo-audit.log" || true
    record cargo-audit ran "$DSR_STATE_DIR/scans/cargo-audit.json" null ""
  else
    record cargo-audit not_installed "" null "" "cargo install cargo-audit"
  fi
fi

if wanted bundler-audit && [ -f Gemfile.lock ]; then
  if dsr_have bundle-audit; then
    out="$scans/bundler-audit.json"
    run_with_timeout bundle-audit check --update --format json --output "$out" >"$scans/bundler-audit.log" 2>&1 || true
    record bundler-audit ran "$DSR_STATE_DIR/scans/bundler-audit.json" null ""
  else
    record bundler-audit not_installed "" null "" "gem install bundler-audit"
  fi
fi

join() { local IFS=,; printf '%s' "$*"; }
summary=$(cat <<EOF
{
  "generated_at": "$(dsr_now_iso)",
  "scope": "$( [ "$scan_all" = true ] && echo all || echo files)",
  "target_files": $target_count,
  "results": [$(join "${results[@]+"${results[@]}"}")],
  "not_installed": [$(join "${missing[@]+"${missing[@]}"}")]
}
EOF
)
printf '%s\n' "$summary" >"$scans/summary.json"
printf '%s\n' "$summary"
