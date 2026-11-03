#!/usr/bin/env bash
# Shared helpers for devsecops-reviewer scripts. Source this file; don't run it.
# Portable across Linux, macOS (bash 3.2) and Git Bash on Windows. No jq needed.

# shellcheck disable=SC2034  # used by the scripts that source this file
DSR_SCHEMA_VERSION=1
DSR_STATE_DIR=".security-review"
DSR_EMPTY_TREE="4b825dc642cb6eb9a060e54bf8d69288fbee4904"

DSR_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DSR_PLUGIN_ROOT="$(cd "$DSR_LIB_DIR/../.." && pwd)"

dsr_plugin_version() {
  local manifest="$DSR_PLUGIN_ROOT/.claude-plugin/plugin.json"
  if [ -f "$manifest" ]; then
    sed -nE 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$manifest" | head -n1
  else
    echo "unknown"
  fi
}

dsr_now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }
dsr_now_compact() { date -u +%Y%m%dT%H%M%SZ; }

# Escape a string for inclusion inside a JSON string literal.
dsr_json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  # Drop remaining control characters rather than emit invalid JSON.
  printf '%s' "$s" | LC_ALL=C tr -d '\000-\010\013\014\016-\037'
}

# Print a working python interpreter name, or return 1. Skips the Windows
# Store "python3" stub, which exists on PATH but can't run code.
# Call dsr_have_python in the main shell (not inside $(...)) so the result is
# cached in DSR_PY for every later call.
DSR_PY=""
DSR_PY_CHECKED=""
dsr_have_python() {
  if [ -z "$DSR_PY_CHECKED" ]; then
    DSR_PY_CHECKED=1
    local c
    for c in python3 python; do
      if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import json, sys' >/dev/null 2>&1; then
        DSR_PY=$c
        break
      fi
    done
  fi
  [ -n "$DSR_PY" ]
}
dsr_python() { dsr_have_python && echo "$DSR_PY"; }

# dsr_json_get_many <path> <path>...  (JSON on stdin) -> one value per line, in
# order; the last value may span several lines. One interpreter start instead of
# one per field, which matters on Windows where process creation is slow.
dsr_json_get_many() {
  local input py p
  input=$(cat)
  if dsr_have_python; then py=$DSR_PY
    printf '%s' "$input" | "$py" -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    data = {}
out = []
for path in sys.argv[1:]:
    d = data
    for part in path.split("."):
        d = d.get(part) if isinstance(d, dict) else None
    out.append("" if d is None else (json.dumps(d) if isinstance(d, (dict, list)) else str(d)))
sys.stdout.write("\n".join(out))
' "$@" | tr -d '\r'
    return 0
  fi
  local first=1
  for p in "$@"; do
    [ $first -eq 1 ] || printf '\n'
    first=0
    printf '%s' "$input" | dsr_json_get "$p"
  done
}

# dsr_json_get <dotted.path>  (JSON on stdin)  -> prints the value as text.
# Uses python when available; otherwise falls back to a sed match on the last
# key segment, which is good enough for the flat hook payloads we read.
dsr_json_get() {
  local path=$1 input py
  input=$(cat)
  if dsr_have_python; then py=$DSR_PY
    printf '%s' "$input" | "$py" -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for part in sys.argv[1].split("."):
    if isinstance(data, dict) and part in data:
        data = data[part]
    else:
        sys.exit(0)
if isinstance(data, (dict, list)):
    print(json.dumps(data))
elif data is None:
    pass
elif isinstance(data, bool):
    print("true" if data else "false")
else:
    print(data)
' "$path" | tr -d '\r'
    return 0
  fi
  local key=${path##*.}
  printf '%s' "$input" | tr '\n' ' ' |
    sed -nE 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"(([^"\\]|\\.)*)".*/\1/p' |
    head -n1 | sed -e 's/\\"/"/g' -e 's/\\\\/\\/g'
}

dsr_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    openssl dgst -sha256 | awk '{print $NF}'
  fi
}

dsr_is_git_repo() { git rev-parse --is-inside-work-tree >/dev/null 2>&1; }

dsr_repo_root() { git rev-parse --show-toplevel 2>/dev/null; }

dsr_state_dir() {
  local root
  root=$(dsr_repo_root) || return 1
  printf '%s/%s' "$root" "$DSR_STATE_DIR"
}

# Remote URL with any embedded credentials removed (https://user:token@host/...).
dsr_remote_url() {
  local url
  url=$(git config --get remote.origin.url 2>/dev/null) || { echo ""; return 0; }
  printf '%s' "$url" | sed -E 's#(https?://)[^/@]*@#\1#'
}

dsr_repo_name() {
  local url name
  url=$(dsr_remote_url)
  if [ -n "$url" ]; then
    name=$(basename "$url")
    name=${name%.git}
  else
    name=$(basename "$(dsr_repo_root 2>/dev/null || pwd)")
  fi
  printf '%s' "$name"
}

dsr_branch() { git rev-parse --abbrev-ref HEAD 2>/dev/null || echo ""; }
dsr_head() { git rev-parse --verify -q HEAD 2>/dev/null || echo ""; }
dsr_developer() { git config --get user.email 2>/dev/null || echo ""; }

# Find the ref this branch will be compared against when nothing else is given:
# its upstream, else the remote default branch, else local main/master.
dsr_default_base_ref() {
  local ref current
  if ref=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null) && [ -n "$ref" ]; then
    echo "$ref"; return 0
  fi
  current=$(dsr_branch)
  if ref=$(git symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null) && [ -n "$ref" ]; then
    echo "$ref"; return 0
  fi
  for ref in origin/main origin/master main master; do
    [ "$ref" = "$current" ] && continue
    if git rev-parse --verify -q "$ref^{commit}" >/dev/null 2>&1; then
      echo "$ref"; return 0
    fi
  done
  return 1
}

# Make sure .security-review/ is ignored by git in the current repo.
dsr_ensure_gitignore() {
  local root gi
  root=$(dsr_repo_root) || return 1
  gi="$root/.gitignore"
  if git -C "$root" check-ignore -q "$DSR_STATE_DIR/probe" 2>/dev/null; then
    return 0
  fi
  if [ -f "$gi" ] && [ -s "$gi" ] && [ "$(tail -c1 "$gi" | od -An -c | tr -d ' ')" != '\n' ]; then
    printf '\n' >>"$gi"
  fi
  printf '%s\n' "# devsecops-reviewer local state (stamps, reports, logs)" "$DSR_STATE_DIR/" >>"$gi"
  echo "added $DSR_STATE_DIR/ to .gitignore" >&2
}

dsr_have() { command -v "$1" >/dev/null 2>&1; }

# Print a script's header comment (everything after the shebang up to the first
# non-comment line) as its --help text.
dsr_usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$1"; }
