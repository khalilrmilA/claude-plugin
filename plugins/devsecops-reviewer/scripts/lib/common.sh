#!/usr/bin/env bash
# Shared helpers for devsecops-reviewer scripts. Source this file; don't run it.
# Portable across Linux, macOS (bash 3.2) and Git Bash on Windows. No jq needed.
#
# Process creation is slow on Windows (tens of milliseconds per fork), and some
# of these helpers run on every git command and every log line, so the hot ones
# avoid subshells: they set a variable instead of printing (the *_to functions).

# shellcheck disable=SC2034  # used by the scripts that source this file
DSR_SCHEMA_VERSION=1
DSR_STATE_DIR=".security-review"
DSR_EMPTY_TREE="4b825dc642cb6eb9a060e54bf8d69288fbee4904"

DSR_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DSR_PLUGIN_ROOT="$(cd "$DSR_LIB_DIR/../.." && pwd)"

# Read the plugin version from the manifest without spawning a process.
DSR_PLUGIN_VERSION=""
dsr_plugin_version_to() { # <var>
  if [ -z "$DSR_PLUGIN_VERSION" ]; then
    DSR_PLUGIN_VERSION="unknown"
    local manifest="$DSR_PLUGIN_ROOT/.claude-plugin/plugin.json" line
    if [ -f "$manifest" ]; then
      while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
          *'"version"'*)
            line=${line#*\"version\"}; line=${line#*\"}; line=${line%%\"*}
            [ -n "$line" ] && DSR_PLUGIN_VERSION=$line
            break;;
        esac
      done <"$manifest"
    fi
  fi
  printf -v "$1" '%s' "$DSR_PLUGIN_VERSION"
}
dsr_plugin_version() { local v; dsr_plugin_version_to v; printf '%s\n' "$v"; }

# UTC timestamps. bash >= 4.2 can read the epoch with a builtin; the calendar
# date is then derived arithmetically, because printf's %()T formats in the
# local time zone and overriding TZ is not honoured on every platform. Older
# bash calls date.
dsr_now_iso_to() { # <var>
  local __e=""
  if [ -n "${EPOCHSECONDS:-}" ]; then
    __e=$EPOCHSECONDS
  elif [ "${BASH_VERSINFO[0]:-3}" -gt 4 ] || { [ "${BASH_VERSINFO[0]:-3}" -eq 4 ] && [ "${BASH_VERSINFO[1]:-0}" -ge 2 ]; }; then
    printf -v __e '%(%s)T' -1
  fi
  case "$__e" in
    ''|*[!0-9]*) printf -v "$1" '%s' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; return 0;;
  esac
  dsr_epoch_to_iso_to "$1" "$__e"
}
# dsr_epoch_to_iso_to <var> <epoch seconds>: civil date from a day count.
dsr_epoch_to_iso_to() {
  local __e=$2
  local __days=$(( __e / 86400 )) __rem=$(( __e % 86400 ))
  local __z=$(( __days + 719468 ))
  local __era=$(( __z / 146097 ))
  local __doe=$(( __z - __era * 146097 ))
  local __yoe=$(( (__doe - __doe / 1460 + __doe / 36524 - __doe / 146096) / 365 ))
  local __doy=$(( __doe - (365 * __yoe + __yoe / 4 - __yoe / 100) ))
  local __mp=$(( (5 * __doy + 2) / 153 ))
  local __d=$(( __doy - (153 * __mp + 2) / 5 + 1 ))
  local __m=$(( __mp < 10 ? __mp + 3 : __mp - 9 ))
  local __y=$(( __yoe + __era * 400 + (__m <= 2 ? 1 : 0) ))
  printf -v "$1" '%04d-%02d-%02dT%02d:%02d:%02dZ' "$__y" "$__m" "$__d" \
    $(( __rem / 3600 )) $(( __rem % 3600 / 60 )) $(( __rem % 60 ))
}
dsr_now_iso() { local t; dsr_now_iso_to t; printf '%s\n' "$t"; }
dsr_now_compact() { date -u +%Y%m%dT%H%M%SZ; }

# dsr_json_escape_to <var> <string>: escape for a JSON string literal, no fork
# unless the value holds raw control characters (then they are dropped rather
# than emitting invalid JSON).
dsr_json_escape_to() {
  local LC_ALL=C __s=$2
  __s=${__s//\\/\\\\}
  __s=${__s//\"/\\\"}
  __s=${__s//$'\n'/\\n}
  __s=${__s//$'\r'/\\r}
  __s=${__s//$'\t'/\\t}
  case "$__s" in
    *[$'\001'-$'\010'$'\013'$'\014'$'\016'-$'\037']*)
      __s=$(printf '%s' "$__s" | tr -d '\000-\010\013\014\016-\037');;
  esac
  printf -v "$1" '%s' "$__s"
}
# Printing form, for callers outside the hot paths.
dsr_json_escape() { local __out; dsr_json_escape_to __out "$1"; printf '%s' "$__out"; }

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

# dsr_file_field_to <var> <file> <key>: first string or number value of "key" in
# a small flat JSON file we wrote ourselves (scope.json, stamp.json). No fork.
dsr_file_field_to() {
  local __v="" __line
  if [ -f "$2" ]; then
    while IFS= read -r __line || [ -n "$__line" ]; do
      case "$__line" in
        *"\"$3\""*)
          __line=${__line#*\"$3\"}; __line=${__line#*:}
          __line=${__line#"${__line%%[![:space:]]*}"}
          case "$__line" in
            \"*) __line=${__line#\"}; __v=${__line%%\"*};;
            *) __v=${__line%%[,[:space:]\}]*};;
          esac
          break;;
      esac
    done <"$2"
  fi
  printf -v "$1" '%s' "$__v"
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
dsr_strip_url_credentials_to() { # <var> <url>
  local __u=$2 __scheme __rest
  case "$__u" in
    http://*@*|https://*@*)
      __scheme=${__u%%://*}; __rest=${__u#*://}
      # Only strip when the "@" comes before the first "/" (the authority part).
      case "${__rest%%/*}" in *@*) __u="$__scheme://${__rest#*@}";; esac;;
  esac
  printf -v "$1" '%s' "$__u"
}
dsr_remote_url() {
  local url
  url=$(git config --get remote.origin.url 2>/dev/null) || { echo ""; return 0; }
  dsr_strip_url_credentials_to url "$url"
  printf '%s' "$url"
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
