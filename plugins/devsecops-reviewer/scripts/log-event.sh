#!/usr/bin/env bash
# Append telemetry events to .security-review/logs/events.jsonl.
#
# Usage:
#   log-event.sh <event_type> [--review-id ID] [--json '{"k":"v"}'] [key=value ...] [key:=<raw json>]
#   log-event.sh --batch [--review-id ID] < events.tsv
#
#   key=value   adds a string field to "details"
#   key:=json   adds a raw JSON value (number, bool, array, object) to "details"
#   --json      merges a whole JSON object into "details" (must be an object)
#   --batch     reads one event per line from stdin: TAB-separated fields, the
#               first is the event type and the rest are key=value / key:=json.
#               The repository context is computed once for the whole batch,
#               which is what makes logging many events cheap.
#
# The review id defaults to the one in .security-review/scope/scope.json, so
# every event from one review can be correlated; pass "--review-id -" for none.
# See README "Logs and telemetry" for the format.
#
# Many locals here are assigned indirectly by the dsr_*_to helpers in common.sh
# (printf -v "$1"), which shellcheck cannot follow, so it reads them as unset.
# shellcheck disable=SC2154
set -u

case "${BASH_SOURCE[0]}" in
  */*) . "${BASH_SOURCE[0]%/*}/lib/common.sh";;
  *) . "./lib/common.sh";;
esac

DSR_EVENT_TYPES="review_started config_loaded scope_detected stack_detected scanner_result coverage_ledger_updated agent_started agent_completed finding_reported finding_verified question_asked question_answered finding_accepted finding_rejected fix_applied fix_verified verdict block_overridden push_blocked push_allowed review_error"

usage() {
  dsr_usage "$0"
  echo "Event types: $DSR_EVENT_TYPES"
}

[ $# -ge 1 ] || { usage >&2; exit 2; }

batch="false"
event=""
case "$1" in
  -h|--help) usage; exit 0;;
  --batch) batch="true"; shift;;
  *) event=$1; shift;;
esac

valid_event() { case " $DSR_EVENT_TYPES " in *" $1 "*) return 0;; esac; return 1; }

if [ "$batch" = "false" ] && ! valid_event "$event"; then
  echo "log-event: unknown event type '$event'" >&2; usage >&2; exit 2
fi

review_id=""
raw_object=""
uses_raw="false"
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --review-id) review_id=${2:-}; shift 2 || shift;;
    --json) raw_object=${2:-}; uses_raw="true"; shift 2 || shift;;
    *) args+=("$1"); shift;;
  esac
done

# --- repository context, computed once --------------------------------------
# One git call gives the root, HEAD and the branch; it fails as a whole on a
# repository with no commits, so that case falls back to separate calls.
root=""; head=""; branch=""
if ctx=$(git rev-parse --show-toplevel HEAD --abbrev-ref HEAD 2>/dev/null); then
  { IFS= read -r root; IFS= read -r head; IFS= read -r branch; } <<EOF
$ctx
EOF
else
  root=$(git rev-parse --show-toplevel 2>/dev/null) || root=""
  if [ -n "$root" ]; then
    head=$(git rev-parse --verify -q HEAD 2>/dev/null) || head=""
    branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null) || branch=""
  fi
fi
if [ -n "$root" ]; then
  state_dir="$root/$DSR_STATE_DIR"
  developer=""; remote=""
  while IFS=' ' read -r cfg_key cfg_val; do
    case "$cfg_key" in
      user.email) developer=$cfg_val;;
      remote.origin.url) remote=$cfg_val;;
    esac
  done <<EOF
$(git config --get-regexp '^(user\.email|remote\.origin\.url)$' 2>/dev/null)
EOF
  dsr_strip_url_credentials_to remote "$remote"
  if [ -n "$remote" ]; then
    repo=${remote%/}; repo=${repo##*/}; repo=${repo##*:}; repo=${repo%.git}
  else
    repo=${root##*/}
  fi
else
  # Still log, next to the current directory, so not-a-repo runs are visible.
  state_dir="$PWD/$DSR_STATE_DIR"
  head=""; branch=""; developer=""; remote=""; repo=${PWD##*/}
fi
log_dir="$state_dir/logs"
[ -d "$log_dir" ] || mkdir -p "$log_dir" 2>/dev/null || { echo "log-event: cannot create $log_dir" >&2; exit 1; }

# "--review-id -" means "no review yet" (e.g. review_started, before the scope exists).
if [ "$review_id" = "-" ]; then
  review_id=""
elif [ -z "$review_id" ]; then
  dsr_file_field_to review_id "$state_dir/scope/scope.json" review_id
fi

dsr_now_iso_to now
dsr_plugin_version_to version
host=${HOSTNAME:-}
[ -n "$host" ] || host=$(hostname 2>/dev/null || echo unknown)

dsr_json_escape_to e_review "$review_id"
dsr_json_escape_to e_repo "$repo"
dsr_json_escape_to e_remote "$remote"
dsr_json_escape_to e_branch "$branch"
dsr_json_escape_to e_dev "$developer"
dsr_json_escape_to e_host "$host"
dsr_json_escape_to e_session "${CLAUDE_SESSION_ID:-${DSR_SESSION_ID:-}}"
prefix_tail=$(printf '"review_id":"%s","repo":"%s","repo_remote":"%s","branch":"%s","commit":"%s","developer":"%s","host":"%s","plugin":"devsecops-reviewer","plugin_version":"%s","session_id":"%s"' \
  "$e_review" "$e_repo" "$e_remote" "$e_branch" "$head" "$e_dev" "$e_host" "$version" "$e_session")

# build_line <event> <field>...  -> sets LINE (one JSON object)
LINE=""
build_line() {
  local ev=$1 details="{" sep="" f k v ek evv
  shift
  for f in "$@"; do
    case "$f" in
      *:=*)
        k=${f%%:=*}; v=${f#*:=}
        dsr_json_escape_to ek "$k"
        # Plain numbers and literals are safe as they are; anything else is
        # checked by a JSON parser before the line is written.
        case "$v" in
          true|false|null) ;;
          ''|-|*[!0-9.-]*|*.*.*|?*-*|.*|-.*|*.|0[0-9]*|-0[0-9]*) uses_raw="true";;
        esac
        details+="$sep\"$ek\":$v"; sep=",";;
      *=*)
        k=${f%%=*}; v=${f#*=}
        dsr_json_escape_to ek "$k"; dsr_json_escape_to evv "$v"
        details+="$sep\"$ek\":\"$evv\""; sep=",";;
      "") ;;
      *) echo "log-event: ignoring argument '$f' (expected key=value)" >&2;;
    esac
  done
  if [ -n "$raw_object" ]; then
    local inner
    inner=$(printf '%s' "$raw_object" | sed -E 's/^[[:space:]]*\{//; s/\}[[:space:]]*$//')
    if [ -n "$(printf '%s' "$inner" | tr -d '[:space:]')" ]; then
      details+="$sep$inner"
    fi
  fi
  details+="}"
  LINE="{\"schema_version\":$DSR_SCHEMA_VERSION,\"timestamp\":\"$now\",\"event\":\"$ev\",$prefix_tail,\"details\":$details}"
}

lines=()
if [ "$batch" = "true" ]; then
  while IFS= read -r row || [ -n "$row" ]; do
    row=${row%$'\r'}
    [ -n "$row" ] || continue
    IFS=$'\t' read -r -a fields <<<"$row"
    ev=${fields[0]:-}
    if ! valid_event "$ev"; then
      echo "log-event: skipping unknown event type '$ev' in batch" >&2
      continue
    fi
    build_line "$ev" "${fields[@]:1}"
    lines+=("$LINE")
  done
else
  build_line "$event" ${args[@]+"${args[@]}"}
  lines+=("$LINE")
fi

[ ${#lines[@]} -gt 0 ] || exit 0

# Raw JSON values are the only way a line can be malformed. Reject bad lines
# instead of corrupting the log for downstream shippers.
if [ "$uses_raw" = "true" ] && dsr_have_python; then
  if ! printf '%s\n' "${lines[@]}" | "$DSR_PY" -c '
import json, sys
for n, line in enumerate(sys.stdin, 1):
    line = line.strip()
    if line:
        json.loads(line)
' 2>/dev/null; then
    echo "log-event: refusing to write invalid JSON (check --json / key:= values)" >&2
    exit 2
  fi
fi

printf '%s\n' "${lines[@]}" >>"$log_dir/events.jsonl"
