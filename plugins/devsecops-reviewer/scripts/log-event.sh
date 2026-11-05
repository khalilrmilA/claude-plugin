#!/usr/bin/env bash
# Append one telemetry event to .security-review/logs/events.jsonl.
#
# Usage:
#   log-event.sh <event_type> [--review-id ID] [--json '{"k":"v"}'] [key=value ...] [key:=<raw json>]
#
#   key=value   adds a string field to "details"
#   key:=json   adds a raw JSON value (number, bool, array, object) to "details"
#   --json      merges a whole JSON object into "details" (must be an object)
#
# The review id defaults to the one in .security-review/scope/scope.json, so
# every event from one review can be correlated; pass "--review-id -" for none.
# See README "Logs and telemetry" for the format.
set -u

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

DSR_EVENT_TYPES="review_started config_loaded scope_detected stack_detected scanner_result agent_started agent_completed finding_reported finding_verified question_asked question_answered finding_accepted finding_rejected fix_applied fix_verified verdict block_overridden push_blocked push_allowed review_error coverage_ledger_updated"

usage() {
  dsr_usage "$0"
  echo "Event types: $DSR_EVENT_TYPES"
}

[ $# -ge 1 ] || { usage >&2; exit 2; }
event=$1; shift
case "$event" in -h|--help) usage; exit 0;; esac

case " $DSR_EVENT_TYPES " in
  *" $event "*) ;;
  *) echo "log-event: unknown event type '$event'" >&2; usage >&2; exit 2;;
esac

review_id=""
details_parts=()
raw_object=""

while [ $# -gt 0 ]; do
  case "$1" in
    --review-id) review_id=${2:-}; shift 2;;
    --json) raw_object=${2:-}; shift 2;;
    *:=*)
      k=${1%%:=*}; v=${1#*:=}
      details_parts+=("\"$(dsr_json_escape "$k")\":$v"); shift;;
    *=*)
      k=${1%%=*}; v=${1#*=}
      details_parts+=("\"$(dsr_json_escape "$k")\":\"$(dsr_json_escape "$v")\""); shift;;
    *) echo "log-event: ignoring argument '$1' (expected key=value)" >&2; shift;;
  esac
done

if ! dsr_is_git_repo; then
  # Still log, next to the current directory, so not-a-repo runs are visible.
  state_dir="$PWD/$DSR_STATE_DIR"
else
  state_dir=$(dsr_state_dir)
fi
log_dir="$state_dir/logs"
mkdir -p "$log_dir" 2>/dev/null || { echo "log-event: cannot create $log_dir" >&2; exit 1; }

# "--review-id -" means "no review yet" (e.g. review_started, before the scope exists).
if [ "$review_id" = "-" ]; then
  review_id=""
elif [ -z "$review_id" ] && [ -f "$state_dir/scope/scope.json" ]; then
  review_id=$(sed -nE 's/.*"review_id"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$state_dir/scope/scope.json" | head -n1)
fi

details="{"
sep=""
for p in "${details_parts[@]+"${details_parts[@]}"}"; do
  details+="$sep$p"; sep=","
done
if [ -n "$raw_object" ]; then
  inner=$(printf '%s' "$raw_object" | sed -E 's/^[[:space:]]*\{//; s/\}[[:space:]]*$//')
  if [ -n "$(printf '%s' "$inner" | tr -d '[:space:]')" ]; then
    details+="$sep$inner"
  fi
fi
details+="}"

line=$(printf '{"schema_version":%s,"timestamp":"%s","event":"%s","review_id":"%s","repo":"%s","repo_remote":"%s","branch":"%s","commit":"%s","developer":"%s","host":"%s","plugin":"devsecops-reviewer","plugin_version":"%s","session_id":"%s","details":%s}' \
  "$DSR_SCHEMA_VERSION" \
  "$(dsr_now_iso)" \
  "$event" \
  "$(dsr_json_escape "$review_id")" \
  "$(dsr_json_escape "$(dsr_repo_name)")" \
  "$(dsr_json_escape "$(dsr_remote_url)")" \
  "$(dsr_json_escape "$(dsr_branch)")" \
  "$(dsr_head)" \
  "$(dsr_json_escape "$(dsr_developer)")" \
  "$(dsr_json_escape "$(hostname 2>/dev/null || echo unknown)")" \
  "$(dsr_plugin_version)" \
  "$(dsr_json_escape "${CLAUDE_SESSION_ID:-${DSR_SESSION_ID:-}}")" \
  "$details")

# Reject a malformed line instead of corrupting the log for downstream shippers.
if dsr_have_python; then py=$DSR_PY
  if ! printf '%s' "$line" | "$py" -c 'import json,sys; json.loads(sys.stdin.read())' 2>/dev/null; then
    echo "log-event: refusing to write invalid JSON (check --json / key:= values)" >&2
    exit 2
  fi
fi

printf '%s\n' "$line" >>"$log_dir/events.jsonl"
