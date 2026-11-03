#!/usr/bin/env bash
# Push gate: decide whether the commits about to be pushed were security-reviewed.
#
# Usage:
#   check-review-stamp.sh                     check HEAD against its upstream; exit 0 ok, 1 not ok
#   check-review-stamp.sh --claude-hook       Claude Code PreToolUse hook (JSON on stdin)
#   check-review-stamp.sh --pre-push <remote> <url>   git pre-push hook (ref lines on stdin)
#
# A push is allowed when .security-review/stamp.json has verdict PASS,
# PASS_WITH_WARNINGS or OVERRIDDEN and every file changed by the pushed commits
# has exactly the content (git blob id) that was reviewed. This keeps the stamp
# valid when the developer reviews first and commits afterwards, and makes it
# invalid as soon as anything unreviewed is committed.
#
# This script never runs the review itself; it only reads the stamp, so it is fast.
set -u

# Fast path for the Claude Code hook, which runs before every git command:
# leave without spawning anything unless the payload mentions "push".
if [ "${1:-}" = "--claude-hook" ]; then
  hook_input=$(cat)
  case "$hook_input" in *push*) ;; *) exit 0;; esac
fi

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

ZERO_SHA="0000000000000000000000000000000000000000"
SKILL_CMD="/devsecops-reviewer:security-review"
mode="manual"
case "${1:-}" in
  --claude-hook) mode="claude"; shift;;
  --pre-push) mode="prepush"; shift;;
  -h|--help) dsr_usage "$0"; exit 0;;
esac

# Logged in the background so telemetry never slows down the push decision.
log_event() {
  ( bash "$DSR_PLUGIN_ROOT/scripts/log-event.sh" "$@" >/dev/null 2>&1 </dev/null & ) >/dev/null 2>&1
}

stamp_field() { sed -nE 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$2" | head -n1; }

# evaluate <local_sha> [remote_sha]  -> sets REASON and returns 0 (allowed) / 1 (blocked)
REASON=""
evaluate() {
  local local_sha=$1 remote_sha=${2:-} root state stamp verdict base ref mismatches nfiles report
  root=$(dsr_repo_root) || { REASON=""; return 0; }
  state="$root/$DSR_STATE_DIR"
  stamp="$state/stamp.json"

  # What is being pushed: local_sha minus what the remote already has.
  base=""
  if [ -n "$remote_sha" ] && [ "$remote_sha" != "$ZERO_SHA" ] && git cat-file -e "$remote_sha^{commit}" 2>/dev/null; then
    base=$(git merge-base "$local_sha" "$remote_sha" 2>/dev/null || echo "$remote_sha")
  else
    ref=$(dsr_default_base_ref 2>/dev/null || true)
    [ -n "$ref" ] && base=$(git merge-base "$local_sha" "$ref" 2>/dev/null || true)
  fi
  [ -n "$base" ] || base="$DSR_EMPTY_TREE"

  local changes
  changes=$(git -c core.quotePath=false diff --raw --no-abbrev --no-renames "$base" "$local_sha" 2>/dev/null)
  if [ -z "$changes" ]; then
    REASON="nothing to review in the pushed range"
    return 0
  fi
  nfiles=$(printf '%s\n' "$changes" | wc -l | tr -d ' ')

  if [ ! -f "$stamp" ]; then
    REASON="no security review stamp found for this repository ($nfiles changed file(s) in the push)"
    return 1
  fi
  verdict=$(stamp_field verdict "$stamp")
  report=$(stamp_field report "$stamp")
  case "$verdict" in
    PASS|PASS_WITH_WARNINGS|OVERRIDDEN) ;;
    BLOCKED)
      REASON="the last security review verdict is BLOCKED (report: ${report:-.security-review/reports/}); fix the critical/high findings or record an override with a written reason"
      return 1;;
    *)
      REASON="the review stamp is unreadable (verdict '$verdict')"
      return 1;;
  esac
  if [ ! -f "$state/stamp.files" ]; then
    REASON="the review stamp has no file manifest; re-run the review"
    return 1
  fi

  # Compare each pushed file's blob with the reviewed blob.
  mismatches=$(printf '%s\n' "$changes" | awk -F'\t' -v manifest="$state/stamp.files" '
    BEGIN { while ((getline line < manifest) > 0) { split(line, p, "\t"); m[p[2]] = p[1] } }
    {
      split($1, meta, " "); status = substr(meta[5], 1, 1); blob = meta[4]; path = $2
      if (!(path in m)) { print "not reviewed: " path; next }
      if (status == "D") { if (m[path] != "DELETED") print "deletion not reviewed: " path; next }
      if (m[path] != blob) print "changed since review: " path
    }')
  if [ -n "$mismatches" ]; then
    local shown count
    count=$(printf '%s\n' "$mismatches" | wc -l | tr -d ' ')
    shown=$(printf '%s\n' "$mismatches" | head -n 8 | paste -sd ';' - | sed 's/;/; /g')
    [ "$count" -gt 8 ] && shown="$shown; ... ($count total)"
    REASON="the pushed commits contain code that was not covered by the last review ($shown)"
    return 1
  fi
  REASON="all $nfiles pushed file(s) match the reviewed content (verdict $verdict)"
  return 0
}

# --- git push detection for the Claude Code hook --------------------------------
# Prints each "git ... push ..." segment of a shell command line.
push_segments() {
  printf '%s\n' "$1" | tr ';&|' '\n\n\n' | while IFS= read -r seg; do
    seg=$(printf '%s' "$seg" | sed -E 's/^[[:space:]]*[({]?[[:space:]]*//; s/^([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)*//; s/^(command|exec|env)[[:space:]]+//')
    if printf '%s' "$seg" | grep -qE '^git([[:space:]]+(-C[[:space:]]+[^[:space:]]+|-c[[:space:]]+[^[:space:]]+|--[a-z-]+(=[^[:space:]]+)?))*[[:space:]]+push([[:space:]]|$)'; then
      printf '%s\n' "$seg"
    fi
  done
}

deny_json() {
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$(dsr_json_escape "$1")"
}

case "$mode" in
  claude)
    dsr_have_python || true
    { IFS= read -r hook_cwd; IFS= read -r -d '' command; } <<EOF
$(printf '%s' "$hook_input" | dsr_json_get_many cwd tool_input.command)
EOF
    [ -n "$command" ] || exit 0
    segs=$(push_segments "$command")
    [ -n "$segs" ] || exit 0
    if [ -n "$hook_cwd" ]; then cd "$hook_cwd" 2>/dev/null || exit 0; fi
    while IFS= read -r seg; do
      # Pushes that send no code: dry runs and remote branch deletions.
      if printf '%s' "$seg" | grep -qE '[[:space:]](--dry-run|-n|--delete|-d)([[:space:]]|$)|[[:space:]]:[^[:space:]]+([[:space:]]|$)'; then
        continue
      fi
      dir=$(printf '%s' "$seg" | sed -nE 's/^git[[:space:]]+(.*[[:space:]])?-C[[:space:]]+([^[:space:]]+).*/\2/p' | sed -E "s/^['\"]//; s/['\"]$//")
      if [ -n "$dir" ]; then cd "$dir" 2>/dev/null || continue; fi
      dsr_is_git_repo || continue
      head=$(dsr_head); [ -n "$head" ] || continue
      upstream=""
      upstream=$(git rev-parse --verify -q '@{u}' 2>/dev/null || true)
      if evaluate "$head" "$upstream"; then
        log_event push_allowed source=claude_hook reason="$REASON"
      else
        log_event push_blocked source=claude_hook reason="$REASON" command="$seg"
        deny_json "Push blocked by devsecops-reviewer: $REASON. Run the $SKILL_CMD skill (the devsecops-reviewer plugin skill, not the built-in /security-review), resolve its findings, then push again. Do not try to bypass this check."
        exit 0
      fi
    done <<EOF
$segs
EOF
    exit 0
    ;;

  prepush)
    remote_name=${1:-}; remote_url=${2:-}
    dsr_is_git_repo || exit 0
    blocked=0
    messages=""
    while read -r local_ref local_sha remote_ref remote_sha; do
      [ -n "${local_sha:-}" ] || continue
      [ "$local_sha" = "$ZERO_SHA" ] && continue          # deleting a remote ref
      if git cat-file -e "$local_sha^{tag}" 2>/dev/null; then continue; fi   # annotated tag
      if evaluate "$local_sha" "$remote_sha"; then
        log_event push_allowed source=git_pre_push ref="$local_ref" remote="$remote_name" reason="$REASON"
      else
        blocked=1
        messages="$messages
  $local_ref -> $remote_ref: $REASON"
        log_event push_blocked source=git_pre_push ref="$local_ref" remote="$remote_name" reason="$REASON"
      fi
    done
    if [ "$blocked" -eq 1 ]; then
      {
        echo ""
        echo "=================================================================="
        echo " Push blocked by devsecops-reviewer"
        echo "=================================================================="
        printf '%s\n' "$messages" | sed '/^$/d'
        echo ""
        echo " Run the security review in Claude Code before pushing:"
        echo "     $SKILL_CMD"
        echo " then push again. (Remote: ${remote_name:-?} ${remote_url:-})"
        echo "=================================================================="
      } >&2
      exit 1
    fi
    exit 0
    ;;

  manual)
    dsr_is_git_repo || { echo "not a git repository"; exit 1; }
    head=$(dsr_head); [ -n "$head" ] || { echo "no commits yet"; exit 0; }
    upstream=$(git rev-parse --verify -q '@{u}' 2>/dev/null || true)
    if evaluate "$head" "$upstream"; then echo "OK: $REASON"; exit 0; fi
    echo "BLOCKED: $REASON"
    exit 1
    ;;
esac
