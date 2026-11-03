#!/usr/bin/env bash
# Record the review verdict and write the push-gate stamp.
#
# Usage:
#   finalize-review.sh --verdict PASS|PASS_WITH_WARNINGS|BLOCKED
#                      [--report <path>] [--counts critical,high,medium,low,info]
#                      [--override-reason "<text>"]
#
# --override-reason turns a BLOCKED verdict into OVERRIDDEN (the push gate then
# allows it); the reason is stored in the stamp and logged as block_overridden.
#
# Writes .security-review/stamp.json and .security-review/stamp.files
# ("<blob-id>\t<path>" for every reviewed file; "DELETED" for deletions).
# The push gate accepts a push when every file it changes matches a reviewed
# blob, so committing after the review keeps the stamp valid.
set -u

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

verdict=""
report=""
counts="0,0,0,0,0"
override_reason=""
while [ $# -gt 0 ]; do
  case "$1" in
    --verdict) verdict=$(printf '%s' "${2:-}" | tr '[:lower:] -' '[:upper:]__'); shift 2;;
    --report) report=${2:-}; shift 2;;
    --counts) counts=${2:-}; shift 2;;
    --override-reason) override_reason=${2:-}; shift 2;;
    -h|--help) dsr_usage "$0"; exit 0;;
    *) echo "finalize-review: unknown argument '$1'" >&2; exit 2;;
  esac
done

case "$verdict" in
  PASS|PASS_WITH_WARNINGS|BLOCKED) ;;
  *) echo "finalize-review: --verdict must be PASS, PASS_WITH_WARNINGS or BLOCKED" >&2; exit 2;;
esac
if [ -n "$override_reason" ] && [ "$verdict" != "BLOCKED" ]; then
  echo "finalize-review: --override-reason only applies to a BLOCKED verdict" >&2; exit 2
fi
if [ "$verdict" = "BLOCKED" ] && [ -n "$override_reason" ]; then
  trimmed=$(printf '%s' "$override_reason" | tr -d '[:space:]')
  if [ ${#trimmed} -lt 15 ]; then
    echo "finalize-review: an override needs a real written reason (at least 15 characters)" >&2; exit 2
  fi
fi

dsr_is_git_repo || { echo "finalize-review: not a git repository" >&2; exit 3; }
root=$(dsr_repo_root)
cd "$root" || exit 3
state="$root/$DSR_STATE_DIR"
scope_json="$state/scope/scope.json"
files_txt="$state/scope/files.txt"
[ -f "$scope_json" ] && [ -f "$files_txt" ] || { echo "finalize-review: no scope found; run get-scope.sh first" >&2; exit 2; }
dsr_ensure_gitignore

field() { sed -nE 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"?([^",]*)"?,?$/\1/p' "$scope_json" | head -n1; }
review_id=$(field review_id)
mode=$(field mode)
base=$(field base)
diff_sha=$(field diff_sha256)
scope_head=$(field head)

IFS=, read -r c_crit c_high c_med c_low c_info <<EOF
$counts
EOF
num() { case "${1:-}" in ''|*[!0-9]*) echo 0;; *) echo "$1";; esac; }
c_crit=$(num "$c_crit"); c_high=$(num "$c_high"); c_med=$(num "$c_med")
c_low=$(num "$c_low"); c_info=$(num "$c_info")

final="$verdict"
[ -n "$override_reason" ] && final="OVERRIDDEN"

# Blob ids of the reviewed files as they are now (after any accepted fixes).
manifest="$state/stamp.files.tmp"
: >"$manifest"
existing=$(mktemp)
awk -F'\t' '$1!="D" {print $2}' "$files_txt" | while IFS= read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done >"$existing"
if [ -s "$existing" ]; then
  git hash-object --stdin-paths <"$existing" | paste - "$existing" >>"$manifest"
fi
awk -F'\t' '$1=="D" {print $2}' "$files_txt" | while IFS= read -r f; do
  [ -e "$f" ] || printf 'DELETED\t%s\n' "$f"
done >>"$manifest"
rm -f "$existing"

# Files that changed after the scope was taken but were never in it are not
# covered by this stamp; pushing them will require another review.
unreviewed=$(git status --porcelain --untracked-files=normal -- . ":(exclude)$DSR_STATE_DIR" 2>/dev/null |
  sed -E 's/^...//; s/.* -> //; s/^"(.*)"$/\1/' | while IFS= read -r f; do
    grep -q -F "	$f" "$manifest" || printf '%s\n' "$f"
  done)

head=$(dsr_head)
now=$(dsr_now_iso)
developer=$(dsr_developer)
report_rel=${report#"$root/"}

stamp_tmp="$state/stamp.json.tmp"
cat >"$stamp_tmp" <<EOF
{
  "schema_version": $DSR_SCHEMA_VERSION,
  "tool": "devsecops-reviewer",
  "plugin_version": "$(dsr_plugin_version)",
  "review_id": "$review_id",
  "verdict": "$final",
  "original_verdict": "$verdict",
  "head": "$head",
  "scope_head": "$scope_head",
  "branch": "$(dsr_json_escape "$(dsr_branch)")",
  "scope_mode": "$mode",
  "base": "$base",
  "timestamp": "$now",
  "developer": "$(dsr_json_escape "$developer")",
  "diff_sha256": "$diff_sha",
  "files_manifest": "$DSR_STATE_DIR/stamp.files",
  "files_manifest_sha256": "$(dsr_sha256 <"$manifest")",
  "reviewed_files": $(wc -l <"$manifest" | tr -d ' '),
  "report": "$(dsr_json_escape "$report_rel")",
  "counts": {"critical": $c_crit, "high": $c_high, "medium": $c_med, "low": $c_low, "info": $c_info},
  "override_reason": "$(dsr_json_escape "$override_reason")"
}
EOF
mv "$manifest" "$state/stamp.files"
mv "$stamp_tmp" "$state/stamp.json"

log="$DSR_PLUGIN_ROOT/scripts/log-event.sh"
bash "$log" verdict --review-id "$review_id" verdict="$final" original_verdict="$verdict" \
  report="$report_rel" critical:="$c_crit" high:="$c_high" medium:="$c_med" low:="$c_low" info:="$c_info" || true
if [ -n "$override_reason" ]; then
  bash "$log" block_overridden --review-id "$review_id" reason="$override_reason" \
    critical:="$c_crit" high:="$c_high" || true
fi

echo "Stamp written: $DSR_STATE_DIR/stamp.json (verdict $final, HEAD ${head:0:12}, $(wc -l <"$state/stamp.files" | tr -d ' ') files)"
if [ -n "$unreviewed" ]; then
  echo "Warning: these changed files were not part of the reviewed scope and are not covered by the stamp:"
  printf '%s\n' "$unreviewed" | sed 's/^/  /'
fi
case "$final" in
  BLOCKED) echo "Push gate: BLOCKED. Fix the critical/high findings and re-run the review, or override with a written reason.";;
  *) echo "Push gate: open for these exact file contents.";;
esac
