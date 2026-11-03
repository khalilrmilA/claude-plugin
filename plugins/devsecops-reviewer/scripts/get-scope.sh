#!/usr/bin/env bash
# Compute the review scope and save it under .security-review/scope/.
#
# Usage: get-scope.sh [--all | --staged | --since <ref>]
#
#   (default)      diff of the working tree against the merge-base with the
#                  upstream branch (or origin/HEAD, main, master), which covers
#                  committed-but-unpushed, staged, unstaged and new untracked files
#   --all          every tracked and untracked (non-ignored) file
#   --staged       only what is staged in the index, against HEAD
#   --since <ref>  working tree against the merge-base with <ref>
#
# Writes:
#   scope/scope.json  review_id, mode, base, head, branch, counts, diff hash
#   scope/files.txt   "<status>\t<path>" per file (status A/M/D/R/T/?)
#   scope/scope.diff  unified diff (for --all: a note, the files are the scope)
# Prints scope.json to stdout. Exit 3 = not a git repository.
set -u

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

mode="default"
since_ref=""
while [ $# -gt 0 ]; do
  case "$1" in
    --all) mode="all"; shift;;
    --staged) mode="staged"; shift;;
    --since) mode="since"; since_ref=${2:-}; shift 2 || shift;;
    --non-interactive|--ci) shift;;  # handled by the skill, accepted here for convenience
    -h|--help) dsr_usage "$0"; exit 0;;
    *) echo "get-scope: unknown argument '$1'" >&2; exit 2;;
  esac
done

if ! dsr_have git; then
  echo '{"error":"git_not_found","message":"git is not installed or not on PATH"}'
  exit 3
fi
if ! dsr_is_git_repo; then
  echo '{"error":"not_a_git_repo","message":"current directory is not inside a git work tree"}'
  exit 3
fi

root=$(dsr_repo_root)
cd "$root" || exit 3
dsr_ensure_gitignore

state="$root/$DSR_STATE_DIR"
out="$state/scope"
mkdir -p "$out"
files="$out/files.txt"
diff_file="$out/scope.diff"
: >"$files"
: >"$diff_file"

head=$(dsr_head)
branch=$(dsr_branch)
base=""
base_ref=""
note=""

# Paths we never review: our own state directory.
filter_paths() { grep -v -E "^[^	]*	$DSR_STATE_DIR/" || true; }

add_untracked() {
  git ls-files --others --exclude-standard -z | tr '\0' '\n' | while IFS= read -r f; do
    [ -n "$f" ] && printf '?\t%s\n' "$f"
  done
}

untracked_diff() {
  git ls-files --others --exclude-standard -z | tr '\0' '\n' | while IFS= read -r f; do
    [ -z "$f" ] && continue
    case "$f" in "$DSR_STATE_DIR"/*) continue;; esac
    # Skip big files; agents can still open them by path.
    size=$(wc -c <"$f" 2>/dev/null | tr -d ' ')
    if [ "${size:-0}" -gt 1048576 ]; then
      printf 'diff --git a/%s b/%s\nnew file (%s bytes, diff omitted)\n' "$f" "$f" "$size"
      continue
    fi
    git diff --no-index --no-color -- /dev/null "$f" 2>/dev/null || true
  done
}

name_status() { # $@ = git diff args; prints "<S>\t<path>" (a rename is R new + D old)
  git -c core.quotePath=false diff --name-status -M --no-color "$@" | awk -F'\t' '
    /^R/ { print "R\t" $3; print "D\t" $2; next }
    /^C/ { print "A\t" $3; next }
    { s = substr($1, 1, 1); print s "\t" $2 }'
}

case "$mode" in
  all)
    base="$DSR_EMPTY_TREE"; base_ref="(empty tree)"
    git ls-files -z | tr '\0' '\n' | while IFS= read -r f; do
      [ -n "$f" ] && [ -e "$f" ] && printf 'A\t%s\n' "$f"
    done >"$files.tmp"
    add_untracked >>"$files.tmp"
    note="--all: every tracked and untracked non-ignored file is in scope; no diff is produced."
    printf '# %s\n' "$note" >"$diff_file"
    ;;
  staged)
    if [ -n "$head" ]; then base="$head"; base_ref="HEAD"; else base="$DSR_EMPTY_TREE"; base_ref="(empty tree)"; fi
    name_status --cached "$base" >"$files.tmp"
    git diff --cached --no-color "$base" >"$diff_file"
    ;;
  since|default)
    if [ "$mode" = "since" ]; then
      if [ -z "$since_ref" ] || ! git rev-parse --verify -q "$since_ref^{commit}" >/dev/null; then
        echo "{\"error\":\"bad_ref\",\"message\":\"--since needs a valid commit-ish, got '$(dsr_json_escape "$since_ref")'\"}"
        exit 2
      fi
      base_ref="$since_ref"
    else
      base_ref=$(dsr_default_base_ref || true)
    fi
    if [ -n "$base_ref" ] && [ -n "$head" ]; then
      base=$(git merge-base HEAD "$base_ref" 2>/dev/null || true)
    fi
    if [ -z "$base" ]; then
      # No upstream and no main/master to compare with (e.g. a fresh repo):
      # review everything that would be pushed.
      if [ -n "$head" ] && [ -z "$base_ref" ]; then
        note="No upstream or main/master branch found; comparing against the empty tree (all committed files plus local changes)."
      elif [ -n "$base_ref" ]; then
        note="No merge-base with $base_ref; comparing against the empty tree."
      else
        note="Repository has no commits yet; reviewing staged and untracked files."
      fi
      base="$DSR_EMPTY_TREE"
      [ -z "$base_ref" ] && base_ref="(empty tree)"
    fi
    if [ -n "$head" ]; then
      name_status "$base" >"$files.tmp"
      git diff --no-color -M "$base" >"$diff_file"
    else
      name_status --cached "$base" >"$files.tmp"
      git diff --cached --no-color "$base" >"$diff_file"
    fi
    add_untracked >>"$files.tmp"
    untracked_diff >>"$diff_file"
    ;;
esac

filter_paths <"$files.tmp" | awk -F'\t' '!seen[$2]++' >"$files"
rm -f "$files.tmp"

count_status() { awk -F'\t' -v s="$1" '$1==s' "$files" | wc -l | tr -d ' '; }
total=$(wc -l <"$files" | tr -d ' ')
dirty="false"
if [ -n "$(git status --porcelain --untracked-files=normal -- . ":(exclude)$DSR_STATE_DIR" 2>/dev/null)" ]; then
  dirty="true"
fi

if [ "$mode" = "all" ]; then
  diff_hash=$( { git ls-files -s; add_untracked; } | dsr_sha256)
else
  diff_hash=$(dsr_sha256 <"$diff_file")
fi

review_id="$(dsr_now_compact)-$(printf '%s' "$head$RANDOM$$" | dsr_sha256 | cut -c1-6)"

cat >"$out/scope.json" <<EOF
{
  "review_id": "$review_id",
  "created_at": "$(dsr_now_iso)",
  "mode": "$mode",
  "since_ref": "$(dsr_json_escape "$since_ref")",
  "base": "$base",
  "base_ref": "$(dsr_json_escape "$base_ref")",
  "head": "$head",
  "branch": "$(dsr_json_escape "$branch")",
  "dirty": $dirty,
  "file_count": $total,
  "added": $(( $(count_status A) + $(count_status '?') )),
  "modified": $(( $(count_status M) + $(count_status T) + $(count_status R) )),
  "deleted": $(count_status D),
  "diff_sha256": "$diff_hash",
  "diff_lines": $(wc -l <"$diff_file" | tr -d ' '),
  "files_list": "$DSR_STATE_DIR/scope/files.txt",
  "diff_file": "$DSR_STATE_DIR/scope/scope.diff",
  "note": "$(dsr_json_escape "$note")"
}
EOF

cat "$out/scope.json"
