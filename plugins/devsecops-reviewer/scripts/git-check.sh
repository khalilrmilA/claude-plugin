#!/usr/bin/env bash
# Diagnose whether git works here, for step 1 of the security review.
#
# Usage: git-check.sh
#
# Prints JSON: {"ok": bool, "problem": "<code>", ...}. Exit 0 when git is usable
# in a repository, 1 otherwise. Problem codes (see the git-access-setup skill):
#   git_not_found      git is not installed or not on PATH
#   not_a_git_repo     the current directory is not inside a work tree
#   dubious_ownership  git refuses the repo (safe.directory)
#   git_error          another git error; see "detail"
set -u

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

case "${1:-}" in -h|--help) dsr_usage "$0"; exit 0;; esac

emit() { # ok problem detail
  printf '{"ok":%s,"problem":"%s","detail":"%s","cwd":"%s","git_version":"%s","repo_root":"%s","has_commits":%s,"user_email_set":%s,"remote":"%s","branch":"%s","upstream":"%s"}\n' \
    "$1" "$2" "$(dsr_json_escape "$3")" "$(dsr_json_escape "$PWD")" "$(dsr_json_escape "${ver:-}")" \
    "$(dsr_json_escape "${root:-}")" "${has_commits:-false}" "${email_set:-false}" \
    "$(dsr_json_escape "${remote:-}")" "$(dsr_json_escape "${branch:-}")" "$(dsr_json_escape "${upstream:-}")"
}

if ! dsr_have git; then
  emit false git_not_found "git is not installed or not on PATH"; exit 1
fi
ver=$(git --version 2>/dev/null | sed 's/^git version //')

err=$(git rev-parse --show-toplevel 2>&1 >/dev/null)
if [ -n "$err" ]; then
  case "$err" in
    *"dubious ownership"*|*safe.directory*) emit false dubious_ownership "$err"; exit 1;;
    *"not a git repository"*) emit false not_a_git_repo "$err"; exit 1;;
    *) emit false git_error "$err"; exit 1;;
  esac
fi

root=$(dsr_repo_root)
if git rev-parse --verify -q HEAD >/dev/null 2>&1; then has_commits=true; else has_commits=false; fi
[ -n "$(dsr_developer)" ] && email_set=true || email_set=false
remote=$(dsr_remote_url)
branch=$(dsr_branch)
upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)

# A cheap command that exercises the object store.
if ! out=$(git status --porcelain 2>&1 >/dev/null) || [ -n "$out" ]; then
  emit false git_error "${out:-git status failed}"; exit 1
fi
emit true "" ""
