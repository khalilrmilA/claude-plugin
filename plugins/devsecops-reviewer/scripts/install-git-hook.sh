#!/usr/bin/env bash
# Install the devsecops-reviewer pre-push hook into the current git repository.
#
# Usage: install-git-hook.sh [--mode check|headless|warn] [--uninstall]
#
# - Never overwrites a foreign pre-push hook: it is renamed to pre-push.chained
#   and our hook runs it first, with the same arguments and stdin.
# - Copies the stamp checker into <hooks>/devsecops-reviewer/ so the hook keeps
#   working when the plugin is updated or moved. Re-run to update it.
# - Respects core.hooksPath (husky and similar).
set -u

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

MARKER="devsecops-reviewer pre-push hook"
mode=""
uninstall="false"
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) mode=${2:-}; shift 2;;
    --uninstall) uninstall="true"; shift;;
    -h|--help) dsr_usage "$0"; exit 0;;
    *) echo "install-git-hook: unknown argument '$1'" >&2; exit 2;;
  esac
done

dsr_is_git_repo || { echo "install-git-hook: not inside a git repository" >&2; exit 3; }
root=$(dsr_repo_root)
cd "$root" || exit 3
hooks_dir=$(git rev-parse --git-path hooks)
case "$hooks_dir" in /*|[A-Za-z]:*) ;; *) hooks_dir="$root/$hooks_dir";; esac
mkdir -p "$hooks_dir"
target="$hooks_dir/pre-push"
chained="$hooks_dir/pre-push.chained"
support="$hooks_dir/devsecops-reviewer"

ours() { [ -f "$1" ] && grep -q "$MARKER" "$1" 2>/dev/null; }

if [ "$uninstall" = "true" ]; then
  if ours "$target"; then
    rm -f "$target"
    [ -f "$chained" ] && mv "$chained" "$target" && echo "restored the previous pre-push hook"
    rm -rf "$support"
    echo "devsecops-reviewer pre-push hook removed from $hooks_dir"
  else
    echo "no devsecops-reviewer pre-push hook installed in $hooks_dir"
  fi
  exit 0
fi

if [ -f "$target" ] && ! ours "$target"; then
  if [ -f "$chained" ]; then
    echo "install-git-hook: both $target and $chained exist and neither is ours." >&2
    echo "Merge them by hand, then re-run this installer." >&2
    exit 1
  fi
  mv "$target" "$chained"
  chmod +x "$chained" 2>/dev/null || true
  echo "kept your existing pre-push hook as $(basename "$chained"); it will run first"
fi

mkdir -p "$support/scripts/lib" "$support/.claude-plugin"
cp "$DSR_PLUGIN_ROOT/scripts/check-review-stamp.sh" "$DSR_PLUGIN_ROOT/scripts/log-event.sh" "$support/scripts/"
cp "$DSR_PLUGIN_ROOT/scripts/lib/common.sh" "$support/scripts/lib/"
cp "$DSR_PLUGIN_ROOT/.claude-plugin/plugin.json" "$support/.claude-plugin/"
cp "$DSR_PLUGIN_ROOT/git-hooks/pre-push" "$target"
chmod +x "$target" "$support/scripts/"*.sh 2>/dev/null || true

if [ -n "$mode" ]; then
  case "$mode" in
    check|headless|warn) git config devsecops.prePushMode "$mode";;
    *) echo "install-git-hook: --mode must be check, headless or warn" >&2; exit 2;;
  esac
fi

case "$hooks_dir" in
  "$root"/.git/*|"$root/.git") ;;
  *) echo "note: core.hooksPath points to $hooks_dir; if that directory is committed, commit the hook too or each developer must run this installer.";;
esac

echo "devsecops-reviewer pre-push hook installed in $hooks_dir (mode: $(git config --get devsecops.prePushMode 2>/dev/null || echo check))"
