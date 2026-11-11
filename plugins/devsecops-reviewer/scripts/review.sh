#!/usr/bin/env bash
# Wrapper for review.py (the deterministic review bookkeeping).
#
# Usage: review.sh <command> [args...]   (see `review.py` for the commands)
#
# Picks a working Python 3 interpreter, runs review.py from the repository root,
# and ships whatever telemetry review.py produced through log-event.sh in a
# single batch (so logging many findings costs one process, not one per event).
# Exit 3 means Python 3 is not available; the security-review skill then falls
# back to merging findings by hand per finding-schema.md.
set -u

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

if ! dsr_have_python; then
  echo "devsecops-review: this step needs Python 3, which was not found on PATH." >&2
  echo "Install Python 3 (python.org), or follow the manual merge/verdict steps in the security-review skill." >&2
  exit 3
fi

# review.py writes relative to the repository root.
if root=$(dsr_repo_root 2>/dev/null) && [ -n "$root" ]; then
  cd "$root" || exit 3
fi

events=$(mktemp 2>/dev/null) || events="${TMPDIR:-/tmp}/dsr-events.$$"
: >"$events" 2>/dev/null || events=""

DSR_EVENTS_OUT="$events" "$DSR_PY" "$DSR_PLUGIN_ROOT/scripts/review.py" "$@"
rc=$?

# Flush telemetry (never let logging change the command's exit code).
if [ -n "$events" ] && [ -s "$events" ]; then
  bash "$DSR_PLUGIN_ROOT/scripts/log-event.sh" --batch <"$events" >/dev/null 2>&1 || true
fi
[ -n "$events" ] && rm -f "$events" 2>/dev/null

exit $rc
