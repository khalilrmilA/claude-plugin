#!/usr/bin/env bash
# Run the security review non-interactively on each fixture and score the output.
#
# Usage: run-evals.sh [--fixture <name>] [--model <alias>] [--keep] [--no-score]
#
# For each fixture under evals/fixtures/:
#   1. copy it to evals/.work/<fixture> (a throwaway git repo),
#   2. run `claude -p "/devsecops-reviewer:security-review --all --non-interactive"`
#      with only this plugin loaded (--plugin-dir),
#   3. copy the produced report JSON to evals/results/<ts>/actual/<fixture>.json,
#   4. after all fixtures, run score.py and write evals/results/<ts>/report.md.
#
# Requires the `claude` CLI, git and python3. Dependency findings are only
# expected when a dependency scanner (osv-scanner/npm/pip-audit/composer) is
# installed; otherwise they are excluded from scoring (--no-scanners).
set -u

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
plugin_dir="$repo_root/plugins/devsecops-reviewer"
fixtures_dir="$here/fixtures"
ts="$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="$here/results/$ts"
actual_dir="$out_dir/actual"
transcripts_dir="$out_dir/transcripts"
# Per-run work dir (under results/) so concurrent runs never collide.
work_dir="$out_dir/work"

only=""
model=""
keep="false"
do_score="true"
while [ $# -gt 0 ]; do
  case "$1" in
    --fixture) only=${2:-}; shift 2;;
    --model) model=${2:-}; shift 2;;
    --keep) keep="true"; shift;;
    --no-score) do_score="false"; shift;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "run-evals: unknown argument '$1'" >&2; exit 2;;
  esac
done

command -v claude >/dev/null 2>&1 || { echo "run-evals: 'claude' CLI not found on PATH" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "run-evals: git not found" >&2; exit 2; }
PY=python3; command -v python3 >/dev/null 2>&1 || PY=python

mkdir -p "$actual_dir" "$transcripts_dir"

# Which dependency scanners are installed? Controls which ecosystems' dep
# findings are graded (osv-scanner covers all; npm/pip-audit/composer are
# ecosystem-specific). A JS tool must not make Maven/pip findings count.
installed_scanners=""
for t in osv-scanner npm pip-audit composer; do
  if command -v "$t" >/dev/null 2>&1; then
    installed_scanners="${installed_scanners:+$installed_scanners,}$t"
  fi
done
if [ -n "$installed_scanners" ]; then
  score_scanner_args=(--installed-scanners "$installed_scanners")
else
  score_scanner_args=(--no-scanners)
fi

model_args=()
[ -n "$model" ] && model_args=(--model "$model")

echo "Plugin:   $plugin_dir"
echo "Results:  $out_dir"
if [ -n "$installed_scanners" ]; then
  echo "Scanners: $installed_scanners -> dep findings graded only for ecosystems these cover"
else
  echo "Scanners: none installed -> dependency findings excluded from scoring"
fi
echo ""

for fx in "$fixtures_dir"/*/; do
  name="$(basename "$fx")"
  [ -n "$only" ] && [ "$only" != "$name" ] && continue
  [ -f "$here/expected/$name.json" ] || { echo "skip $name (no expected file)"; continue; }

  echo "=== $name"
  w="$work_dir/$name"
  rm -rf "$w"; mkdir -p "$w"
  cp -r "$fx"/. "$w"/
  (
    cd "$w" || exit 1
    git init -q -b main
    git config user.email evals@devsecops.local
    git config user.name "eval runner"
    git config core.autocrlf false
    git add -A
    git commit -qm "fixture" || true
  )

  # Run the review. acceptEdits is harmless here because --non-interactive
  # never edits; we allow the plugin's own scripts and read-only git/tools.
  (
    cd "$w" || exit 1
    claude -p "/devsecops-reviewer:security-review --all --non-interactive" \
      --plugin-dir "$plugin_dir" \
      "${model_args[@]+"${model_args[@]}"}" \
      --permission-mode acceptEdits \
      --allowedTools "Bash(devsecops-review *),Bash(bash *),Bash(git diff *),Bash(git log *),Bash(git status *),Bash(git show *),Bash(git ls-files *),Bash(git rev-parse *),Bash(git merge-base *),Bash(git blame *),Read,Grep,Glob,Write,Agent" \
      --disallowedTools "Bash(git push *),Bash(git commit *),Bash(git reset *),Bash(git checkout *),Bash(git add *)" \
      --output-format json </dev/null >"$transcripts_dir/$name.result.json" 2>"$transcripts_dir/$name.err" || \
      echo "  (claude exited non-zero; see transcripts/$name.err)"
  )

  # The plugin writes the machine report here; take the newest.
  report="$(ls -t "$w/.security-review/reports/"*.json 2>/dev/null | head -n1)"
  if [ -n "$report" ] && [ -f "$report" ]; then
    cp "$report" "$actual_dir/$name.json"
    echo "  report: $(basename "$report")"
  else
    echo "  NO REPORT PRODUCED -> recall 0 for this fixture"
    echo '{"findings":[],"error":"no report produced"}' >"$actual_dir/$name.json"
  fi
  [ "$keep" = "false" ] && rm -rf "$w"
done

if [ "$do_score" = "true" ]; then
  echo ""
  "$PY" "$here/score.py" --expected "$here/expected" --actual "$actual_dir" \
    --out "$out_dir/report.md" "${score_scanner_args[@]}"
  rc=$?
  echo ""
  echo "Report: $out_dir/report.md"
  exit $rc
fi
