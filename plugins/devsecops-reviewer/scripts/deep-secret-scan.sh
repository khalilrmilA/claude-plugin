#!/usr/bin/env bash
# Deep secret scan over the working tree and/or git history.
#
# Usage: deep-secret-scan.sh [--tree | --history | --all] [--since <ref>]
#
#   --tree      scan the current working tree only
#   --history   scan git history only
#   --all       scan both (default)
#   --since <ref>  bound history to commits after <ref> (history mode)
#
# Uses gitleaks when installed (fuller coverage); always runs a built-in
# pattern fallback so it works without it. Writes a MASKED JSON result to
# .security-review/scans/deep-secrets.json and prints a masked summary.
# Reports only: it never edits files or rewrites history.
set -u

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

mode="all"
since=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tree) mode="tree"; shift;;
    --history) mode="history"; shift;;
    --all) mode="all"; shift;;
    --since) since=${2:-}; shift 2;;
    -h|--help) dsr_usage "$0"; exit 0;;
    *) echo "deep-secret-scan: unknown argument '$1'" >&2; exit 2;;
  esac
done

dsr_is_git_repo || { echo '{"error":"not_a_git_repo"}'; exit 3; }
root=$(dsr_repo_root); cd "$root" || exit 3
state="$root/$DSR_STATE_DIR"; scans="$state/scans"
mkdir -p "$scans"
out="$scans/deep-secrets.json"
raw="$scans/deep-secrets.raw"
: > "$raw"

# Mask a secret value: keep up to 4 leading chars, then ****.
mask() { printf '%s****' "$(printf '%s' "$1" | cut -c1-4)"; }

# kind|extended-regex  (regexes kept conservative to limit false positives)
PATTERNS='
aws-access-key|AKIA[0-9A-Z]{16}
github-token|gh[pousr]_[0-9A-Za-z]{30,}
google-api-key|AIza[0-9A-Za-z_-]{30,}
slack-token|xox[baprs]-[0-9A-Za-z-]{10,}
private-key|-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----
jwt|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}
slack-webhook|hooks\.slack\.com/services/[A-Za-z0-9/]{20,}
generic-assignment|(password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)["'"'"' ]*[:=]["'"'"' ]*[0-9A-Za-z/+._-]{12,}
'

placeholder_re='your[-_ ]|example|changeme|placeholder|xxxx|<[A-Za-z_]+>|dummy|sample|test[-_]?key|FAKE|\.\.\.'

emit() { # file | line | kind | where(tree/commit) | rawmatch
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$raw"
}

have_gitleaks=false
dsr_have gitleaks && have_gitleaks=true

# ---- gitleaks path ----
run_gitleaks() { # $1=tree|history
  local gl="$scans/gitleaks-$1.json" args
  if [ "$1" = "tree" ]; then args="detect --no-git --source ."; else args="detect --source ."; [ -n "$since" ] && args="$args --log-opts=$since..HEAD"; fi
  # shellcheck disable=SC2086
  gitleaks $args -f json -r "$gl" >/dev/null 2>&1
  [ -s "$gl" ] || return 0
  if dsr_have_python; then
    "$DSR_PY" - "$gl" "$1" <<'PY' >> "$raw"
import json,sys
data=json.load(open(sys.argv[1],encoding="utf-8")); where=sys.argv[2]
for f in data:
    secret=(f.get("Secret") or f.get("Match") or "")[:64]
    loc = f.get("Commit","")[:8] if where=="history" and f.get("Commit") else "tree"
    print("\t".join([f.get("File",""),str(f.get("StartLine","")),f.get("RuleID","gitleaks"),loc,secret]))
PY
  fi
}

# ---- fallback pattern path (tree) ----
fallback_tree() {
  printf '%s\n' "$PATTERNS" | while IFS='|' read -r kind re; do
    [ -n "$kind" ] || continue
    git grep -nIE "$re" -- . 2>/dev/null | while IFS=: read -r file line rest; do
      m=$(printf '%s' "$rest" | grep -oE "$re" | head -1)
      [ -n "$m" ] || m="$rest"
      emit "$file" "$line" "$kind" "tree" "$m"
    done
  done
}

# ---- fallback pattern path (history, pickaxe) ----
fallback_history() {
  local range="--all"; [ -n "$since" ] && range="$since..HEAD"
  printf '%s\n' "$PATTERNS" | while IFS='|' read -r kind re; do
    [ -n "$kind" ] || continue
    git log $range --pickaxe-regex -S"$re" --format='%h' 2>/dev/null | sort -u | while read -r c; do
      [ -n "$c" ] || continue
      emit "(history)" "" "$kind" "$c" ""
    done
  done
}

case "$mode" in
  tree)    $have_gitleaks && run_gitleaks tree    || fallback_tree;;
  history) $have_gitleaks && run_gitleaks history || fallback_history;;
  all)     if $have_gitleaks; then run_gitleaks tree; run_gitleaks history; else fallback_tree; fallback_history; fi;;
esac

# ---- assemble masked JSON + summary ----
total=$(grep -c . "$raw" 2>/dev/null || echo 0)
findings_json="[]"
if [ "$total" -gt 0 ] && dsr_have_python; then
  findings_json=$("$DSR_PY" - "$raw" "$placeholder_re" <<'PY'
import json,sys,re
rows=[l.rstrip("\n") for l in open(sys.argv[1],encoding="utf-8") if l.strip()]
ph=re.compile(sys.argv[2], re.I)
seen=set(); out=[]
for r in rows:
    p=r.split("\t")
    while len(p)<5: p.append("")
    f,line,kind,where,secret=p[:5]
    key=(f,line,kind,where)
    if key in seen: continue
    seen.add(key)
    masked=(secret[:4]+"****") if secret else ""
    placeholder=bool(secret and ph.search(secret))
    out.append({"file":f,"line":line,"kind":kind,
                "where":"history" if where not in("tree","") else where or "tree",
                "commit":where if where not in("tree","") else "",
                "masked":masked,"likely_placeholder":placeholder})
print(json.dumps(out))
PY
)
fi

tree_n=$(printf '%s' "$findings_json" | grep -o '"where": *"tree"' | wc -l | tr -d ' ')
hist_n=$(printf '%s' "$findings_json" | grep -o '"where": *"history"' | wc -l | tr -d ' ')
tool="fallback"; $have_gitleaks && tool="gitleaks"
cat > "$out" <<EOF
{"schema":$DSR_SCHEMA_VERSION,"generated_at":"$(dsr_now_iso)","mode":"$mode","tool":"$tool","counts":{"tree":$tree_n,"history":$hist_n},"findings":$findings_json}
EOF
rm -f "$raw"

echo "deep secret scan ($tool, mode=$mode): $tree_n in tree, $hist_n in history -> $out"
if [ "$tool" = "fallback" ]; then
  echo "note: gitleaks not installed; built-in patterns ran. Install for fuller coverage: winget install Gitleaks.Gitleaks / brew install gitleaks"
fi
exit 0
