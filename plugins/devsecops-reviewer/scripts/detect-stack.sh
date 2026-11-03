#!/usr/bin/env bash
# Detect languages, frameworks, package managers and infra files in the repo.
#
# Usage: detect-stack.sh [--root <dir>]
#
# Prints JSON and saves it to .security-review/stack.json. "checklists" lists
# the stack-checklists/*.md files the review should load for this repo.
set -u

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

root=""
while [ $# -gt 0 ]; do
  case "$1" in
    --root) root=${2:-}; shift 2;;
    -h|--help) dsr_usage "$0"; exit 0;;
    *) echo "detect-stack: unknown argument '$1'" >&2; exit 2;;
  esac
done

if [ -z "$root" ]; then
  root=$(dsr_repo_root 2>/dev/null || pwd)
fi
cd "$root" || exit 1

checklist_dir="$DSR_PLUGIN_ROOT/skills/security-review/stack-checklists"

# File inventory: tracked + untracked non-ignored when in git, else a find.
inventory=$(mktemp)
trap 'rm -f "$inventory"' EXIT
if dsr_is_git_repo; then
  { git ls-files; git ls-files --others --exclude-standard; } 2>/dev/null |
    grep -v -E '(^|/)(node_modules|vendor|\.venv|venv|dist|build|target|\.git|\.security-review)/' >"$inventory"
else
  find . -type f \
    -not -path '*/node_modules/*' -not -path '*/vendor/*' -not -path '*/.git/*' \
    -not -path '*/.venv/*' -not -path '*/venv/*' -not -path '*/.security-review/*' \
    2>/dev/null | sed 's#^\./##' >"$inventory"
fi

count_ext() { grep -c -i -E "\\.($1)$" "$inventory" 2>/dev/null || true; }
has_file() { grep -q -E "(^|/)($1)$" "$inventory" 2>/dev/null; }
files_named() { grep -E "(^|/)($1)$" "$inventory" 2>/dev/null | head -n 50; }

# Search manifests for a dependency/framework marker.
manifest_has() { # $1 = manifest name regex, $2 = content regex (ERE, case-insensitive)
  local f
  while IFS= read -r f; do
    [ -f "$f" ] && grep -q -i -E "$2" "$f" 2>/dev/null && return 0
  done <<EOF
$(files_named "$1")
EOF
  return 1
}

languages=()
add_lang() { local n; n=$(count_ext "$2"); [ "${n:-0}" -gt 0 ] && languages+=("{\"name\":\"$1\",\"files\":$n}"); }
add_lang python "py"
add_lang javascript "js|jsx|mjs|cjs"
add_lang typescript "ts|tsx"
add_lang php "php|phtml"
add_lang java "java"
add_lang kotlin "kt|kts"
add_lang csharp "cs|cshtml|razor"
add_lang go "go"
add_lang ruby "rb|erb"
add_lang rust "rs"
add_lang c_cpp "c|cc|cpp|h|hpp"
add_lang swift "swift"
add_lang scala "scala"
add_lang shell "sh|bash"
add_lang sql "sql"
add_lang html_templates "html|htm|jinja|jinja2|j2|twig|hbs|ejs|pug|vue|svelte"

frameworks=()
checklists=()
add_fw() { frameworks+=("\"$1\""); }
add_cl() { [ -f "$checklist_dir/$1.md" ] && checklists+=("\"$1\""); }

# Python
if manifest_has 'requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py|setup\.cfg' '(^|[^a-z])django([^a-z]|$)'; then add_fw django; add_cl python-django; fi
if manifest_has 'requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py|setup\.cfg' '(^|[^a-z-])flask([^a-z-]|$)'; then add_fw flask; add_cl python-flask-fastapi; fi
if manifest_has 'requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py|setup\.cfg' 'fastapi'; then add_fw fastapi; add_cl python-flask-fastapi; fi
# JavaScript / TypeScript
if manifest_has 'package\.json' '"express"'; then add_fw express; add_cl node-express; fi
if manifest_has 'package\.json' '"(koa|fastify|@nestjs/core|hapi|@hapi/hapi)"'; then add_fw node-server; add_cl node-express; fi
if manifest_has 'package\.json' '"next"'; then add_fw nextjs; add_cl node-express; add_cl frontend-spa; fi
if manifest_has 'package\.json' '"(react|vue|@angular/core|svelte)"'; then add_fw frontend-spa; add_cl frontend-spa; fi
# PHP
if has_file 'composer\.json' || [ "$(count_ext 'php')" -gt 0 ]; then add_cl php; fi
if manifest_has 'composer\.json' 'laravel/framework'; then add_fw laravel; fi
if manifest_has 'composer\.json' 'symfony/'; then add_fw symfony; fi
# JVM
if manifest_has 'pom\.xml|build\.gradle|build\.gradle\.kts' 'spring-boot|springframework'; then add_fw spring; add_cl java-spring; fi
if [ "$(count_ext 'java|kt')" -gt 0 ]; then add_cl java-spring; fi
# .NET
if [ "$(count_ext 'cs|csproj')" -gt 0 ] || has_file '[^/]*\.csproj|[^/]*\.sln'; then add_fw dotnet; add_cl dotnet-aspnet; fi
# Go / Ruby
if has_file 'go\.mod'; then add_fw go; add_cl go; fi
if manifest_has 'Gemfile' 'rails'; then add_fw rails; add_cl ruby-rails; fi
# Infra / CI
infra=()
if has_file 'Dockerfile|[^/]*\.Dockerfile|docker-compose[^/]*\.ya?ml|compose\.ya?ml'; then infra+=("\"docker\""); add_cl infra-docker-k8s-iac; fi
if grep -q -i -E '\.tf$' "$inventory"; then infra+=("\"terraform\""); add_cl infra-docker-k8s-iac; fi
if grep -q -E '(^|/)(k8s|kubernetes|helm|charts)/' "$inventory" || grep -q -E '(^|/)Chart\.yaml$' "$inventory"; then infra+=("\"kubernetes\""); add_cl infra-docker-k8s-iac; fi
if grep -q -E '^\.github/workflows/' "$inventory" || has_file '\.gitlab-ci\.yml|Jenkinsfile|azure-pipelines\.yml|bitbucket-pipelines\.yml|\.circleci/config\.yml'; then infra+=("\"ci\""); add_cl ci-pipelines; fi
# Always relevant
add_cl general

package_managers=()
add_pm() { has_file "$2" && package_managers+=("{\"name\":\"$1\",\"manifests\":[$(files_named "$2" | head -n 10 | sed 's/.*/"&"/' | paste -sd, -)]}"); }
add_pm npm 'package-lock\.json'
add_pm yarn 'yarn\.lock'
add_pm pnpm 'pnpm-lock\.yaml'
add_pm node-manifest 'package\.json'
add_pm pip 'requirements[^/]*\.txt'
add_pm poetry 'poetry\.lock'
add_pm pipenv 'Pipfile\.lock'
add_pm python-project 'pyproject\.toml'
add_pm composer 'composer\.(json|lock)'
add_pm maven 'pom\.xml'
add_pm gradle 'build\.gradle(\.kts)?'
add_pm nuget '[^/]*\.csproj|packages\.config'
add_pm go 'go\.(mod|sum)'
add_pm bundler 'Gemfile(\.lock)?'
add_pm cargo 'Cargo\.(toml|lock)'

# De-duplicate JSON string arrays while keeping order.
uniq_join() { printf '%s\n' "$@" | awk 'NF && !seen[$0]++' | paste -sd, -; }

json=$(cat <<EOF
{
  "root": "$(dsr_json_escape "$root")",
  "detected_at": "$(dsr_now_iso)",
  "languages": [$(uniq_join "${languages[@]+"${languages[@]}"}")],
  "frameworks": [$(uniq_join "${frameworks[@]+"${frameworks[@]}"}")],
  "package_managers": [$(uniq_join "${package_managers[@]+"${package_managers[@]}"}")],
  "infrastructure": [$(uniq_join "${infra[@]+"${infra[@]}"}")],
  "checklists": [$(uniq_join "${checklists[@]+"${checklists[@]}"}")],
  "checklist_dir": "$(dsr_json_escape "$checklist_dir")"
}
EOF
)

if dsr_is_git_repo; then
  state=$(dsr_state_dir)
  mkdir -p "$state" && printf '%s\n' "$json" >"$state/stack.json"
fi
printf '%s\n' "$json"
