#!/usr/bin/env bash
# Telemetry hook handler (Claude Code hook JSON on stdin). Never blocks: always exits 0.
#
#   UserPromptExpansion  developer typed /devsecops-reviewer:security-review -> review_started
#   PreToolUse (Skill)   Claude invoked the skill on its own               -> review_started
#   SubagentStart        one of this plugin's reviewer agents started       -> agent_started
#   SubagentStop         one of this plugin's reviewer agents finished      -> agent_completed
set -u

input=$(cat)
# Cheap exit for the many events that aren't about this plugin.
case "$input" in *devsecops-reviewer*) ;; *) exit 0;; esac

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
dsr_have_python || true

# Fields used below, read in one pass. last_assistant_message goes last because
# it can span several lines.
{
  IFS= read -r event; IFS= read -r cwd; IFS= read -r command_name; IFS= read -r command_args
  IFS= read -r command_source; IFS= read -r tool_name; IFS= read -r skill; IFS= read -r skill_args
  IFS= read -r agent; IFS= read -r agent_id; IFS= read -r -d '' msg
} <<EOF
$(printf '%s' "$input" | dsr_json_get_many hook_event_name cwd command_name command_args command_source \
    tool_name tool_input.skill tool_input.args agent_type agent_id last_assistant_message)
EOF

if [ -n "$cwd" ]; then cd "$cwd" 2>/dev/null || exit 0; fi
dsr_is_git_repo || exit 0

log() { bash "$DSR_PLUGIN_ROOT/scripts/log-event.sh" "$@" >/dev/null 2>&1 || true; }

case "$event" in
  UserPromptExpansion)
    case "$command_name" in
      *devsecops-reviewer:security-review*)
        log review_started --review-id - trigger=user_command args="$command_args" command_source="$command_source";;
    esac
    ;;
  PreToolUse)
    [ "$tool_name" = "Skill" ] || exit 0
    case "$skill" in
      *devsecops-reviewer:security-review*)
        log review_started --review-id - trigger=model_invoked args="$skill_args";;
    esac
    ;;
  SubagentStart)
    case "$agent" in devsecops-reviewer:*) log agent_started agent="$agent" agent_id="$agent_id";; esac
    ;;
  SubagentStop)
    case "$agent" in
      devsecops-reviewer:*)
        count() { printf '%s' "$msg" | grep -o -i -E "\"severity\"[[:space:]]*:[[:space:]]*\"$1\"" | wc -l | tr -d ' '; }
        total=$(printf '%s' "$msg" | grep -o -E '"severity"[[:space:]]*:' | wc -l | tr -d ' ')
        log agent_completed agent="$agent" agent_id="$agent_id" findings:="${total:-0}" \
          critical:="$(count critical)" high:="$(count high)" medium:="$(count medium)" \
          low:="$(count low)" info:="$(count info)" output_chars:="${#msg}"
        ;;
    esac
    ;;
esac
exit 0
