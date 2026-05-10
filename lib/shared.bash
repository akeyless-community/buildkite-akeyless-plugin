#!/bin/bash
set -ueo pipefail

ensure_ssh_agent() {
  if [[ -z "${SSH_AGENT_PID:-}" ]]; then
    echo "Starting an ephemeral ssh-agent" >&2
    eval "$(ssh-agent -s)"
    export EPHEMERAL_SSH_AGENT_PID="${SSH_AGENT_PID}"
  fi
}

load_ssh_keys_from_list() {
  local list_file="$1"
  [[ -f "$list_file" ]] || return 0
  ensure_ssh_agent
  while IFS= read -r keyfile || [[ -n "${keyfile:-}" ]]; do
    [[ -z "${keyfile// }" ]] && continue
    echo "Loading ssh-key from ${keyfile} into ssh-agent (pid ${SSH_AGENT_PID:-})" >&2
    env SSH_ASKPASS="/bin/false" ssh-add "$keyfile"
  done < "$list_file"
}

dump_env_diff() {
  if [[ "${BUILDKITE_PLUGIN_BUILDKITE_AKEYLESS_PLUGIN_DUMP_ENV:-}" =~ ^(true|1)$ ]]; then
    echo "~~~ Environment variables that were set" >&2
    comm -13 <(echo "$env_before") <(env | sort) || true
  fi
}
