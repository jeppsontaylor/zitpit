#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="${ROOT}/scripts/protected_ssh_demo.sh"
SSH_CONFIG_PATH="${ROOT}/.zitpit/demo/ssh/zitpit-demo.sshconfig"
SSH_KEY_PATH="${ROOT}/.zitpit/demo/ssh/id_ed25519"

usage() {
  cat <<EOF
Usage:
  ${SCRIPT_PATH} up
  ${SCRIPT_PATH} down
  ${SCRIPT_PATH} status
  ${SCRIPT_PATH} smoke

Commands:
  up      Build and start the local ZitPit demo, then write an SSH config file.
  down    Stop and remove the local ZitPit demo.
  status  Check service health.
  smoke   Run the automated demo smoke checks.
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

require_docker() {
  if command -v docker >/dev/null 2>&1; then
    return 0
  fi

  if [[ -n "${DOCKER_BIN:-}" ]] && [[ -x "${DOCKER_BIN}" ]]; then
    return 0
  fi

  if [[ -x "/opt/homebrew/bin/docker" ]]; then
    export DOCKER_BIN="/opt/homebrew/bin/docker"
    return 0
  fi

  if [[ -x "/usr/local/bin/docker" ]]; then
    export DOCKER_BIN="/usr/local/bin/docker"
    return 0
  fi

  printf 'Docker was not found. Install Docker Desktop or set DOCKER_BIN.\n' >&2
  exit 1
}

run_xtask() {
  (cd "${ROOT}" && cargo run -p xtask -- "$@")
}

write_ssh_config() {
  mkdir -p "$(dirname "${SSH_CONFIG_PATH}")"
  run_xtask demo ssh-config > "${SSH_CONFIG_PATH}"
}

print_up_instructions() {
  cat <<EOF

ZitPit protected SSH demo is ready.

Repository root:
  ${ROOT}

SSH config file:
  ${SSH_CONFIG_PATH}

SSH private key:
  ${SSH_KEY_PATH}

Direct terminal test:
  ssh -F "${SSH_CONFIG_PATH}" zitpit

Quick non-interactive test:
  ssh -F "${SSH_CONFIG_PATH}" zitpit pwd

Automated smoke test:
  ${SCRIPT_PATH} smoke

Stop the demo:
  ${SCRIPT_PATH} down

For Antigravity / Cursor / Codex:
  Use host: zitpit
  Use the SSH config file above, or copy that Host block into your normal ~/.ssh/config
  Start a brand new SSH session so the protected tmux banner is negotiated from login
EOF
}

main() {
  local command="${1:-up}"

  case "${command}" in
    up)
      require_cmd cargo
      require_cmd ssh
      require_docker
      run_xtask demo up
      write_ssh_config
      print_up_instructions
      ;;
    down)
      require_cmd cargo
      require_docker
      run_xtask demo down
      ;;
    status)
      require_cmd cargo
      run_xtask demo status
      ;;
    smoke)
      require_cmd cargo
      require_docker
      write_ssh_config
      run_xtask demo smoke
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      printf 'Unknown command: %s\n\n' "${command}" >&2
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
