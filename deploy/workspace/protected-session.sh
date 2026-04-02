#!/usr/bin/env bash
set -euo pipefail

fatal() {
  printf 'ZitPit could not verify this SSH terminal as protected.\n' >&2
  printf '%s\n' "$1" >&2
  exit 1
}

emit_osc() {
  printf '\033]%s\a' "$1"
}

normalize_term() {
  local term="${TERM:-}"
  case "${term}" in
    ""|dumb|unknown)
      export TERM="${ZITPIT_FALLBACK_TERM:-xterm-256color}"
      ;;
  esac
}

emit_terminal_identity() {
  local term="${TERM:-}"
  case "${term}" in
    xterm*|screen*|tmux*|rxvt*|alacritty*|foot*|wezterm*|kitty*)
      emit_osc "2;${ZITPIT_WINDOW_TITLE:-ZitPit Protected SSH}"
      emit_osc "11;${ZITPIT_BG_COLOR:-#103a1f}"
      export ZITPIT_OSC_IDENTITY_ACTIVE=1
      ;;
  esac
}

reset_terminal_identity() {
  case "${ZITPIT_OSC_IDENTITY_ACTIVE:-0}" in
    1)
      # Reset dynamic colors to the terminal's themed defaults on disconnect.
      emit_osc "110"
      emit_osc "111"
      emit_osc "112"
      ;;
  esac
}

if [[ -n "${SSH_ORIGINAL_COMMAND:-}" ]]; then
  exec /bin/bash -lc "${SSH_ORIGINAL_COMMAND}"
fi

if [[ ! -t 0 || ! -t 1 ]]; then
  fatal "Interactive login was blocked because the protected terminal UI could not be attached."
fi

TMUX_BIN="${ZITPIT_TMUX_BIN:-$(command -v tmux || true)}"
TMUX_CONF="${ZITPIT_TMUX_CONF:-/etc/zitpit/tmux-protected.conf}"
SESSION_NAME="${ZITPIT_TMUX_SESSION_NAME:-zitpit-protected}"

if [[ -z "${TMUX_BIN}" ]]; then
  fatal "tmux is missing from the workspace image."
fi

if [[ ! -r "${TMUX_CONF}" ]]; then
  fatal "The managed tmux config is missing."
fi

export ZITPIT_PROTECTED="${ZITPIT_PROTECTED:-1}"
export ZITPIT_PROTECTED_UI="tmux"
export ZITPIT_WINDOW_TITLE="${ZITPIT_WINDOW_TITLE:-ZitPit Protected SSH}"
export ZITPIT_BG_COLOR="${ZITPIT_BG_COLOR:-#103a1f}"

normalize_term
trap reset_terminal_identity EXIT
emit_terminal_identity
"${TMUX_BIN}" -f "${TMUX_CONF}" new-session -A -s "${SESSION_NAME}"
