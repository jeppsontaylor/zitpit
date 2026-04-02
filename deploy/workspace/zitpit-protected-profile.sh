case $- in
  *i*) ;;
  *) return 0 2>/dev/null || exit 0 ;;
esac

_zitpit_emit_terminal_identity() {
  case "${TERM:-}" in
    xterm*|screen*|tmux*|rxvt*|alacritty*|foot*|wezterm*|kitty*)
      printf '\033]2;%s\a' "${ZITPIT_WINDOW_TITLE:-ZitPit Protected SSH}"
      printf '\033]11;%s\a' "${ZITPIT_BG_COLOR:-#103a1f}"
      ;;
  esac
}

export ZITPIT_PROTECTED="${ZITPIT_PROTECTED:-1}"
export ZITPIT_WINDOW_TITLE="${ZITPIT_WINDOW_TITLE:-ZitPit Protected SSH}"
export ZITPIT_BG_COLOR="${ZITPIT_BG_COLOR:-#103a1f}"

case "${TERM:-}" in
  ""|dumb|unknown)
    export TERM="${ZITPIT_FALLBACK_TERM:-xterm-256color}"
    ;;
esac

case "${PS1:-}" in
  *"ZITPIT PROTECTED"*) ;;
  *)
    PS1='[ZITPIT PROTECTED] '"${PS1:-\\u@\\h:\\w\\$ }"
    ;;
esac

case ";${PROMPT_COMMAND:-};" in
  *";_zitpit_emit_terminal_identity;"*) ;;
  "")
    PROMPT_COMMAND="_zitpit_emit_terminal_identity"
    ;;
  *)
    PROMPT_COMMAND="_zitpit_emit_terminal_identity;${PROMPT_COMMAND}"
    ;;
esac

_zitpit_emit_terminal_identity
