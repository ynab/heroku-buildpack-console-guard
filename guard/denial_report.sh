# shellcheck shell=bash
# Durable record of a console-guard denial. Sourced by both halves of the guard
# (profile/console_guard.sh and guard/shim.sh); provides _cg_report_denial.
#
# WHY THIS FILE EXISTS
#
# The denial banner is written to the operator's terminal over the rendezvous
# connection. It is not in the app's log stream, and it never reaches Datadog.
# So a blocked command leaves behind only Heroku's own `api:dyno` record, which
# shows that a command was attempted but cannot distinguish a guard denial from
# an application error -- and the cross-check queries have to read "no console
# record for this dyno" as "blocked, or lost", which is not an audit trail.
#
# One record per denial closes that. The queries then read a missing console
# record as lost, full stop.
#
# WHERE IT GOES
#
# The same endpoint and the same credential as the console_audit gem:
# CONSOLE_LOGGING_DATADOG_PROXY_URL, carrying HTTP Basic userinfo. One endpoint,
# one credential to issue and rotate, one Datadog source, and the join keys the
# proxy already derives (`dyno_id`, and `console_identity` from `operator`)
# apply to these records unchanged. `event` is what tells them apart.
#
# NO ATTRIBUTION FIELDS
#
# The gem sends `service` / `env` / `app` / `version`, but stamps them on the
# *worker*, because `heroku run -e` can rewrite every one of them and a record
# tagged `env:staging` would keep flowing to Datadog while dropping quietly out
# of a production-scoped monitor. This runs inside the one-off dyno, where that
# defence is not available, so it sends none of them and lets datadog-proxy
# attribute the record from the credential it was authenticated with.
#
# LIMITATION
#
# Fail-open, and not sufficient on its own. The URL variable is inherited by the
# one-off dyno, so an operator who knows about this can suppress their own
# denial record with `heroku run -e CONSOLE_LOGGING_DATADOG_PROXY_URL=`. What
# survives that is the `api:dyno` webhook and the exit status. See the README.

_CG_REPORT_VERSION="@@CG_VERSION@@"
_CG_REPORT_URL_VAR="CONSOLE_LOGGING_DATADOG_PROXY_URL"
_CG_REPORT_EVENT="command_denied"
_CG_REPORT_CONNECT_TIMEOUT=2
_CG_REPORT_MAX_TIME=4
# Matches the profile script's denial banner, so the record and the banner agree
# on what the guard was judging.
_CG_REPORT_CMD_MAX=300

# JSON-escape a string onto stdout, without the surrounding quotes.
#
# Byte-wise on purpose. A one-off dyno runs in the C locale, so `${s:i:1}` walks
# bytes; a multi-byte character's bytes are each >= 0x80, fall through to the
# default arm untouched, and are reassembled by concatenation. That keeps the
# U+FFFF the CLI's --exit-code marker carries intact instead of mangling it.
_cg_json_escape() {
  local _s="$1" _out="" _i _c
  for (( _i = 0; _i < ${#_s}; _i++ )); do
    _c="${_s:_i:1}"
    case "$_c" in
      '"')   _out+='\"' ;;
      '\')   _out+='\\' ;;
      $'\n') _out+='\n' ;;
      $'\r') _out+='\r' ;;
      $'\t') _out+='\t' ;;
      # The rest of the C0 controls have no short form and are illegal raw in a
      # JSON string, so they would make the whole record unparseable.
      [[:cntrl:]]) _out+="$(printf '\\u%04x' "'$_c")" ;;
      *)     _out+="$_c" ;;
    esac
  done
  printf '%s' "$_out"
}

# _cg_json_field <name> <value> -- emits `,"name":"value"`, or nothing when the
# value is empty. Omitted rather than null so that a missing operator reads as
# absent in Datadog rather than as the string "null".
_cg_json_field() {
  [[ -n "${2:-}" ]] || return 0
  printf ',"%s":"%s"' "$1" "$(_cg_json_escape "$2")"
}

_cg_report_truncate() {
  if (( ${#1} > _CG_REPORT_CMD_MAX )); then
    printf '%s [truncated]' "${1:0:_CG_REPORT_CMD_MAX}"
  else
    printf '%s' "$1"
  fi
}

# _cg_report_denial <rule> <command> <enforced>
#
#   rule      short stable identifier for the check that refused -- the field to
#             group a monitor by, because denial *messages* get reworded
#   command   what the guard was judging, as the banner shows it
#   enforced  true|false. Sent in permit mode as well: phase 1 exists to measure
#             what enforcement would block, which is only measurable if the
#             would-be denials are recorded.
_cg_report_denial() {
  local _cg_rule="${1:-unknown}" _cg_cmd="${2:-}" _cg_enforced="${3:-true}"
  local _cg_url="${!_CG_REPORT_URL_VAR:-}"

  # Nothing configured: an app that has not been given the endpoint is not one
  # this can report for. Silent, because it is also the state of every app
  # before rollout reaches it.
  [[ -n "$_cg_url" ]] || return 0

  if ! command -v curl > /dev/null 2>&1; then
    echo "console-guard: curl is unavailable, denial not recorded" >&2
    return 0
  fi

  local _cg_body
  _cg_body="{\"event\":\"${_CG_REPORT_EVENT}\",\"enforced\":${_cg_enforced}"
  _cg_body+="$(_cg_json_field rule "$_cg_rule")"
  _cg_body+="$(_cg_json_field command "$(_cg_report_truncate "$_cg_cmd")")"
  _cg_body+="$(_cg_json_field operator "${CONSOLE_USER:-}")"
  _cg_body+="$(_cg_json_field reason "${CONSOLE_REASON:-}")"
  # Resolved from the dyno metadata file by the profile script, which refuses a
  # session whose $DYNO disagrees with it. HEROKU_DYNO_ID is the fallback and is
  # `-e`-settable, so it is only as good as the app's metadata being enabled.
  _cg_body+="$(_cg_json_field dyno_id "${CONSOLE_GUARD_DYNO_ID:-${HEROKU_DYNO_ID:-}}")"
  _cg_body+="$(_cg_json_field guard_version "$_CG_REPORT_VERSION")"
  # datadog-proxy claims `timestamp` as the log's official date, exactly as it
  # does for the gem's records, so a denial is filed at the moment it happened.
  _cg_body+="$(_cg_json_field timestamp "$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')")"
  _cg_body+="}"

  # One attempt, short timeouts, no retry: the dyno is about to exit, and the
  # operator should not wait on the audit pipeline to be told they were denied.
  #
  # stderr is discarded because curl reports failures by quoting the URL, which
  # carries the Basic credential. Report the status code instead, never the URL.
  local _cg_code
  _cg_code="$(curl --silent --output /dev/null --write-out '%{http_code}' \
                   --connect-timeout "$_CG_REPORT_CONNECT_TIMEOUT" \
                   --max-time "$_CG_REPORT_MAX_TIME" \
                   --header 'Content-Type: application/json' \
                   --data-binary "$_cg_body" \
                   "$_cg_url" 2>/dev/null)"

  case "$_cg_code" in
    2*) return 0 ;;
    *)
      # Loud, because a denial that was not recorded is the gap this file
      # exists to close. Never fatal: refusing the command is the control, and
      # recording it must not be able to hold that up.
      echo "console-guard: denial not recorded (${_CG_REPORT_URL_VAR} returned ${_cg_code:-no response})" >&2
      return 0
      ;;
  esac
}
