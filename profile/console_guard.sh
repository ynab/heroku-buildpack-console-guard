# shellcheck shell=bash
# shellcheck disable=SC2016  # `$(` and friends appear here as literals to match on
# Console gate for one-off Heroku dynos.
# Installed by heroku-buildpack-console-guard into .profile.d/
#
# This file is SOURCED by the login shell that runs the dyno command. It has no
# shebang on purpose: it is not executable, and `return` below would be a syntax
# error if it were run as a script.
#
# It is one of two halves. This half can only see the dyno command as a string,
# before the shell expands it, so it checks only what is sound to check on a raw
# string:
#
#   - is this a gated dyno
#   - is the caller identified (CONSOLE_USER / CONSOLE_REASON)
#   - is the command free of compound statements and redirections
#   - is argv[0] literally `rails` or `rake`
#
# Everything about the *arguments* lives in the command wrapper installed on
# PATH (see guard/shim.sh), which runs after expansion and can therefore see the
# real argv. Quoting or expanding argv[0] makes it stop matching the allowlist
# here, so it fails closed -- that is what guarantees the wrapper is reached.
#
# - Requires CONSOLE_USER and CONSOLE_REASON for all one-off dynos
# - Blocks compound statements, redirections and command substitution
# - Only permits `rails` and `rake` (unqualified, so the wrapper applies)
# - Warns when runtime-dyno-metadata is disabled (the dyno UUID correlates a
#   session with Heroku's own api:dyno record)
# - Exports CONSOLE_AUDIT_ENABLED=true, which activates the in-app console
#   audit hook
#

# Values substituted by bin/compile at build time.
_CG_VERSION="@@CG_VERSION@@"
_cg_metadata_file="@@CG_DYNO_METADATA_FILE@@"
_cg_shim_dir="${HOME:-/app}/.console-guard/bin"
_cg_lib_dir="${HOME:-/app}/.console-guard/lib"

# ---------- denial reporting ----------
# Sourced before the first check, because the $DYNO-spoof refusal below is one of
# the denials worth recording. A missing library degrades to a no-op: the record
# is observability, and losing it must not change what the guard permits.
if [[ -r "$_cg_lib_dir/denial_report.sh" ]]; then
  # shellcheck source=guard/denial_report.sh
  . "$_cg_lib_dir/denial_report.sh"
else
  echo "console-guard: denial reporter is missing, denials will not be recorded" >&2
  _cg_report_denial() { :; }
fi

# ---------- enforcement mode (phase 1 rollout) ----------
# Phase 1 permits but does not block: every check still runs and reports, but a
# failure is a warning rather than an exit. Set CONSOLE_BLOCK_ENFORCE=false as an
# app config var to opt into permit mode. Defaults to enforcing, so an app that
# was never configured fails closed.
#
# Deliberately not tamper-proof. This variable and permit mode are both temporary
# and go away together at the end of phase 1; while permit mode is on nothing
# blocks anyway, so overriding it per session gains an operator nothing.
_cg_enforcing=true
if [[ "${CONSOLE_BLOCK_ENFORCE:-true}" == "false" ]]; then
  _cg_enforcing=false
fi

# ---------- determine the dyno name ----------
# $DYNO is an environment variable, and `heroku run -e DYNO=web.1` would
# otherwise let an operator skip the gate entirely. Dyno metadata also writes the
# dyno's name and UUID to a file inside the dyno, which `-e` cannot touch, so
# prefer that and treat a mismatch as tampering.
_cg_dyno_name="${DYNO:-}"
_cg_dyno_id="${HEROKU_DYNO_ID:-}"
_cg_metadata_seen=false

if [[ -r "$_cg_metadata_file" ]]; then
  _cg_meta_raw="$(tr -d '\n' < "$_cg_metadata_file" 2>/dev/null)"
  # Minimal, dependency-free extraction of "name" and "id" from the metadata
  # JSON. Anything unparseable is treated as absent rather than as an error, so a
  # change in the file's shape degrades to the $DYNO fallback below.
  #
  # The file carries several objects, each with its own "name"/"id" (dyno, app,
  # release). Narrow to the "dyno" object first: a greedy match over the whole
  # file picks the LAST "name", which is app.name (empty), silently defeating the
  # spoof check. The dyno object has no nested braces, so [^}] delimits it.
  _cg_meta_dyno="$(printf '%s' "$_cg_meta_raw" |
    sed -n 's/.*"dyno"[[:space:]]*:[[:space:]]*{\([^}]*\)}.*/\1/p')"
  _cg_meta_name="$(printf '%s' "$_cg_meta_dyno" |
    sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  _cg_meta_id="$(printf '%s' "$_cg_meta_dyno" |
    sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

  if [[ -n "$_cg_meta_name" ]]; then
    _cg_metadata_seen=true
    if [[ -n "${DYNO:-}" && "${DYNO}" != "$_cg_meta_name" ]]; then
      {
        echo ""
        echo "=========================================="
        echo "  \$DYNO (${DYNO}) does not match this dyno's metadata"
        echo "  (${_cg_meta_name}). Refusing to run."
        echo "  console-guard ${_CG_VERSION}"
        echo "=========================================="
        echo ""
      } >&2
      # Recorded with the metadata's dyno id, not $DYNO's, so the record files
      # under the dyno this actually is.
      CONSOLE_GUARD_DYNO_ID="${_cg_meta_id:-}" \
        _cg_report_denial dyno_name_spoofed "\$DYNO=${DYNO}" true

      # Fatal in both enforcement modes. This is not a command-policy decision an
      # operator can be warned about; it is an attempt to change which dyno the
      # guard believes it is running on.
      exit 1
    fi
    _cg_dyno_name="$_cg_meta_name"
    [[ -n "$_cg_meta_id" ]] && _cg_dyno_id="$_cg_meta_id"
  fi
  unset _cg_meta_raw _cg_meta_dyno _cg_meta_name _cg_meta_id
fi

# ---------- decide what applies to this dyno ----------
# One-off dyno families:
#   run.N        `heroku run` / `heroku run:detached` -- fully gated
#   scheduler.N  Heroku Scheduler -- audited but not gated: there is no
#                interactive operator to supply a user or a reason, and the
#                command comes from app configuration
#   release.N    release phase -- same
# Long-running dynos (web.N, worker.N, and any other app-defined process type)
# get neither: the audit hook is a console concern.
_cg_gated=false
_cg_audited=false
case "$_cg_dyno_name" in
  run.*)                 _cg_gated=true;  _cg_audited=true ;;
  scheduler.*|release.*) _cg_audited=true ;;
  "")
    # No dyno name from either source. Assume a one-off dyno and gate it, rather
    # than letting a command through ungated.
    _cg_gated=true; _cg_audited=true
    ;;
esac

if [[ "$_cg_gated" != "true" ]]; then
  if [[ "$_cg_audited" == "true" ]]; then
    export CONSOLE_AUDIT_ENABLED=true
  fi
  unset -f _cg_report_denial _cg_json_escape _cg_json_field \
           _cg_report_truncate 2>/dev/null
  unset _cg_enforcing _CG_VERSION _cg_metadata_file _cg_shim_dir _cg_lib_dir \
        _cg_dyno_name _cg_dyno_id _cg_metadata_seen _cg_gated _cg_audited \
        _CG_REPORT_VERSION _CG_REPORT_URL_VAR _CG_REPORT_EVENT \
        _CG_REPORT_CONNECT_TIMEOUT _CG_REPORT_MAX_TIME _CG_REPORT_CMD_MAX
  return 0
fi

# The trusted dyno id, for the command wrapper's own denial records: it is
# resolved from the metadata file above, which `heroku run -e` cannot reach,
# whereas HEROKU_DYNO_ID can be set to anything. Exported here rather than
# earlier so it appears only on the dynos the wrapper is installed for.
if [[ -n "$_cg_dyno_id" ]]; then
  export CONSOLE_GUARD_DYNO_ID="$_cg_dyno_id"
fi

# ---------- the CLI's exit-status marker ----------
# `heroku run --exit-code` appends
#
#   ; echo "<U+FFFF> heroku-command-exit-status: $?"
#
# to the dyno command and reads the resulting line off stdout to decide what to
# exit with. It is the only way `heroku run` reports failure, so every CI caller
# that can tell a broken migration from a good one uses it.
#
# That matters here twice over. The appended text makes the command a compound
# statement, which the gate below would otherwise reject; and a denial exits
# during .profile.d, so the appended `echo` never runs, no marker reaches stdout,
# and the CLI reports success for a command it never ran.
# U+FFFF as explicit UTF-8 bytes, not the \u escape. A one-off dyno runs in the C
# locale (`locale charmap` is ANSI_X3.4-1968), and there bash cannot represent the
# codepoint, so the \u form silently yields the six-character string \uFFFF. The
# strip would then never match and the denial marker would be unrecognisable.
_CG_EXIT_SENTINEL=$'\xef\xbf\xbf'
_CG_EXIT_MARKER="; echo \"${_CG_EXIT_SENTINEL} heroku-command-exit-status: \$?\""

# Read the login shell's argv up front: both the marker check and the command
# parsing below need it, and _cg_deny needs the marker answer from its very first
# call site -- the identity gate is the denial CI is most likely to hit.
_cg_argv=()
if [[ -r /proc/$$/cmdline ]]; then
  while IFS= read -r -d '' _cg_arg; do
    _cg_argv+=("$_cg_arg")
  done < /proc/$$/cmdline
fi

# True only when the caller passed --exit-code, so a plain `heroku run` is not
# given a stray marker line it never asked for.
_cg_exit_marker_seen=false
for _cg_arg in "${_cg_argv[@]}"; do
  if [[ "$_cg_arg" == *"$_CG_EXIT_MARKER" ]]; then
    _cg_exit_marker_seen=true
    break
  fi
done

# ---------- extract the dyno command ----------
# Heroku executes the one-off command through a login shell, which is the process
# that sources this script, so its argv is `bash -c <the dyno command>` and we
# want the payload.
#
# Extracted here, before the first check, so that every denial record carries the
# command -- including the identity denial, which is the one CI hits and the one
# where "what did they try to run" matters most. The refusals for an argv this
# cannot read stay further down, where they were, so denial precedence is
# unchanged.
_CG_DYNO_CMD=""
_cg_cmd_read=false

if (( ${#_cg_argv[@]} > 0 )); then
  case "${_cg_argv[0]##*/}" in
    bash|sh|zsh|dash)
      _cg_i=1
      while (( _cg_i < ${#_cg_argv[@]} )); do
        # Match `-c` and also combined short forms such as `-lc`, which mean the
        # same thing to the shell.
        case "${_cg_argv[_cg_i]}" in
          -c|-[!-]*c)
            _CG_DYNO_CMD="${_cg_argv[_cg_i + 1]:-}"
            _cg_cmd_read=true
            break
            ;;
        esac
        (( _cg_i++ ))
      done
      ;;
  esac
fi

# ---------- strip the CLI's exit-status marker ----------
# Removed before anything vets or reports the command, so `heroku run --exit-code
# rake foo` is judged -- and recorded -- as `rake foo` rather than as the compound
# the CLI made of it. See the marker definition above for why dropping
# --exit-code is not an option.
#
# Exact literal, anchored to the end, removed at most once. A looser pattern is a
# shell escape: `rails c ; bash # heroku-command-exit-status` would be stripped
# back to `rails c` and permitted. Two markers leave one behind, which the
# compound check then rejects.
#
# If Heroku changes the marker this stops matching and CI is denied again --
# noisy, but the safe direction to fail in.
if [[ "$_cg_cmd_read" == "true" ]]; then
  _cg_candidate="${_CG_DYNO_CMD%"${_CG_DYNO_CMD##*[![:space:]]}"}"
  if [[ "$_cg_candidate" == *"$_CG_EXIT_MARKER" ]]; then
    _cg_candidate="${_cg_candidate%"$_CG_EXIT_MARKER"}"
    _CG_DYNO_CMD="${_cg_candidate%"${_cg_candidate##*[![:space:]]}"}"
  fi
fi

# Print a denial. Exits the dyno when enforcing; warns and continues otherwise.
#
# <rule> is a short stable identifier for the check that refused. It is what a
# monitor groups by, because denial messages get reworded and rule names do not.
_cg_deny() {
  local _cg_rule="$1"; shift
  local _cg_line
  {
    echo ""
    echo "=========================================="
    for _cg_line in "$@"; do
      echo "  ${_cg_line}"
    done
    if [[ "$_cg_enforcing" != "true" ]]; then
      echo ""
      echo "  CONSOLE_BLOCK_ENFORCE=false -- permitting anyway (phase 1)."
      echo "  This command WILL BE BLOCKED once enforcement is enabled."
    fi
    echo "  console-guard ${_CG_VERSION}"
    echo "=========================================="
    echo ""
  } >&2

  # Before the exit, and in permit mode too: phase 1 exists to measure what
  # enforcement would block, which is only measurable if the would-be denials
  # are recorded.
  local _cg_enforced=false
  [[ "$_cg_enforcing" == "true" ]] && _cg_enforced=true
  _cg_report_denial "$_cg_rule" "${_CG_DYNO_CMD:-${_cg_argv[*]:-}}" "$_cg_enforced"

  if [[ "$_cg_enforcing" == "true" ]]; then
    # Stand in for the `echo` the CLI appended, which exiting here skips. On
    # stdout, because that is the stream the CLI parses -- the banner above goes
    # to stderr and is invisible to it. Without this a denied CI job exits 0 and
    # the pipeline goes green.
    if [[ "$_cg_exit_marker_seen" == "true" ]]; then
      printf '%s heroku-command-exit-status: 1\n' "$_CG_EXIT_SENTINEL"
    fi
    exit 1
  fi
}

_CG_USAGE='heroku run -e "CONSOLE_USER=$(heroku whoami);CONSOLE_REASON=test" rails c -a app_name'

# ---------- the command wrapper must be installed ----------
# All argument policy lives in the wrapper. If it is missing this script cannot
# enforce anything meaningful, so refuse rather than run half a gate.
if [[ ! -x "$_cg_shim_dir/rails" || ! -x "$_cg_shim_dir/rake" ||
      ! -x "$_cg_shim_dir/bundle" ]]; then
  _cg_deny wrapper_missing \
           "The console guard command wrapper is missing from this dyno." \
           "" \
           "Expected: ${_cg_shim_dir}/{rails,rake,bundle}" \
           "" \
           "This is a build problem, not an operator mistake. Redeploy the" \
           "app; if it persists the buildpack is misconfigured."
fi

# ---------- require CONSOLE_USER and CONSOLE_REASON ----------
# A value that is entirely whitespace is treated the same as an unset one.
_cg_user_check="${CONSOLE_USER:-}"
_cg_reason_check="${CONSOLE_REASON:-}"

# Name the one that is missing. "both are required" sends an operator checking
# the variable that was already fine, and the usual cause -- a failed
# `heroku whoami` substituting an empty string -- looks like neither was set.
_cg_missing=()
[[ -z "${_cg_user_check//[[:space:]]/}" ]]   && _cg_missing+=("CONSOLE_USER")
[[ -z "${_cg_reason_check//[[:space:]]/}" ]] && _cg_missing+=("CONSOLE_REASON")

if (( ${#_cg_missing[@]} > 0 )); then
  if (( ${#_cg_missing[@]} == 2 )); then
    _cg_missing_desc="CONSOLE_USER and CONSOLE_REASON are"
  else
    _cg_missing_desc="${_cg_missing[0]} is"
  fi
  _cg_deny identity_missing \
           "${_cg_missing_desc} not set." \
           "" \
           "Both are required on one-off dynos. CONSOLE_USER must be your" \
           "\`heroku whoami\` value, so that console records can be compared" \
           "against Heroku's own audit trail." \
           "" \
           "If you built CONSOLE_USER from \`heroku whoami\`, check that it" \
           "succeeded -- an expired login makes it print an error and return" \
           "an empty string, which arrives here as unset." \
           "" \
           "Usage:" \
           "  ${_CG_USAGE}"
fi

# ---------- permit mode still has to hand the app an operator ----------
# console1984 raises MissingUsername on an empty CONSOLE_USER
# (ask_for_username_if_empty defaults to false), so leaving it empty kills the
# console even in permit mode -- which is exactly the breakage permit mode
# exists to avoid during phase 1. Supply a placeholder instead.
#
# Deliberately not a plausible username: it has to be obvious in an audit record
# that nobody identified themselves, and it must never collide with a real
# `heroku whoami` value.
#
# Only in permit mode. When enforcing, _cg_deny above has already exited.
if [[ "$_cg_enforcing" != "true" && -z "${_cg_user_check//[[:space:]]/}" ]]; then
  export CONSOLE_USER="[not provided]"
fi

# ---------- refuse an argv the gate cannot read ----------
# The extraction itself happened above, before the first check. What is left here
# is the pair of refusals for the shapes it could not handle, kept in this
# position so that the identity gate above still takes precedence.

# Denials echo the command back. Without it a denial cannot be diagnosed from the
# operator's side -- "this command is not permitted" says nothing about which
# part of the string the gate objected to, or whether it even parsed the string
# the operator typed.
_cg_show() {
  local _cg_text="$1"
  if (( ${#_cg_text} > 300 )); then
    printf '%s [truncated]' "${_cg_text:0:300}"
  else
    printf '%s' "$_cg_text"
  fi
}

if (( ${#_cg_argv[@]} == 0 )); then
  # Fail closed: if we cannot read the command, we cannot vet it.
  _cg_deny command_unreadable \
           "Could not read the dyno command." \
           "" \
           "/proc/\$\$/cmdline is empty or unreadable, and the console gate" \
           "cannot vet a command it cannot see, so the session is refused." \
           "" \
           "This is a platform or build problem, not an operator mistake."
else
  # No `-c` payload means this is not the `bash -c <command>` shape the gate is
  # built on: the login shell was invoked some other way, or the command arrives
  # on stdin. There is no command string to vet, so refuse -- and say so.
  if [[ "$_cg_cmd_read" != "true" || -z "${_CG_DYNO_CMD//[[:space:]]/}" ]]; then
    _cg_cmd_read=false
    _cg_deny command_not_bash_c \
             "Could not determine the dyno command." \
             "" \
             "The gate expects this session's login shell to have been invoked" \
             "as \`bash -c <command>\`. It was not, so there is no command" \
             "string to vet and the session is refused." \
             "" \
             "Login shell argv:" \
             "  $(_cg_show "${_cg_argv[*]}")" \
             "" \
             "This is a platform or build problem, not an operator mistake."
  fi
fi

# ---------- block compound statements and redirections ----------
# The allowlist below matches argv[0] only, so without this an operator could
# append a second command -- eg `rails runner "1"; bash` -- and reach a shell.
#
# Redirections are rejected for the same reason the wrapper rejects a bare `-`:
# `rails c < /app/payload.rb` feeds a program in through stdin, so the command
# string names a file rather than the code that runs.
#
# Best effort: `rails runner 'system("bash")'` contains none of these and still
# shells out.
if [[ "$_cg_cmd_read" == "true" ]] &&
   [[ "$_CG_DYNO_CMD" == *';'*   ||
      "$_CG_DYNO_CMD" == *'&'*   ||
      "$_CG_DYNO_CMD" == *'|'*   ||
      "$_CG_DYNO_CMD" == *'`'*   ||
      "$_CG_DYNO_CMD" == *'$('*  ||
      "$_CG_DYNO_CMD" == *'<'*   ||
      "$_CG_DYNO_CMD" == *'>'*   ||
      "$_CG_DYNO_CMD" == *$'\n'* ]]; then
  _cg_deny compound_statement \
           "Compound statements and redirections are not permitted on one-off" \
           "dynos." \
           "" \
           "The command may not contain any of:  ;  &  |  \`  \$(  <  >  newline" \
           "" \
           "Command:" \
           "  $(_cg_show "$_CG_DYNO_CMD")" \
           "" \
           "Run each command as its own \`heroku run\`."
fi

# Take argv[0] only; the wrapper handles the rest. `read -ra` splits on IFS
# without performing pathname expansion, so nothing can be glob-expanded here.
# IFS is set explicitly because an earlier .profile.d script could have changed
# it.
IFS=$' \t\n' read -ra _cg_tokens <<< "$_CG_DYNO_CMD"
_cg_bin="${_cg_tokens[0]:-}"

# ---------- command allowlist ----------
# Only `rails`, `rake` and `bundle` are permitted, because those are the only
# paths that enter a Rails process where the console audit hook can observe what
# runs. Everything else --
# bash, sh, zsh, irb, ruby, node, python, psql, pg_dump, pg_restore, pgcli,
# curl, wget, nc, ssh, scp, env, printenv, cat -- is blocked by falling through
# this allowlist.
#
# `bundle` is here because Heroku's Ruby buildpack rewrites `rake <task>` on a
# one-off dyno to `bundle exec rake <task>` before this script runs, so without
# it no rake task works at all. It is admitted only as far as the wrapper: the
# `bundle` wrapper permits `bundle exec rails|rake` and nothing else, so
# `bundle exec bash` still dies -- on `bash`, one layer later.
#
# The name must be unqualified. `bin/rails` and `/app/bin/rails` are rejected
# even though they are the same program, because naming a path bypasses the PATH
# lookup that reaches the command wrapper, and the wrapper is where argument
# policy is enforced. A leading `VAR=value` assignment is rejected for the same
# reason: `PATH=/app/bin rails c` would take the wrapper out of the picture.
if [[ "$_cg_cmd_read" == "true" ]]; then
  case "$_cg_bin" in
    rails|rake|bundle) : ;;
    *)
      _cg_deny command_not_allowed \
               "This command is not permitted on one-off dynos." \
               "" \
               "Command:" \
               "  $(_cg_show "$_CG_DYNO_CMD")" \
               "Rejected because its first word is:" \
               "  $(_cg_show "$_cg_bin")" \
               "" \
               "Allowed:" \
               "  rails <task>" \
               "  rake <task>" \
               "  bundle exec rails|rake <task>" \
               "" \
               "The name must be unqualified -- \`rails\`, not \`bin/rails\` --" \
               "and may not be preceded by a VAR=value assignment." \
               "" \
               "Example:" \
               "  ${_CG_USAGE}"
      ;;
  esac
fi

# ---------- reach the command wrapper ----------
# Prepended, so `rails` and `rake` resolve to the wrapper, which re-resolves the
# real binary from the rest of PATH.
export PATH="$_cg_shim_dir:$PATH"

# `rails credentials:edit` and `rails encrypted:edit` spawn $EDITOR, which an
# operator can set with `-e`. The wrapper blocks those subcommands; this removes
# the mechanism as well.
unset EDITOR VISUAL

# ---------- dyno metadata check ----------
# The dyno UUID is what correlates a console audit record with Heroku's own
# api:dyno webhook record for the same session, and the metadata file is what
# makes the dyno name above un-spoofable. Without dyno metadata neither is
# available. This is a configuration error on the app, not an operator mistake,
# so it warns rather than blocks.
if [[ "$_cg_metadata_seen" != "true" || -z "$_cg_dyno_id" ]]; then
  {
    echo ""
    echo "WARNING: dyno metadata is not enabled on this app, so this session"
    echo "         cannot be correlated with Heroku's audit trail, and the gate"
    echo "         is relying on \$DYNO, which an operator can set."
    echo "         Enable it:"
    echo "           heroku labs:enable runtime-dyno-metadata -a ${HEROKU_APP_NAME:-app_name}"
    echo ""
  } >&2
fi

# ---------- activate the console audit hook ----------
# Exported after the gates above: .profile.d runs after config vars and
# `heroku run -e` vars are applied, so this overrides any operator-supplied
# value. It is also exported in permit mode, so that phase 1 still produces
# console audit records.
export CONSOLE_AUDIT_ENABLED=true

# This script is sourced, so clean up after ourselves rather than leaking state
# into the console session.
#
# The command wrapper sources the denial reporter itself, so nothing here needs
# to survive for it -- and CONSOLE_GUARD_DYNO_ID, which does, is exported.
unset -f _cg_deny _cg_show _cg_report_denial _cg_json_escape _cg_json_field \
         _cg_report_truncate
unset _cg_enforcing _CG_VERSION _cg_metadata_file _cg_shim_dir _cg_lib_dir \
      _cg_dyno_name _cg_dyno_id _cg_metadata_seen _cg_gated _cg_audited \
      _cg_user_check _cg_reason_check _cg_missing _cg_missing_desc _cg_argv \
      _cg_arg _cg_i _cg_tokens _cg_bin _cg_cmd_read _CG_DYNO_CMD _CG_USAGE \
      _CG_REPORT_VERSION _CG_REPORT_URL_VAR _CG_REPORT_EVENT \
      _CG_REPORT_CONNECT_TIMEOUT _CG_REPORT_MAX_TIME _CG_REPORT_CMD_MAX
