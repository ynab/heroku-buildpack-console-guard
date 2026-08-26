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
  unset _cg_enforcing _CG_VERSION _cg_metadata_file _cg_shim_dir \
        _cg_dyno_name _cg_dyno_id _cg_metadata_seen _cg_gated _cg_audited
  return 0
fi

# Print a denial. Exits the dyno when enforcing; warns and continues otherwise.
_cg_deny() {
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

  if [[ "$_cg_enforcing" == "true" ]]; then
    exit 1
  fi
}

_CG_USAGE='heroku run -e "CONSOLE_USER=$(heroku whoami);CONSOLE_REASON=test" rails c -a app_name'

# ---------- the command wrapper must be installed ----------
# All argument policy lives in the wrapper. If it is missing this script cannot
# enforce anything meaningful, so refuse rather than run half a gate.
if [[ ! -x "$_cg_shim_dir/rails" || ! -x "$_cg_shim_dir/rake" ]]; then
  _cg_deny "The console guard command wrapper is missing from this dyno." \
           "" \
           "Expected: ${_cg_shim_dir}/{rails,rake}" \
           "" \
           "This is a build problem, not an operator mistake. Redeploy the" \
           "app; if it persists the buildpack is misconfigured."
fi

# ---------- require CONSOLE_USER and CONSOLE_REASON ----------
# A value that is entirely whitespace is treated the same as an unset one.
_cg_user_check="${CONSOLE_USER:-}"
_cg_reason_check="${CONSOLE_REASON:-}"
if [[ -z "${_cg_user_check//[[:space:]]/}" || -z "${_cg_reason_check//[[:space:]]/}" ]]; then
  _cg_deny "CONSOLE_USER and CONSOLE_REASON are required." \
           "" \
           "CONSOLE_USER must be your \`heroku whoami\` value, so that console" \
           "records can be compared against Heroku's own audit trail." \
           "" \
           "Usage:" \
           "  ${_CG_USAGE}"
fi

# ---------- determine the dyno command ----------
# Heroku executes the one-off command through a login shell, which is the process
# that sources this script. Its argv is therefore `bash -c <the dyno command>`;
# we want the payload, not the wrapper.
_cg_argv=()
if [[ -r /proc/$$/cmdline ]]; then
  while IFS= read -r -d '' _cg_arg; do
    _cg_argv+=("$_cg_arg")
  done < /proc/$$/cmdline
fi

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

_CG_DYNO_CMD=""
_cg_cmd_read=false

if (( ${#_cg_argv[@]} == 0 )); then
  # Fail closed: if we cannot read the command, we cannot vet it.
  _cg_deny "Could not read the dyno command." \
           "" \
           "/proc/\$\$/cmdline is empty or unreadable, and the console gate" \
           "cannot vet a command it cannot see, so the session is refused." \
           "" \
           "This is a platform or build problem, not an operator mistake."
else
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

  # No `-c` payload means this is not the `bash -c <command>` shape the gate is
  # built on: the login shell was invoked some other way, or the command arrives
  # on stdin. There is no command string to vet, so refuse -- and say so.
  if [[ "$_cg_cmd_read" != "true" || -z "${_CG_DYNO_CMD//[[:space:]]/}" ]]; then
    _cg_cmd_read=false
    _cg_deny "Could not determine the dyno command." \
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
  _cg_deny "Compound statements and redirections are not permitted on one-off" \
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
# Only `rails` and `rake` are permitted, because those are the only paths that
# enter a Rails process where the console audit hook can observe what runs.
# Everything else --
# bash, sh, zsh, irb, ruby, node, python, psql, pg_dump, pg_restore, pgcli,
# curl, wget, nc, ssh, scp, env, printenv, cat -- is blocked by falling through
# this allowlist. Note that `bundle exec` is NOT permitted: allowing it would
# allow `bundle exec bash`.
#
# The name must be unqualified. `bin/rails` and `/app/bin/rails` are rejected
# even though they are the same program, because naming a path bypasses the PATH
# lookup that reaches the command wrapper, and the wrapper is where argument
# policy is enforced. A leading `VAR=value` assignment is rejected for the same
# reason: `PATH=/app/bin rails c` would take the wrapper out of the picture.
if [[ "$_cg_cmd_read" == "true" ]]; then
  case "$_cg_bin" in
    rails|rake) : ;;
    *)
      _cg_deny "This command is not permitted on one-off dynos." \
               "" \
               "Command:" \
               "  $(_cg_show "$_CG_DYNO_CMD")" \
               "Rejected because its first word is:" \
               "  $(_cg_show "$_cg_bin")" \
               "" \
               "Allowed:" \
               "  rails <task>" \
               "  rake <task>" \
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
unset -f _cg_deny _cg_show
unset _cg_enforcing _CG_VERSION _cg_metadata_file _cg_shim_dir _cg_dyno_name \
      _cg_dyno_id _cg_metadata_seen _cg_gated _cg_audited _cg_user_check \
      _cg_reason_check _cg_argv _cg_arg _cg_i _cg_tokens _cg_bin \
      _cg_cmd_read _CG_DYNO_CMD _CG_USAGE
