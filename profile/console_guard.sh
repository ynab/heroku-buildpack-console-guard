#!/usr/bin/env bash
# Console gate for one-off Heroku dynos.
# Installed by heroku-buildpack-console-guard into .profile.d/
#
# - Requires CONSOLE_USER and CONSOLE_REASON for all one-off dynos
# - Blocks compound statements (shell metacharacters)
# - Only permits allowlisted commands (rails / rake), minus an explicit deny list
# - Warns when runtime-dyno-metadata is disabled (HEROKU_DYNO_ID correlates a
#   session with Heroku's own api:dyno record)
# - Exports CONSOLE_AUDIT_ENABLED=true once all checks pass, which activates the
#   in-app console audit hook
#

# Only activate on one-off dynos
[[ "${DYNO:-}" == run.* ]] || return 0

# ---------- enforcement mode (phase 1 rollout) ----------
# Phase 1 permits but does not block: every check still runs and reports, but a
# failure is a warning rather than an exit. Set CONSOLE_BLOCK_ENFORCE=false as an
# app config var to opt into permit mode. Defaults to enforcing, so an app that
# was never configured fails closed.
#
# Deliberately not tamper-proof: during phase 1 nothing blocks anyway, so
# overriding it via `heroku run -e` gains an operator nothing.
_cg_enforcing=true
if [[ "${CONSOLE_BLOCK_ENFORCE:-true}" == "false" ]]; then
  _cg_enforcing=false
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
    echo "=========================================="
    echo ""
  } >&2

  if [[ "$_cg_enforcing" == "true" ]]; then
    exit 1
  fi
}

_CG_USAGE='heroku run -e "CONSOLE_USER=$(heroku whoami);CONSOLE_REASON=test" rails c -a app_name'

# ---------- require CONSOLE_USER and CONSOLE_REASON ----------
# Whitespace-only values count as missing: this is the only enforcement point.
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

_CG_DYNO_CMD=""
if (( ${#_cg_argv[@]} > 0 )); then
  case "${_cg_argv[0]##*/}" in
    bash|sh|zsh|dash)
      _cg_i=1
      while (( _cg_i < ${#_cg_argv[@]} )); do
        if [[ "${_cg_argv[_cg_i]}" == "-c" ]]; then
          _CG_DYNO_CMD="${_cg_argv[_cg_i + 1]:-}"
          break
        fi
        (( _cg_i++ ))
      done
      ;;
  esac
  # No `-c` payload (or a non-shell argv[0]): fall back to the whole argv.
  if [[ -z "$_CG_DYNO_CMD" ]]; then
    _CG_DYNO_CMD="${_cg_argv[*]}"
  fi
fi

if [[ -z "${_CG_DYNO_CMD//[[:space:]]/}" ]]; then
  # Fail closed: if we cannot read the command, we cannot vet it.
  _cg_deny "Could not determine the dyno command (/proc/\$\$/cmdline unreadable)." \
           "" \
           "The console gate cannot vet a command it cannot read, so the" \
           "session is refused."
fi

# ---------- block compound statements ----------
# The allowlist below is a prefix match, so without this an operator could append
# a second command -- eg `rails runner "1"; bash` -- and reach a shell. This is
# best effort: `rails runner 'system("bash")'` contains no metacharacter and
# still shells out.
if [[ "$_CG_DYNO_CMD" == *';'*   ||
      "$_CG_DYNO_CMD" == *'&'*   ||
      "$_CG_DYNO_CMD" == *'|'*   ||
      "$_CG_DYNO_CMD" == *'`'*   ||
      "$_CG_DYNO_CMD" == *'$('*  ||
      "$_CG_DYNO_CMD" == *$'\n'* ]]; then
  _cg_deny "Compound statements are not permitted on one-off dynos." \
           "" \
           "The command may not contain any of:  ;  &  |  \`  \$(  newline" \
           "" \
           "Run each command as its own \`heroku run\`."
fi

# Split the command into tokens for the checks below. `read -ra` splits on IFS
# without performing pathname expansion, so no token can be glob-expanded here.
read -ra _cg_tokens <<< "$_CG_DYNO_CMD"
_cg_bin="${_cg_tokens[0]:-}"
_cg_sub="${_cg_tokens[1]:-}"

# ---------- command allowlist ----------
# Only `rails` and `rake` are permitted, because those are the only paths that
# enter a Rails process where the console audit hook can observe what runs.
# Everything else --
# bash, sh, zsh, irb, ruby, node, python, psql, pg_dump, pg_restore, pgcli,
# curl, wget, nc, ssh, scp, env, printenv, cat -- is blocked by falling through
# this allowlist. Note that `bundle exec` is NOT permitted: allowing it would
# allow `bundle exec bash`.
case "$_cg_bin" in
  rails|rake|bin/rails|bin/rake|./bin/rails|./bin/rake) : ;;
  *)
    _cg_deny "This command is not permitted on one-off dynos." \
             "" \
             "Allowed:" \
             "  rails <task>" \
             "  rake <task>" \
             "" \
             "Example:" \
             "  ${_CG_USAGE}"
    ;;
esac

# ---------- deny list (commands that start with rails/rake but are not allowed) ----------

# `rails dbconsole` / `rails db` drop to a raw psql session; no statement is
# ever seen by the console audit hook.
if [[ "$_cg_sub" == "dbconsole" || "$_cg_sub" == "db" ]]; then
  _cg_deny "\`rails ${_cg_sub}\` is not permitted on one-off dynos."
fi

for _cg_tok in "${_cg_tokens[@]}"; do
  # A bare `-` makes `rails runner` read the program from stdin, so the code
  # that runs appears in no log at all -- not the dyno command string, not the
  # api:dyno webhook, not an in-app ARGV capture.
  if [[ "$_cg_tok" == "-" ]]; then
    _cg_deny "Reading the program from stdin is not permitted." \
             "" \
             "A bare \`-\` argument means the executed code never appears in" \
             "any audit record. Pass the code inline instead."
  fi

  # `-c` would reach a shell (`bash -c`, `sh -c`). No legitimate rails/rake
  # invocation uses it. `rails c` -- the console shorthand -- is unaffected.
  if [[ "$_cg_tok" == "-c" ]]; then
    _cg_deny "The \`-c\` flag is not permitted on one-off dynos." \
             "" \
             "Use \`rails c\` for a console."
  fi

  # Destructive database tasks, in both the rake and rails spellings.
  if [[ "$_cg_tok" =~ ^db:(reset|drop|schema:load|migrate:reset)(:all)?$ ]]; then
    _cg_deny "\`${_cg_tok}\` is not permitted on one-off dynos."
  fi
done

# `rails runner` reading its program from a file has the same shape as reading
# from stdin: the command string names a path rather than the code that runs.
# Rails decides file-vs-inline-code by whether the path exists on disk, which we
# cannot reproduce here, so this is a heuristic on how the argument looks.
if [[ "$_cg_sub" == "runner" || "$_cg_sub" == "r" ]]; then
  for _cg_tok in "${_cg_tokens[@]:2}"; do
    case "$_cg_tok" in
      --file|--file=*|/*|./*|../*|*.rb)
        _cg_deny "\`rails runner\` may not read its program from a file." \
                 "" \
                 "The command string would name a path rather than the code" \
                 "that runs, so the executed code is never audited." \
                 "" \
                 "Pass the code inline instead."
        ;;
    esac
  done
fi

# ---------- dyno metadata check ----------
# HEROKU_DYNO_ID is what correlates a console audit record with Heroku's own
# api:dyno webhook record for the same session. Without runtime-dyno-metadata it
# is empty and that correlation is unavailable. This is a configuration error on
# the app, not an operator mistake, so it warns rather than blocks.
if [[ -z "${HEROKU_DYNO_ID:-}" ]]; then
  {
    echo ""
    echo "WARNING: HEROKU_DYNO_ID is not set, so this session cannot be"
    echo "         correlated with Heroku's audit trail."
    echo "         Enable dyno metadata on this app:"
    echo "           heroku labs:enable runtime-dyno-metadata -a ${HEROKU_APP_NAME:-app_name}"
    echo ""
  } >&2
fi

# ---------- activate the console audit hook ----------
# Exported unconditionally after all gates above have passed: .profile.d runs
# after config vars and `heroku run -e` vars are applied, so this overrides any
# operator-supplied value. It is also exported in permit mode, so that phase 1
# still produces console audit records.
export CONSOLE_AUDIT_ENABLED=true

# This script is sourced, so clean up after ourselves rather than leaking state
# into the console session.
unset -f _cg_deny
unset _cg_enforcing _cg_user_check _cg_reason_check _cg_argv _cg_arg _cg_i \
      _cg_tokens _cg_tok _cg_bin _cg_sub _CG_DYNO_CMD _CG_USAGE
