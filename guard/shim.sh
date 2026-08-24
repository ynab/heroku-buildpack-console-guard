#!/usr/bin/env bash
# Console guard command wrapper. Installed by heroku-buildpack-console-guard as
# both `rails` and `rake` in a directory prepended to PATH on one-off dynos.
#
# WHY THIS FILE EXISTS
#
# The profile script can only see the dyno command as a *string*, before the
# shell has performed quote removal, parameter expansion and pathname
# expansion. Any policy expressed as a string comparison there is therefore
# comparing something other than what `rails` will actually receive:
#
#   rails "dbconsole"          -> string has `"dbconsole"`, argv has `dbconsole`
#   rails runner "$P"  (P=-)   -> string has `"$P"`,        argv has `-`
#   rails runner *.r?          -> string has the glob,      argv has a filename
#
# This wrapper runs after the shell has finished expanding, so `"$@"` here is
# exactly the argv `rails` would have seen. Every deny-list rule therefore lives
# in this file and not in the profile script.
#
# The division of labour is:
#
#   profile script  ->  is this a gated dyno; is the caller identified; is the
#                       command free of compound statements and redirections;
#                       is argv[0] literally `rails` or `rake`
#   this wrapper    ->  everything about the arguments
#
# argv[0] is the one thing the profile script can check soundly, because
# quoting or expanding it makes it stop matching the allowlist and so fails
# closed. That is what guarantees control reaches this wrapper.

set -uo pipefail

_cg_version="@@CG_VERSION@@"

# Phase 1 permit mode. Read at runtime, and deliberately not tamper-proof: this
# variable and permit mode are both temporary and go away together at the end of
# phase 1. See profile/console_guard.sh for the full note.
_cg_enforcing=true
if [[ "${CONSOLE_BLOCK_ENFORCE:-true}" == "false" ]]; then
  _cg_enforcing=false
fi

_cg_prog="${0##*/}"

_cg_deny() {
  local line
  {
    echo ""
    echo "=========================================="
    for line in "$@"; do
      echo "  ${line}"
    done
    if [[ "$_cg_enforcing" != "true" ]]; then
      echo ""
      echo "  CONSOLE_BLOCK_ENFORCE=false -- permitting anyway (phase 1)."
      echo "  This command WILL BE BLOCKED once enforcement is enabled."
    fi
    echo "  console-guard ${_cg_version}"
    echo "=========================================="
    echo ""
  } >&2

  if [[ "$_cg_enforcing" == "true" ]]; then
    exit 1
  fi
}

# ---------- resolve the real rails/rake ----------
# PATH still contains this wrapper's directory, so a plain `exec rails` would
# re-enter this script. Walk PATH and take the first match that is not this
# file.
_cg_self_dir="$(cd "$(dirname "$0")" && pwd)"
_cg_real=""
IFS=':' read -ra _cg_path_entries <<< "${PATH:-}"
for _cg_entry in "${_cg_path_entries[@]}"; do
  [[ -n "$_cg_entry" ]] || _cg_entry="."
  # Compare resolved directories so that a duplicate or symlinked PATH entry
  # pointing at the wrapper directory cannot send us back here.
  _cg_entry_dir="$(cd "$_cg_entry" 2>/dev/null && pwd)" || continue
  [[ "$_cg_entry_dir" == "$_cg_self_dir" ]] && continue
  if [[ -x "$_cg_entry_dir/$_cg_prog" && ! -d "$_cg_entry_dir/$_cg_prog" ]]; then
    _cg_real="$_cg_entry_dir/$_cg_prog"
    break
  fi
done

if [[ -z "$_cg_real" ]]; then
  # Fail closed and loudly: silently doing nothing would look like a broken app
  # rather than a guard problem.
  {
    echo ""
    echo "console-guard: could not find the real \`${_cg_prog}\` on PATH."
    echo "               PATH=${PATH:-}"
    echo "               This is a buildpack bug, not an operator mistake."
    echo ""
  } >&2
  exit 1
fi

# ---------- policy ----------

_cg_sub="${1:-}"

# `rails dbconsole` / `rails db` drop to a raw psql session; no statement is
# ever seen by the console audit hook.
case "$_cg_sub" in
  dbconsole|db)
    _cg_deny "\`${_cg_prog} ${_cg_sub}\` is not permitted on one-off dynos." \
             "" \
             "It opens a raw database session, so no statement reaches the" \
             "console audit hook."
    ;;
esac

# `rails credentials:edit` and `rails encrypted:edit` spawn $EDITOR, which is
# operator-controlled (`heroku run -e EDITOR=bash`) and therefore a shell. The
# profile script also unsets EDITOR and VISUAL; this is the second layer.
case "$_cg_sub" in
  credentials:*|encrypted:*)
    _cg_deny "\`${_cg_prog} ${_cg_sub}\` is not permitted on one-off dynos." \
             "" \
             "These commands spawn an editor, which is a shell escape."
    ;;
esac

for _cg_arg in "$@"; do
  # A bare `-` makes `rails runner` read the program from stdin, so the code
  # that runs appears in no log at all -- not the dyno command string, not the
  # api:dyno webhook, not an in-app ARGV capture.
  if [[ "$_cg_arg" == "-" ]]; then
    _cg_deny "Reading the program from stdin is not permitted." \
             "" \
             "A bare \`-\` argument means the executed code never appears in" \
             "any audit record. Pass the code inline instead."
  fi

  # `-c` would reach a shell (`bash -c`, `sh -c`). No legitimate rails/rake
  # invocation uses it. `rails c` -- the console shorthand -- is unaffected,
  # because that argument is `c`, not `-c`.
  if [[ "$_cg_arg" == "-c" ]]; then
    _cg_deny "The \`-c\` flag is not permitted on one-off dynos." \
             "" \
             "Use \`rails c\` for a console."
  fi
done

# `rails runner` reading its program from a file has the same shape as reading
# from stdin: the command string names a path rather than the code that runs.
#
# Rails decides file-vs-inline-code by whether the path exists on disk. We are
# past expansion here, so we can apply that same test rather than guessing from
# how the argument looks.
if [[ "$_cg_prog" == "rails" && ( "$_cg_sub" == "runner" || "$_cg_sub" == "r" ) ]]; then
  for _cg_arg in "${@:2}"; do
    case "$_cg_arg" in
      --file|--file=*)
        _cg_deny "\`rails runner\` may not read its program from a file." \
                 "" \
                 "Pass the code inline instead."
        ;;
    esac
    if [[ -f "$_cg_arg" ]]; then
      _cg_deny "\`rails runner\` may not read its program from a file." \
               "" \
               "\`${_cg_arg}\` exists on disk, so Rails would execute the" \
               "file rather than the argument. The command string would then" \
               "name a path rather than the code that runs, and the executed" \
               "code would never be audited." \
               "" \
               "Pass the code inline instead."
    fi
  done
fi

exec "$_cg_real" "$@"
