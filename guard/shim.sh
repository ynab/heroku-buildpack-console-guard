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

# ---------- denial reporting ----------
# Half the guard's denials happen here rather than in the profile script, and an
# audit trail that records only the other half is worse than none. A missing
# library degrades to a no-op: the record is observability, and losing it must
# not change what the wrapper permits.
_cg_lib="${HOME:-/app}/.console-guard/lib/denial_report.sh"
if [[ -r "$_cg_lib" ]]; then
  # shellcheck source=guard/denial_report.sh
  . "$_cg_lib"
else
  echo "console-guard: denial reporter is missing, denials will not be recorded" >&2
  _cg_report_denial() { :; }
fi

# <rule> is a short stable identifier for the check that refused. It is what a
# monitor groups by, because denial messages get reworded and rule names do not.
_cg_deny() {
  local _cg_rule="$1"; shift
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

  # The post-expansion argv, which is what this half actually judged -- the
  # profile script's copy is the pre-expansion string, and the two differ in
  # exactly the cases this wrapper exists for.
  local _cg_enforced=false
  [[ "$_cg_enforcing" == "true" ]] && _cg_enforced=true
  _cg_report_denial "$_cg_rule" "$_cg_prog ${_cg_argv_seen[*]:-}" "$_cg_enforced"

  if [[ "$_cg_enforcing" == "true" ]]; then
    exit 1
  fi
}

# Captured before any policy runs, and before `bundle exec` rewriting narrows
# what policy looks at, so a denial record shows what was invoked.
_cg_argv_seen=("$@")

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

# ---------- what policy applies to ----------
# Invoked as `bundle`, the interesting command is the one bundler will exec, not
# bundler itself.
#
# Heroku's Ruby buildpack rewrites `rake <task>` on a one-off dyno to
# `bundle exec rake <task>` before the login shell runs, so `bundle` has to be on
# the allowlist for any rake task to work at all. It cannot simply be waved
# through: `bundle exec` unshifts Bundler's own bin directory onto PATH, so the
# rails/rake wrapper is NOT reached afterwards and this is the only place the
# argument rules below can be applied.
_cg_policy_prog="$_cg_prog"
_cg_policy_args=("$@")

if [[ "$_cg_prog" == "bundle" ]]; then
  if [[ "${1:-}" != "exec" ]]; then
    _cg_deny bundle_not_exec \
             "\`bundle ${1:-}\` is not permitted on one-off dynos." \
             "" \
             "Only \`bundle exec rails\` and \`bundle exec rake\` are allowed," \
             "because those are the forms Heroku's Ruby buildpack produces for" \
             "a permitted command."
  fi

  # Unqualified, for the same reason the profile script requires it of the
  # command itself: a path names a program this wrapper has not vetted.
  case "${2:-}" in
    rails|rake)
      _cg_policy_prog="$2"
      ;;
    *)
      _cg_deny bundle_exec_not_allowed \
               "\`bundle exec ${2:-}\` is not permitted on one-off dynos." \
               "" \
               "Only \`rails\` and \`rake\` may be run under \`bundle exec\`," \
               "and the name must be unqualified."
      ;;
  esac

  _cg_policy_args=("${@:3}")
fi

# ---------- policy ----------

_cg_sub="${_cg_policy_args[0]:-}"

# `rails dbconsole` / `rails db` drop to a raw psql session; no statement is
# ever seen by the console audit hook.
case "$_cg_sub" in
  dbconsole|db)
    _cg_deny raw_database_session \
             "\`${_cg_policy_prog} ${_cg_sub}\` is not permitted on one-off dynos." \
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
    _cg_deny editor_escape \
             "\`${_cg_policy_prog} ${_cg_sub}\` is not permitted on one-off dynos." \
             "" \
             "These commands spawn an editor, which is a shell escape."
    ;;
esac

for _cg_arg in ${_cg_policy_args[@]+"${_cg_policy_args[@]}"}; do
  # A bare `-` makes `rails runner` read the program from stdin, so the code
  # that runs appears in no log at all -- not the dyno command string, not the
  # api:dyno webhook, not an in-app ARGV capture.
  if [[ "$_cg_arg" == "-" ]]; then
    _cg_deny stdin_program \
             "Reading the program from stdin is not permitted." \
             "" \
             "A bare \`-\` argument means the executed code never appears in" \
             "any audit record. Pass the code inline instead."
  fi

  # `-c` would reach a shell (`bash -c`, `sh -c`). No legitimate rails/rake
  # invocation uses it. `rails c` -- the console shorthand -- is unaffected,
  # because that argument is `c`, not `-c`.
  if [[ "$_cg_arg" == "-c" ]]; then
    _cg_deny dash_c_flag \
             "The \`-c\` flag is not permitted on one-off dynos." \
             "" \
             "Use \`rails c\` for a console."
  fi
done

# `rails console --sandbox` wraps the whole session in a transaction that is
# rolled back on exit. The audit records are enqueued through ActiveJob, and a
# database-backed queue on the primary database (eg Solid Queue) puts that 
# enqueue inside the same transaction -- so the rollback discards
# the audit trail along with the operator's changes, leaving an interactive
# console with no record of a single statement.
#
# Scoped to `console`/`c` rather than applied to every argv, because `-s` is
# `rake`'s silent flag and legitimate there. `--no-sandbox` must keep working.
#
# Thor parses `--sandbox=true` as well as the bare flag, so the `=` forms are
# denied whatever value they carry. Enumerating Thor's boolean vocabulary would
# be modelling the parser, which is the thing the option allowlist below exists
# to avoid; `--no-sandbox` is the spelling that opts out.
#
# The console_audit gem sets Rails' own `config.disable_sandbox = true` when
# auditing is active, which is a second layer over the same dynos: it holds even
# if the command never reaches this wrapper.
if [[ "$_cg_policy_prog" == "rails" && ( "$_cg_sub" == "console" || "$_cg_sub" == "c" ) ]]; then
  for _cg_arg in "${_cg_policy_args[@]:1}"; do
    case "$_cg_arg" in
      --sandbox|--sandbox=*|-s|-s=*)
        _cg_deny sandbox_console \
                 "\`rails ${_cg_sub} ${_cg_arg}\` is not permitted on one-off dynos." \
                 "" \
                 "A sandboxed console rolls back its transaction on exit, which" \
                 "discards the queued audit records with it -- the session would" \
                 "run entirely unlogged." \
                 "" \
                 "Use \`rails ${_cg_sub}\` instead. It is audited." \
                 "\`--no-sandbox\` is permitted and means the same thing."
        ;;
    esac
  done
fi

# `rails runner` reading its program from a file has the same shape as reading
# from stdin: the command string names a path rather than the code that runs.
#
# Rails decides file-vs-inline-code by whether the path exists on disk. We are
# past expansion here, so we can apply that same test rather than guessing from
# how the argument looks.
if [[ "$_cg_policy_prog" == "rails" && ( "$_cg_sub" == "runner" || "$_cg_sub" == "r" ) ]]; then
  for _cg_arg in "${_cg_policy_args[@]:1}"; do
    case "$_cg_arg" in
      --file|--file=*)
        _cg_deny runner_file \
                 "\`rails runner\` may not read its program from a file." \
                 "" \
                 "Pass the code inline instead."
        ;;
    esac
    if [[ -f "$_cg_arg" ]]; then
      _cg_deny runner_file \
               "\`rails runner\` may not read its program from a file." \
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

# ---------- option allowlist ----------
# `rake -e/-p/-E CODE` evaluates CODE inside Rake's own option parser -- before
# the Rakefile is loaded and without booting Rails -- and then exits. Nothing the
# code does reaches the console audit hook, so it is weaker even than the
# `rails runner 'system("bash")'` case the README accepts as best effort, where
# Rails at least boots and the invocation is recorded. `-f/-r/-I/-R/-C/-g` name a
# path rather than the code that runs, which is what blocks a bare `-` above.
#
# Rails hands any command it does not recognise to that same parser with the
# whole argv, so `rails -e CODE` and `rails db:migrate -e CODE` reach it too.
#
# Allowlisted rather than screened. A deny list has to model which of Rake's
# short options take an argument, in order to know where a bundle such as `-Ne`
# stops being flags -- get that wrong for one option, in this version of Rake or
# a later one, and the bundle hides an `-e`. An allowlist fails the other way: an
# option nobody listed is refused, so the cost of being wrong is a denial rather
# than an unlogged shell.
#
# Every command gets a list; none is exempt. The two Rails commands below parse
# their own options and never reach Rake, so `-e` there is the environment --
# but they are given a list of their own rather than being waved through,
# because a mistake in a list is a denial while a mistake in an exemption is a
# bypass, silently and with no failing test.
#
# _cg_allow_exact  options taking no value: the token must match exactly, so
#                  `-se` is refused rather than read as a bundle
# _cg_allow_value  options taking one: exactly, or with the value attached
#                  (`-T db`, `-Tdb`, `--tasks=db`)
_cg_allow_why=(
  "Options are allowlisted here. Rake evaluates \`-e/-p/-E CODE\` in"
  "its own option parser, before the Rakefile is loaded and without"
  "booting Rails, so nothing that code does reaches the console audit"
  "hook -- and Rails hands any command it does not recognise to that"
  "same parser. Options naming a path are excluded for the reason a"
  "bare \`-\` is."
)
_cg_allow_extras="task names, VAR=value assignments, and:"

case "${_cg_policy_prog}/${_cg_sub}" in
  rails/console|rails/c)
    _cg_allow_exact="--no-sandbox -h --help"
    _cg_allow_value="-e --environment"
    _cg_allow_why=(
      "Options are allowlisted here, so one nobody vetted is refused"
      "rather than passed through to Rails."
    )
    _cg_allow_extras=""
    ;;
  rails/runner|rails/r)
    _cg_allow_exact="-w --skip-executor -h --help"
    _cg_allow_value="-e --environment"
    _cg_allow_why=(
      "Options are allowlisted here, so one nobody vetted is refused"
      "rather than passed through to Rails. The code to run is not an"
      "option and needs no entry."
    )
    _cg_allow_extras=""
    ;;
  *)
    # Rake's read-only and output-shaping options. Absent, deliberately:
    # -e/-E/-p (evaluate code), -f/-r/-I/-R/-C (name a path), and -g/-G/-N,
    # which change which Rakefile is found -- `--system` loads tasks from
    # $HOME/.rake, and $HOME is /app on a dyno.
    _cg_allow_exact="-A -B -m -n -P -q -s -t -v -V -X -h -H"
    _cg_allow_exact+=" --all --build-all --multitask --dry-run --prereqs"
    _cg_allow_exact+=" --quiet --silent --verbose --version --comments --rules"
    _cg_allow_exact+=" --no-deprecation-warnings --help"
    _cg_allow_value="-T -D -W -j"
    _cg_allow_value+=" --tasks --describe --where --jobs --trace --backtrace"
    _cg_allow_value+=" --job-stats"
    ;;
esac

_cg_arg_permitted() {
  local _cg_tok="$1" _cg_name
  # Unquoted on purpose: the lists are space-delimited and must word-split.
  for _cg_name in $_cg_allow_exact; do
    [[ "$_cg_tok" == "$_cg_name" ]] && return 0
  done
  for _cg_name in $_cg_allow_value; do
    [[ "$_cg_tok" == "$_cg_name" ]] && return 0
    case "$_cg_name" in
      --*) [[ "$_cg_tok" == "$_cg_name="* ]] && return 0 ;;
      *)   [[ "$_cg_tok" == "$_cg_name"?* ]] && return 0 ;;
    esac
  done
  return 1
}

# Wrap the permitted set for the denial banner. Derived from the lists above
# rather than written out again, so the two cannot drift apart.
_cg_wrap_allowed() {
  local _cg_line="" _cg_word
  # shellcheck disable=SC2086  # deliberate word splitting, as above
  for _cg_word in $_cg_allow_value $_cg_allow_exact; do
    if (( ${#_cg_line} + ${#_cg_word} + 1 > 58 )); then
      echo "  $_cg_line"
      _cg_line="$_cg_word"
    else
      _cg_line="${_cg_line:+$_cg_line }$_cg_word"
    fi
  done
  [[ -n "$_cg_line" ]] && echo "  $_cg_line"
}

for _cg_arg in ${_cg_policy_args[@]+"${_cg_policy_args[@]}"}; do
  # A bare `-` is handled above, with a message about stdin that says more than
  # this one would.
  [[ "$_cg_arg" == "-" ]] && continue
  [[ "$_cg_arg" == -* ]] || continue
  _cg_arg_permitted "$_cg_arg" && continue

  # Only when it names a command; for `rake -e 1` the "subcommand" is the
  # rejected option itself.
  _cg_context="$_cg_policy_prog"
  [[ -n "$_cg_sub" && "$_cg_sub" != -* ]] && _cg_context+=" $_cg_sub"

  _cg_allowed_lines=()
  while IFS= read -r _cg_line; do
    _cg_allowed_lines+=("$_cg_line")
  done < <(_cg_wrap_allowed)

  _cg_deny option_not_allowed \
           "\`${_cg_policy_prog} ${_cg_arg}\` is not permitted on one-off dynos." \
           "" \
           "${_cg_allow_why[@]}" \
           "" \
           "Permitted after \`${_cg_context}\`:${_cg_allow_extras:+ $_cg_allow_extras}" \
           "${_cg_allowed_lines[@]}" \
           "" \
           "Short options are matched whole, so pass them separately rather" \
           "than bundled into one argument."
done

exec "$_cg_real" "$@"
