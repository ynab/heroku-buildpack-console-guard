#!/usr/bin/env bash
# End-to-end tests for heroku-buildpack-console-guard.
#
#   ./test/run_tests.sh
#
# This suite is deliberately small. Policy -- which commands, arguments and
# options are refused, and what each denial records -- is tested in Ruby, where
# a case is a case rather than a shell payload; see test/run_ruby_tests.rb.
#
# What is left here is everything the *shell* does, which Ruby cannot stand in
# for:
#
#   * bin/compile produces a slug that works
#   * .profile.d is sourced, and the login shell acts on the gate's exit status
#     -- PATH, EDITOR/VISUAL, CONSOLE_AUDIT_ENABLED, CONSOLE_USER, exiting
#   * the shell expands the operator's command before the wrapper sees it, which
#     is the entire reason the guard is in two halves
#   * a permitted command reaches the real binary through the wrapper
#   * neither half's interpreter can be chosen by the operator
#
# Payloads below are deliberately single-quoted: they are shell source for the
# dyno command and must NOT be expanded here.
# shellcheck disable=SC2016
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
# shellcheck source=test/lib/harness.sh
source test/lib/harness.sh

# ============================================================ default build
cg_build default CONSOLE_GUARD_DYNO_METADATA_FILE="$CG_TMP_ROOT/default/dyno-metadata.json"
# A file only some tests create, so the metadata-absent path is the default.
touch "$CG_APP/payload.rb" "$CG_APP/script.rb"

cg_section "a permitted command reaches the real binary"
# Through .profile.d, the PATH the gate prepended, and the wrapper's own
# re-resolution of the real binary from the rest of PATH.
assert_ran 'rails c'                        'rails c'
assert_ran 'rake some_task:some_action'     'rake some_task:some_action'
assert_ran 'rails runner Model.some_method' 'rails runner Model.some_method'
assert_ran 'rake db:rollback STEP=99'       'rake db:rollback STEP=99'
# Heroku's Ruby buildpack rewrites `rake <task>` to this before the login shell
# runs, and `bundle exec` then puts Bundler's bin directory ahead of the
# wrapper -- so the `bundle` wrapper is the only place policy can be applied.
assert_ran 'bundle exec rake db:migrate'    'bundle exec rake db:migrate'

cg_section "a denial from either half stops the session"
assert_blocked 'psql'             'not permitted'
assert_blocked 'rails dbconsole'  'raw database session'
assert_blocked 'rake -e 1'        'allowlisted'
cg_env 'CONSOLE_USER=' ; assert_blocked 'rails c' 'CONSOLE_USER is not set'

cg_section "the shell expands the command before the wrapper sees it"
# The reason the guard is in two halves. The profile script sees a string, and
# every spelling below reaches `rails` as an argv that string does not contain.
# Policy is applied to the argv, so all of them are refused -- and this is the
# only place that can be demonstrated, because it is the shell doing the work.

# quote removal
assert_blocked 'rails "dbconsole"'          'raw database session'
assert_blocked "rails 'dbconsole'"          'raw database session'
assert_blocked 'rails db""console'          'raw database session'
assert_blocked 'rails "credentials:edit"'   'editor'
assert_blocked 'rails runner "-"'           'stdin'
assert_blocked 'rails "-c" foo'             'flag is not permitted'
assert_blocked 'rails c "--sandbox=true"'   'unlogged'
assert_blocked 'rake "--execute=1"'         'allowlisted'
# parameter expansion
cg_env 'P=-'                ; assert_blocked 'rails runner "$P"' 'stdin'
cg_env 'P=-'                ; assert_blocked 'rails runner ${P}' 'stdin'
cg_env 'T=credentials:edit' ; assert_blocked 'rails $T'          'editor'
cg_env 'S=--sandbox'        ; assert_blocked 'rails c $S'        'unlogged'
cg_env 'F=script.rb'        ; assert_blocked 'rails runner $F'   'exists on disk'
# pathname expansion
assert_blocked 'rails runner *.r?'            'exists on disk'
assert_blocked 'rails runner ~/script.rb'     'exists on disk'
assert_blocked 'rails runner $HOME/script.rb' 'exists on disk'
# brace expansion
assert_blocked 'rails runner {-,foo}'         'stdin'
assert_blocked 'rails {db,dbconsole}'         'raw database session'
# ...and a name that does not exist on disk is inline code, as it is to Rails.
assert_ran "rails runner 'Model.where(x: 1).rb'"
assert_ran 'rails runner ~/no_such_file.rb'

cg_section "compound statements and redirections"
# argv[0] is all the allowlist matches, so without this an operator could append
# a second command and reach a shell.
assert_blocked 'rails runner "1"; bash'   'Compound'
assert_blocked 'rails c | tee /tmp/x'     'Compound'
assert_blocked 'rails runner $(whoami)'   'Compound'
assert_blocked 'rails c < /app/script.rb' 'redirections'

cg_section "the CLI's --exit-code marker"
# The CLI reads this line off stdout to decide what to exit with, and a denial
# exits during .profile.d, so the appended echo never runs. Without the gate
# emitting one itself, a blocked CI job goes green.
CG_SENTINEL=$'￿'
CG_MARKER="; echo \"${CG_SENTINEL} heroku-command-exit-status: \$?\""

assert_ran "rake db:version${CG_MARKER}" 'rake db:version'
assert_output 'a denial emits a failing marker on stdout' \
  "psql${CG_MARKER}" "${CG_SENTINEL} heroku-command-exit-status: 1"
assert_no_output 'no marker without --exit-code' 'psql' 'heroku-command-exit-status'

cg_section "a command the gate cannot read is refused as such"
# A real login shell with no -c payload, which is the shape the gate is not
# built on. Fabricating that argv proves the parse; this proves the shape exists.
cg_run_no_dash_c 'rails c'
_cg_probe="$CG_OUT"
assert_true 'refuses when the login shell has no -c payload' \
  bash -c '[[ "$1" == *"Could not determine the dyno command"* ]]' _ "$_cg_probe"
assert_true 'does not run the command' \
  bash -c '[[ "$1" != *"RAN "* ]]' _ "$_cg_probe"
unset _cg_probe

cg_section "the login shell acts on the gate's exit status"
assert_output 'exports CONSOLE_AUDIT_ENABLED on run dynos' 'rails c' 'AUDIT=true'
cg_env 'DYNO=scheduler.9' ; assert_output 'scheduler dynos are audited, not gated' \
  'printenv CONSOLE_AUDIT_ENABLED' 'true'
cg_env 'DYNO=release.9'   ; assert_output 'release dynos are audited, not gated' \
  'printenv CONSOLE_AUDIT_ENABLED' 'true'
cg_env 'DYNO=web.1'       ; assert_no_output 'web dynos are left alone' \
  'printenv CONSOLE_AUDIT_ENABLED; echo done' 'true'
cg_env 'DYNO=worker.1'    ; assert_no_output 'worker dynos are left alone' \
  'printenv CONSOLE_AUDIT_ENABLED; echo done' 'true'
# EDITOR is a shell escape via `rails credentials:edit`. The wrapper blocks those
# subcommands; the profile script removes the mechanism as well.
cg_env 'EDITOR=bash' ; assert_output 'unsets EDITOR for permitted commands' 'rails c' 'EDITOR=unset'
cg_env 'VISUAL=bash' ; assert_output 'unsets VISUAL for permitted commands' 'rails c' 'EDITOR=unset'

cg_section "fail-closed behaviour"
# If the wrapper is not installed the profile script must refuse rather than run
# a half gate -- all argument policy is behind it.
mv "$CG_APP/.console-guard/bin/rails" "$CG_APP/.console-guard/rails.bak"
assert_blocked 'rails c' 'command wrapper is missing'
mv "$CG_APP/.console-guard/rails.bak" "$CG_APP/.console-guard/bin/rails"
assert_ran 'rails c'
# And the same for the policy the wrapper stub execs into.
mv "$CG_APP/.console-guard/libexec" "$CG_APP/.console-guard/libexec.bak"
assert_blocked 'rails c'
mv "$CG_APP/.console-guard/libexec.bak" "$CG_APP/.console-guard/libexec"
assert_ran 'rails c'
# The guard version appears in denials, so an operator report identifies the
# deployed guard.
assert_output 'denials name the guard version' 'psql' 'console-guard '

cg_section "the operator cannot choose the guard's interpreter"
# The policy is Ruby, so three `heroku run -e` variables are code injection into
# the thing vetting the command: PATH (which interpreter), RUBYOPT (what it
# requires first) and RUBYLIB (what answers a stdlib require). None of them may
# reach it, and only a real login shell can demonstrate that.
mkdir -p "$CG_APP/hostile"
cat > "$CG_APP/hostile/ruby" <<'EOF'
#!/bin/bash
echo "HOSTILE RUBY RAN"
exit 0
EOF
chmod 755 "$CG_APP/hostile/ruby"
# A stdlib name the guard requires. Loading this would both announce itself and
# leave JSON undefined, so the guard would die rather than pass anything.
echo 'puts "HOSTILE JSON RAN"' > "$CG_APP/hostile/json.rb"

# Exit 0 from the gate means "not a dyno this applies to", so a hostile ruby that
# simply succeeds would be a complete bypass -- the login shell would leave PATH
# alone and never gate anything.
cg_env "PATH=$CG_APP/hostile:/usr/local/bin:/usr/bin:/bin"
assert_blocked 'psql' 'not permitted'
cg_env "PATH=$CG_APP/hostile:/usr/local/bin:/usr/bin:/bin"
assert_no_output 'a ruby earlier on PATH is not the one that runs' 'psql' 'HOSTILE RUBY RAN'
cg_env 'RUBYOPT=-rhostile_payload' ; assert_blocked 'psql' 'not permitted'
cg_env 'RUBYOPT=-rhostile_payload' ; assert_ran 'rails c'
cg_env "RUBYLIB=$CG_APP/hostile"   ; assert_ran 'rails c'
cg_env "RUBYLIB=$CG_APP/hostile"
assert_no_output 'RUBYLIB cannot answer a stdlib require' 'rails c' 'HOSTILE JSON RAN'
# The wrapper is a separate process with its own interpreter to choose, so the
# same three have to be closed there too.
cg_env "RUBYLIB=$CG_APP/hostile"   ; assert_blocked 'rails dbconsole' 'raw database session'
cg_env 'RUBYOPT=-rhostile_payload' ; assert_blocked 'rails dbconsole' 'raw database session'

# ============================================================ dyno metadata
cg_section "\$DYNO cannot be spoofed when metadata exists"
cg_build metadata CONSOLE_GUARD_DYNO_METADATA_FILE="$CG_TMP_ROOT/metadata/dyno-metadata.json"
cg_write_metadata '{"dyno":{"id":"de7c25da-uuid","name":"run.1234"},"app":{"id":"0d276459-uuid","name":""},"release":{"id":117,"commit":"9eb6f0d7","description":"Deploy 9eb6f0d7"}}'
assert_ran 'rails c'
# The operator claims to be on a web dyno to skip the gate; the file disagrees.
cg_env 'DYNO=web.1' ; assert_blocked 'rails c' 'does not match this dyno'

# ============================================================ dry-run mode
cg_section "phase 1: dry-run mode hands the app an operator"
cg_build permit CONSOLE_GUARD_DYNO_METADATA_FILE="$CG_TMP_ROOT/permit/dyno-metadata.json"
cg_env_sticky 'CONSOLE_BLOCK_ENFORCE=false'
assert_output 'the audit hook is still activated' 'rails c' 'AUDIT=true'
assert_output 'a would-be denial warns and permits' 'psql' 'WILL BE BLOCKED'
# An empty CONSOLE_USER is not enough to be non-blocking: console1984 raises
# MissingUsername on one, so the console dies anyway and dry-run mode fails to
# permit. The app gets a placeholder instead -- obviously not a real username, so
# an audit record cannot be mistaken for an identified session. Only the login
# shell can export it, which is why it has an exit status of its own.
cg_env 'CONSOLE_USER=' ; assert_output 'dry-run mode supplies a placeholder operator' \
  'rails c' 'USER=[not provided]'
cg_env 'CONSOLE_USER=   ' ; assert_output 'whitespace-only counts as absent here too' \
  'rails c' 'USER=[not provided]'
assert_output 'a real CONSOLE_USER is left alone' 'rails c' 'USER=becky'
cg_env_sticky

# ============================================================ denial records
cg_section "denials are recorded through the whole chain"
# The record's shape is pinned in Ruby. What this proves is that a denial from
# either half reaches the endpoint from inside a real dyno session.
cg_build report CONSOLE_GUARD_DYNO_METADATA_FILE="$CG_TMP_ROOT/report/dyno-metadata.json"
cg_write_metadata '{"dyno":{"id":"dyno-uuid-1","name":"run.1234"},"app":{"id":"aid","name":""},"release":{"id":117}}'

assert_reported 'a profile denial is POSTed' 'psql' '"rule":"command_not_allowed"'
assert_reported 'a wrapper denial is POSTed too' 'rails "dbconsole"' \
  '"rule":"raw_database_session"'
# The command is judged and recorded without the CLI's marker, so a CI denial
# record reads as the command the caller wrote.
assert_reported 'the --exit-code marker is not in the record' \
  "psql${CG_MARKER}" '"command":"psql"'

# ============================================================ compile
cg_section "bin/compile"
assert_false 'fails when BUILD_DIR is missing'    "$CG_ROOT/bin/compile"
assert_false 'fails when BUILD_DIR is unwritable' "$CG_ROOT/bin/compile" /proc/nonexistent/app
assert_true  'installs the profile script' test -f "$CG_APP/.profile.d/zzz_console_guard.sh"
assert_true  'installs the rails wrapper'  test -x "$CG_APP/.console-guard/bin/rails"
assert_true  'installs the rake wrapper'   test -x "$CG_APP/.console-guard/bin/rake"
assert_true  'installs the bundle wrapper' test -x "$CG_APP/.console-guard/bin/bundle"
assert_true  'installs the policy' test -f "$CG_APP/.console-guard/lib/console_guard.rb"
assert_true  'installs the gate entry point' \
  test -f "$CG_APP/.console-guard/libexec/run_gate.rb"
assert_true  'installs the wrapper entry point' \
  test -f "$CG_APP/.console-guard/libexec/run_command.rb"
assert_false 'leaves no unsubstituted placeholders' \
  grep -rq '@@CG_' "$CG_APP/.profile.d" "$CG_APP/.console-guard"
assert_true  'generated profile script is valid bash' \
  bash -n "$CG_APP/.profile.d/zzz_console_guard.sh"
assert_true  'generated wrapper is valid bash' bash -n "$CG_APP/.console-guard/bin/rails"
assert_true  'build log records the guard version' grep -q 'Installing console guard' "$CG_BUILD_LOG"
assert_true  'build log records the resolved ruby' grep -q '^       ruby: /' "$CG_BUILD_LOG"

# Every installed .rb parses. A syntax error reaches a production dyno as a gate
# that cannot run, which the login shell then has to treat as a refusal.
_cg_bad_ruby=0
while IFS= read -r _cg_rb; do
  ruby -c "$_cg_rb" > /dev/null 2>&1 || _cg_bad_ruby=$((_cg_bad_ruby + 1))
done < <(find "$CG_APP/.console-guard" -name '*.rb')
assert_true 'every generated ruby file parses' test "$_cg_bad_ruby" -eq 0
unset _cg_bad_ruby _cg_rb

# bin/compile cannot install a guard it has no interpreter for, and a green build
# with no guard is the worst outcome available.
assert_false 'fails when no ruby can be resolved' \
  env -i PATH=/nonexistent "$CG_ROOT/bin/compile" "$CG_TMP_ROOT/no-ruby"

# The slug is built in BUILD_DIR and extracted at /app, so an interpreter
# vendored into it is at a different path in the dyno. Baking the build-time
# path would leave every dyno unable to start the guard -- and the guard treats
# a missing interpreter as a refusal, so it would take out `heroku run` on the
# next deploy rather than failing here.
_cg_vendor="$CG_TMP_ROOT/vendored"
_cg_vendor_bin="$_cg_vendor/app/.heroku/ruby-9.9.9/bin"
mkdir -p "$_cg_vendor_bin" "$_cg_vendor/env"
printf '#!/bin/sh\nexec %s "$@"\n' "$(command -v ruby)" > "$_cg_vendor_bin/ruby"
chmod 755 "$_cg_vendor_bin/ruby"
PATH="$_cg_vendor_bin:$PATH" "$CG_ROOT/bin/compile" \
  "$_cg_vendor/app" "$_cg_vendor/cache" "$_cg_vendor/env" > "$_cg_vendor/build.log" 2>&1
CG_OUT="$(cat "$_cg_vendor/build.log")"
assert_true 'a slug-vendored ruby is baked as the path the dyno will see' \
  grep -q '^_cg_ruby="/app/.heroku/ruby-9.9.9/bin/ruby"$' \
  "$_cg_vendor/app/.profile.d/zzz_console_guard.sh"
assert_true 'and the command wrapper gets the same one' \
  grep -q '^_cg_ruby="/app/.heroku/ruby-9.9.9/bin/ruby"$' \
  "$_cg_vendor/app/.console-guard/bin/rails"
unset _cg_vendor _cg_vendor_bin

cg_finish
