#!/usr/bin/env bash
# End-to-end tests for heroku-buildpack-console-guard.
#
#   ./test/run_tests.sh
#
# No dependencies beyond bash and coreutils. Every case names the behaviour it
# pins; the cases marked "regression" were bypasses that passed the gate at
# 7f1e0d8 (the initial commit) and must stay blocked.

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

cg_section "permitted commands still work"
assert_ran 'rails c'                        'rails c'
assert_ran 'rails console --sandbox'        'rails console --sandbox'
assert_ran 'rake some_task:some_action'     'rake some_task:some_action'
assert_ran 'rails runner Model.some_method' 'rails runner Model.some_method'
# Quoted inline code has to keep working: the wrapper exists so that policy can
# be enforced without banning quotes.
assert_ran "rails runner 'Model.some_method(1, 2)'" 'rails runner Model.some_method(1, 2)'
assert_ran 'rails db:migrate'               'rails db:migrate'
assert_ran 'rake db:migrate'                'rake db:migrate'
# Destructive db tasks are deliberately not gated here: the api:dyno webhook
# records them and the app's own production guard covers the rest.
assert_ran 'rake db:drop'                   'rake db:drop'
assert_ran 'rails db:migrate:reset'         'rails db:migrate:reset'
assert_ran 'rake db:rollback STEP=99'       'rake db:rollback STEP=99'
assert_ran 'rake db:seed'
assert_ran 'rake -T'                        'rake -T'
assert_ran 'rails runner -e production Model.foo'

cg_section "identification is required"
cg_env 'CONSOLE_USER='       ; assert_blocked 'rails c' 'CONSOLE_USER is not set'
cg_env 'CONSOLE_REASON='     ; assert_blocked 'rails c' 'CONSOLE_REASON is not set'
cg_env 'CONSOLE_REASON=   '  ; assert_blocked 'rails c' 'CONSOLE_REASON is not set'
cg_env 'CONSOLE_USER=   '    ; assert_blocked 'rails c' 'CONSOLE_USER is not set'
# Naming the missing one matters: the usual cause is a failed `heroku whoami`
# substituting an empty string, which looks like neither was set.
cg_env 'CONSOLE_USER= CONSOLE_REASON=' ; assert_blocked 'rails c' \
  'CONSOLE_USER and CONSOLE_REASON are not set'
cg_env 'CONSOLE_USER='       ; assert_no_output 'names only the missing variable' \
  'rails c' 'CONSOLE_REASON is not set'

cg_section "allowlist"
assert_blocked 'bash'                  'not permitted'
assert_blocked 'sh'                    'not permitted'
assert_blocked 'irb'
assert_blocked 'ruby -e 1'
assert_blocked 'psql'
assert_blocked 'printenv'
assert_blocked 'curl https://example.com'
# `bundle exec rails|rake` is permitted -- Heroku's Ruby buildpack produces it
# for a permitted command. See the bundle exec section for what that admits.
# Path-qualified forms are rejected because they skip the PATH lookup that
# reaches the command wrapper.
assert_blocked 'bin/rails c'           'must be unqualified'
assert_blocked './bin/rails c'         'must be unqualified'
assert_blocked '/app/bin/rails c'      'must be unqualified'
# A leading assignment could put the wrapper out of reach: PATH=... rails c
assert_blocked 'FOO=1 rails c'         'must be unqualified'
assert_blocked 'PATH=/usr/bin rails c' 'must be unqualified'

cg_section "bundle exec, as Heroku's Ruby buildpack produces it"
# Heroku rewrites `rake <task>` on a one-off dyno to `bundle exec rake <task>`
# before the login shell runs, so `bundle` must be permitted or no rake task
# works at all. `bundle exec` also unshifts Bundler's bin directory onto PATH,
# which puts the real rails/rake ahead of the wrapper -- so the `bundle` wrapper
# is the only place the argument rules can be applied, and these cases pin that.
assert_ran 'bundle exec rake db:migrate'  'bundle exec rake db:migrate'
assert_ran 'bundle exec rails c'          'bundle exec rails c'
assert_ran 'bundle exec rails runner Model.some_method'
# Admitting `bundle` must not admit what it can wrap.
assert_blocked 'bundle exec bash'         'not permitted'
assert_blocked 'bundle exec sh -c id'     'not permitted'
assert_blocked 'bundle exec irb'          'not permitted'
assert_blocked 'bundle install'           'Ruby buildpack produces'
assert_blocked 'bundle'                   'Ruby buildpack produces'
assert_blocked 'bundle exec'              'may be run under'
assert_blocked 'bundle exec bin/rails c'  'unqualified'
# Every rule the rails/rake wrapper applies must apply through bundle too,
# because this is now the only wrapper the command reaches.
assert_blocked 'bundle exec rails dbconsole'        'raw database session'
assert_blocked 'bundle exec rails "dbconsole"'      'raw database session'
assert_blocked 'bundle exec rails credentials:edit' 'editor'
assert_blocked 'bundle exec rails runner -'         'stdin'
assert_blocked 'bundle exec rails runner "-"'       'stdin'
assert_blocked 'bundle exec rails runner script.rb' 'exists on disk'
assert_blocked 'bundle exec rails runner *.r?'      'exists on disk'
assert_blocked 'bundle exec rake -c'                'flag is not permitted'

cg_section "denials report what the gate parsed"
# A denial that does not echo the command cannot be diagnosed from an operator's
# report: "not permitted" alone says nothing about which word was rejected, or
# whether the gate even parsed the string that was typed.
assert_output 'allowlist denial echoes the command' \
  'bundle exec rails c' 'bundle exec rails c'
assert_output 'allowlist denial names the rejected word' \
  'bundle exec rails c' 'bundle'
assert_output 'allowlist denial echoes a qualified path' \
  '/app/bin/rails c' '/app/bin/rails c'
assert_output 'compound denial echoes the command' \
  'rails runner "1"; bash' 'rails runner "1"; bash'

cg_section "a command the gate cannot read is refused as such"
# Not the allowlist denial: there is no command string here, and reporting one
# invented from the whole argv sends the operator hunting for a command they
# never typed.
cg_run_no_dash_c 'rails c'
_cg_probe="$CG_OUT"
assert_true 'refuses when the login shell has no -c payload' \
  bash -c '[[ "$1" == *"Could not determine the dyno command"* ]]' _ "$_cg_probe"
assert_true 'reports the login shell argv it did see' \
  bash -c '[[ "$1" == *"Login shell argv:"* ]]' _ "$_cg_probe"
assert_true 'does not report it as a disallowed command' \
  bash -c '[[ "$1" != *"not permitted on one-off dynos"* ]]' _ "$_cg_probe"
assert_true 'does not run the command' \
  bash -c '[[ "$1" != *"RAN "* ]]' _ "$_cg_probe"
unset _cg_probe

cg_section "compound statements and redirections"
assert_blocked 'rails runner "1"; bash'
assert_blocked 'rails c && bash'
assert_blocked 'rails c | tee /tmp/x'
assert_blocked 'rails runner `whoami`'
assert_blocked 'rails runner $(whoami)'
# regression (finding 3): stdin redirection reopened the hole the bare `-` check
# exists to close.
assert_blocked 'rails c < /app/script.rb'      'redirections'
assert_blocked 'rails c < script.rb'           'redirections'
assert_blocked 'rake some:task <<< "x"'        'redirections'
assert_blocked 'rails runner Model.foo > /tmp/o'
assert_blocked 'rails runner Model.foo 2>/tmp/o'

cg_section "regression (finding 2): quote removal must not defeat policy"
assert_blocked 'rails "dbconsole"'              'not permitted'
assert_blocked "rails 'dbconsole'"              'not permitted'
assert_blocked 'rails db""console'              'not permitted'
assert_blocked 'rails ""dbconsole'              'not permitted'
assert_blocked 'rails "credentials:edit"'       'editor'
assert_blocked 'rails credentials:ed"it"'       'editor'
assert_blocked "rails 'credentials:edit'"       'editor'
assert_blocked 'rails runner "-"'               'stdin'
assert_blocked "rails runner '-'"               'stdin'
assert_blocked 'rails runner -""'               'stdin'
assert_blocked 'rails "-c" foo'                 'flag is not permitted'
assert_blocked 'rails runner "--file=/app/script.rb"'
assert_blocked 'rails runner "--file" script.rb'

cg_section "regression (finding 2): parameter expansion must not defeat policy"
cg_env 'P=-'                    ; assert_blocked 'rails runner $P'      'stdin'
cg_env 'P=-'                    ; assert_blocked 'rails runner "$P"'    'stdin'
cg_env 'P=-'                    ; assert_blocked 'rails runner ${P}'    'stdin'
cg_env 'F=script.rb'            ; assert_blocked 'rails runner $F'      'exists on disk'
cg_env 'T=credentials:edit'     ; assert_blocked 'rails $T'            'editor'
cg_env 'S=dbconsole'            ; assert_blocked 'rails $S'             'not permitted'

cg_section "regression (finding 2): pathname expansion must not defeat policy"
assert_blocked 'rails runner *.r?'      'exists on disk'
assert_blocked 'rails runner scr?pt.rb' 'exists on disk'
assert_blocked 'rails runner script.rb' 'exists on disk'
assert_blocked 'rails runner ./script.rb'
assert_blocked 'rails runner ~/script.rb'  'exists on disk'
assert_blocked 'rails runner $HOME/script.rb' 'exists on disk'
# Brace expansion is another way to smuggle a token past a string check. The
# wrapper sees the expanded argv, so it needs no rule of its own.
assert_blocked 'rails runner {-,foo}'   'stdin'
assert_blocked 'rails {db,dbconsole}'   'not permitted'
assert_blocked 'rails {credentials:edit,x}' 'editor'
# The file test now matches what Rails itself does, so a name that does not exist
# on disk is inline code and is allowed -- the old heuristic blocked it.
assert_ran "rails runner 'Model.where(x: 1).rb'"
assert_ran 'rails runner ~/no_such_file.rb'

cg_section "enforcement defaults to blocking"
# Only the exact string `false` opts into permit mode, so a typo or an empty
# value fails closed.
cg_env 'CONSOLE_BLOCK_ENFORCE=0'     ; assert_blocked 'bash'
cg_env 'CONSOLE_BLOCK_ENFORCE='      ; assert_blocked 'bash'
cg_env 'CONSOLE_BLOCK_ENFORCE=False' ; assert_blocked 'bash'
cg_env 'CONSOLE_BLOCK_ENFORCE=true'  ; assert_blocked 'bash'

cg_section "regression (finding 6): editor-based shell escapes"
assert_blocked 'rails credentials:edit'          'editor'
assert_blocked 'rails credentials:show'          'editor'
assert_blocked 'rails encrypted:edit config/x'   'editor'
cg_env 'EDITOR=bash' ; assert_blocked 'rails credentials:edit'
# EDITOR/VISUAL are also removed from the environment the command inherits.
cg_env 'EDITOR=bash' ; assert_output 'unsets EDITOR for permitted commands' 'rails c' 'EDITOR=unset'
cg_env 'VISUAL=bash' ; assert_output 'unsets VISUAL for permitted commands' 'rails c' 'EDITOR=unset'

cg_section "the audit hook is activated"
assert_output 'exports CONSOLE_AUDIT_ENABLED on run dynos' 'rails c' 'AUDIT=true'

cg_section "regression (finding 7): dyno families"
# Scheduler and release dynos are one-off dynos too. They are not gated -- no
# operator is present to give a reason -- but they must still be audited.
cg_env 'DYNO=scheduler.9' ; assert_output 'scheduler dynos are audited' \
  'printenv CONSOLE_AUDIT_ENABLED' 'true'
cg_env 'DYNO=release.9'   ; assert_output 'release dynos are audited' \
  'printenv CONSOLE_AUDIT_ENABLED' 'true'
cg_env 'DYNO=web.1'       ; assert_no_output 'web dynos are left alone' \
  'printenv CONSOLE_AUDIT_ENABLED; echo done' 'true'
cg_env 'DYNO=worker.1'    ; assert_no_output 'worker dynos are left alone' \
  'printenv CONSOLE_AUDIT_ENABLED; echo done' 'true'
# An unrecognised or absent dyno name is treated as a one-off dyno.
cg_env 'DYNO='            ; assert_blocked 'bash' 'not permitted'

cg_section "fail-closed behaviour"
# regression (finding 8 / the wrapper is load-bearing): if the wrapper is not
# installed the profile script must refuse rather than run a half gate.
mv "$CG_APP/.console-guard/bin/rails" "$CG_APP/.console-guard/rails.bak"
assert_blocked 'rails c' 'command wrapper is missing'
mv "$CG_APP/.console-guard/rails.bak" "$CG_APP/.console-guard/bin/rails"
assert_ran 'rails c'
# The bundle wrapper is load-bearing in the same way: without it, Heroku's
# `bundle exec` rewrite would reach the real bundler with no policy applied.
mv "$CG_APP/.console-guard/bin/bundle" "$CG_APP/.console-guard/bundle.bak"
assert_blocked 'rails c' 'command wrapper is missing'
mv "$CG_APP/.console-guard/bundle.bak" "$CG_APP/.console-guard/bin/bundle"
assert_ran 'rails c'
# The guard version appears in denials, so an operator report identifies the
# deployed guard.
assert_output 'denials name the guard version' 'bash' 'console-guard '

# ============================================================ dyno metadata
cg_section "regression (finding 4): \$DYNO cannot be spoofed when metadata exists"
cg_build metadata CONSOLE_GUARD_DYNO_METADATA_FILE="$CG_TMP_ROOT/metadata/dyno-metadata.json"
# The real /etc/heroku/dyno shape: three objects, each with its own name/id, and
# app.name empty. A greedy parser reads app.name (empty) instead of dyno.name and
# silently falls back to trusting $DYNO -- the finding-4 hole, reopened.
cg_write_metadata '{"dyno":{"id":"de7c25da-uuid","name":"run.1234"},"app":{"id":"0d276459-uuid","name":""},"release":{"id":117,"commit":"9eb6f0d7","description":"Deploy 9eb6f0d7"}}'
assert_ran 'rails c'
assert_no_output 'no metadata warning when metadata is present' 'rails c' 'dyno metadata is not enabled'
# The operator claims to be on a web dyno to skip the gate; the file disagrees.
cg_env 'DYNO=web.1'    ; assert_blocked 'bash' 'does not match this dyno'
cg_env 'DYNO=web.1'    ; assert_blocked 'rails c' 'does not match this dyno'
cg_env 'DYNO=run.9999' ; assert_blocked 'bash' 'does not match this dyno'
# Unparseable metadata degrades to the $DYNO fallback rather than erroring.
cg_write_metadata 'not json at all'
assert_ran 'rails c'
assert_output 'warns when metadata is unreadable' 'rails c' 'dyno metadata is not enabled'

# ============================================================ permit mode
cg_section "phase 1: permit mode (CONSOLE_BLOCK_ENFORCE=false)"
cg_build permit CONSOLE_GUARD_DYNO_METADATA_FILE="$CG_TMP_ROOT/permit/dyno-metadata.json"
touch "$CG_APP/script.rb"
cg_env_sticky 'CONSOLE_BLOCK_ENFORCE=false'
assert_output 'the audit hook is still activated' 'rails c' 'AUDIT=true'
# Warns and runs, from both halves of the gate.
assert_output 'profile check warns and permits' 'bash' 'WILL BE BLOCKED'
assert_output 'wrapper check warns and permits' 'rails "dbconsole"' 'WILL BE BLOCKED'
assert_ran 'rails "dbconsole"'
assert_ran 'rails runner "-"'
assert_ran 'rails credentials:edit'
cg_env 'CONSOLE_USER=' ; assert_output 'missing identification warns and permits' \
  'rails c' 'WILL BE BLOCKED'
# An empty CONSOLE_USER is not enough to be non-blocking: console1984 raises
# MissingUsername on one, so the console dies anyway and permit mode fails to
# permit. The app gets a placeholder instead -- obviously not a real username,
# so an audit record cannot be mistaken for an identified session.
cg_env 'CONSOLE_USER=' ; assert_output 'permit mode supplies a placeholder operator' \
  'rails c' 'USER=[not provided]'
cg_env 'CONSOLE_USER=   ' ; assert_output 'whitespace-only counts as absent here too' \
  'rails c' 'USER=[not provided]'
# A supplied identity is passed through untouched.
assert_output 'a real CONSOLE_USER is left alone' 'rails c' 'USER=becky'
# ...but tampering with the dyno name is still fatal in permit mode.
cg_write_metadata '{"dyno":{"id":"uuid","name":"run.1234"},"app":{"id":"aid","name":""},"release":{"id":117}}'
cg_env 'DYNO=web.1' ; assert_blocked 'bash' 'does not match this dyno'
cg_env_sticky

# ============================================================ compile
cg_section "bin/compile"
assert_false 'fails when BUILD_DIR is missing'    "$CG_ROOT/bin/compile"
assert_false 'fails when BUILD_DIR is unwritable' "$CG_ROOT/bin/compile" /proc/nonexistent/app
assert_true  'installs the profile script' test -f "$CG_APP/.profile.d/zzz_console_guard.sh"
assert_true  'installs the rails wrapper'   test -x "$CG_APP/.console-guard/bin/rails"
assert_true  'installs the rake wrapper'    test -x "$CG_APP/.console-guard/bin/rake"
assert_true  'installs the bundle wrapper'  test -x "$CG_APP/.console-guard/bin/bundle"
assert_true  'generated bundle wrapper is valid bash' \
  bash -n "$CG_APP/.console-guard/bin/bundle"
assert_false 'leaves no unsubstituted placeholders' \
  grep -rq '@@CG_' "$CG_APP/.profile.d" "$CG_APP/.console-guard"
assert_true  'generated profile script is valid bash' \
  bash -n "$CG_APP/.profile.d/zzz_console_guard.sh"
assert_true  'generated wrapper is valid bash' bash -n "$CG_APP/.console-guard/bin/rails"
assert_true  'build log records the guard version' grep -q 'Installing console guard' "$CG_BUILD_LOG"

cg_finish
