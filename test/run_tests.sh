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
assert_ran 'rails console'                  'rails console'
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

cg_section "the CLI's --exit-code marker"
# `heroku run --exit-code` appends this to the dyno command and reads the line it
# produces off stdout. Without special handling every CI caller is denied as a
# compound statement, and every denial exits 0 because the appended echo never runs.
CG_SENTINEL=$'￿'
CG_MARKER="; echo \"${CG_SENTINEL} heroku-command-exit-status: \$?\""

assert_ran    "rake db:version${CG_MARKER}"          'rake db:version'
assert_ran    "rails runner 1${CG_MARKER}"           'rails runner 1'
assert_ran    "bundle exec rake db:version${CG_MARKER}"

# The marker is stripped, not trusted: what precedes it is still vetted in full.
assert_blocked "psql${CG_MARKER}"                    'not permitted'
assert_blocked "rails c ; bash${CG_MARKER}"          'Compound'
assert_blocked "rails dbconsole${CG_MARKER}"         'not permitted'

# Stripped at most once, so a second copy still reads as a compound.
assert_blocked "rails c${CG_MARKER}${CG_MARKER}"     'Compound'

# The reason the match is an exact literal rather than a pattern: a loose rule
# such as s/;.*exit-status.*$// strips this back to `rails c` and lets a shell out.
assert_blocked 'rails c ; bash # heroku-command-exit-status'  'Compound'
assert_blocked 'rails c ; bash ; echo "heroku-command-exit-status: $?"' 'Compound'

# A denial has to stand in for the echo it skipped, on stdout, or the CLI reports
# success for a command that never ran.
assert_output 'denial emits a failing exit-status marker when --exit-code was used' \
  "psql${CG_MARKER}" "${CG_SENTINEL} heroku-command-exit-status: 1"
cg_env 'CONSOLE_USER=' ; assert_output \
  'the identity gate emits it too -- the denial CI is likeliest to hit' \
  "rake db:version${CG_MARKER}" "${CG_SENTINEL} heroku-command-exit-status: 1"

# ...and must not invent one for a caller that never asked for it.
assert_no_output 'no marker without --exit-code' \
  'psql' 'heroku-command-exit-status'

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

cg_section "sandboxed consoles roll back the audit trail"
assert_blocked 'rails console --sandbox'        'unlogged'
assert_blocked 'rails c --sandbox'              'unlogged'
assert_blocked 'rails c -s'                     'unlogged'
assert_blocked 'rails console -s'               'unlogged'
assert_blocked 'bundle exec rails c --sandbox'  'unlogged'
assert_blocked 'rails c "--sandbox"'            'unlogged'
cg_env 'S=--sandbox'            ; assert_blocked 'rails c $S'           'unlogged'
# Thor takes `--flag=value` for a boolean, so the `=` forms have to be denied by
# this rule and not merely by the option allowlist below -- otherwise adding a
# sandbox-ish entry to the console's allowlist reopens the bypass with the whole
# suite green. Denied whatever the value is, `false` included: deciding which
# values Thor reads as true is modelling the parser.
assert_blocked 'rails c "--sandbox=true"'       'unlogged'
assert_blocked 'rails console "--sandbox=true"' 'unlogged'
assert_blocked 'rails c "--sandbox=1"'          'unlogged'
assert_blocked 'rails c "--sandbox=false"'      'unlogged'
assert_blocked 'rails c "-s=true"'              'unlogged'
assert_blocked 'bundle exec rails c "--sandbox=true"' 'unlogged'
cg_env 'S=--sandbox=true'       ; assert_blocked 'rails c $S'           'unlogged'
# The denial points at the spelling that works.
assert_output 'the sandbox denial names --no-sandbox' \
  'rails c "--sandbox=true"' '`--no-sandbox` is permitted'
# Scoped to the console: -s is rake's silent flag, and --no-sandbox is the safe
# direction. Neither is collateral damage.
assert_ran 'rake -s some:task'
assert_ran 'rails c --no-sandbox'
assert_ran 'rails c'

cg_section "rake evaluates code in its own option parser"
# -e/-p/-E eval and exit inside rake's option parser, before the Rakefile is
# loaded, so nothing boots and the audit hook records nothing at all.
assert_blocked 'rake -e 1'                     'allowlisted'
assert_blocked 'rake --execute 1'              'allowlisted'
assert_blocked 'rake -p 1+1'                   'allowlisted'
assert_blocked 'rake -E 1'                     'allowlisted'
assert_blocked 'rake --execute-print 1'        'allowlisted'
assert_blocked 'rake --execute-continue 1'     'allowlisted'
assert_blocked 'rake "--execute=1"'            'allowlisted'
assert_blocked 'bundle exec rake -e 1'         'allowlisted'
cg_env 'P=-e' ; assert_blocked 'rake $P 1'     'allowlisted'
# Short options bundle in rake, so the allowlist matches whole tokens: `-s` is
# permitted but `-se` is a different token and is refused.
assert_blocked 'rake -Ne 1'                    'allowlisted'
assert_blocked 'rake -se 1'                    'allowlisted'
assert_blocked 'rake -qsNe 1'                  'allowlisted'
# ...which also means a bundle of two permitted flags is refused. Cheap: -s -q.
assert_blocked 'rake -sq some:task'            'matched whole'
# Abbreviated long forms, which rake accepts and the allowlist does not.
assert_blocked 'rake --exec 1'                 'allowlisted'
assert_blocked 'rake --ex 1'                   'allowlisted'
assert_blocked 'rake --task'                   'allowlisted'
# Options that name a path rather than the code that runs.
assert_blocked 'rake -f Rakefile some:task'    'allowlisted'
assert_blocked 'rake -r ./payload some:task'   'allowlisted'
assert_blocked 'rake -I /app some:task'        'allowlisted'
assert_blocked 'rake -R /app some:task'        'allowlisted'
assert_blocked 'rake -C /app some:task'        'allowlisted'
assert_blocked 'rake --require ./payload'      'allowlisted'
assert_blocked 'rake --rakefile Rakefile'      'allowlisted'
# `--system` loads tasks from $HOME/.rake, and $HOME is /app on a dyno. The
# allowlist refuses these without anyone having had to think of them.
assert_blocked 'rake -g some:task'             'allowlisted'
assert_blocked 'rake -G some:task'             'allowlisted'
assert_blocked 'rake -N some:task'             'allowlisted'
assert_blocked 'rake --system some:task'       'allowlisted'
assert_blocked 'rake --suppress-backtrace x'   'allowlisted'
assert_blocked 'rake --no-such-option'         'allowlisted'
# Rails hands a command it does not recognise to rake's option parser, argv and
# all, so the same options arrive by way of `rails`.
assert_blocked 'rails -e 1'                    'allowlisted'
assert_blocked 'rails db:migrate -e 1'         'allowlisted'
assert_blocked 'bundle exec rails -e 1'        'allowlisted'
# The denial names what is permitted, so a false positive is self-service.
assert_output 'the denial lists the permitted options' \
  'rake --no-such-option' '--tasks'
assert_output 'the denial names the command it applies to' \
  'rails db:migrate --no-such-option' 'Permitted after `rails db:migrate`'

cg_section "the permitted rake options still work"
assert_ran 'rake -T'                    'rake -T'
assert_ran 'rake -T db'
assert_ran 'rake -Tdb'                  'rake -Tdb'
assert_ran 'rake "--tasks=db"'
assert_ran 'rake -D db'
assert_ran 'rake -W some:task'
assert_ran 'rake -P'
assert_ran 'rake -s some:task'
assert_ran 'rake -q some:task'
assert_ran 'rake -n some:task'
assert_ran 'rake -t some:task'
assert_ran 'rake -v some:task'
assert_ran 'rake -V'
assert_ran 'rake -A -T'
assert_ran 'rake -B some:task'
assert_ran 'rake -m some:task'
assert_ran 'rake -j 4 some:task'
assert_ran 'rake -j4 some:task'
assert_ran 'rake -X some:task'
assert_ran 'rake --trace some:task'     'rake --trace some:task'
assert_ran 'rake "--trace=stderr" some:task'
assert_ran 'rake --backtrace some:task'
assert_ran 'rake --dry-run some:task'
assert_ran 'rake --all --tasks'
assert_ran 'rake --comments --tasks'
assert_ran 'rake --rules'
assert_ran 'rake --job-stats some:task'
assert_ran 'rake --silent some:task'
assert_ran 'rake --version'
# Task names, task arguments and VAR=value assignments are not options and are
# not screened.
assert_ran 'rake db:rollback STEP=99'   'rake db:rollback STEP=99'
assert_ran 'rake "some:task[a,b]"'
assert_ran 'rake -s db:migrate STEP=1'

cg_section "the commands Rails parses itself get their own list"
# `-e` is the environment here, not rake's execute. These commands never reach
# rake's parser -- but they are allowlisted rather than exempted, so a mistake
# in the list is a denial rather than a silent bypass.
assert_ran 'rails runner -e production Model.foo'
assert_ran 'rails runner --environment production Model.foo'
assert_ran 'rails runner -w Model.foo'
assert_ran 'rails c -e production'
assert_ran 'rails console --environment production'
assert_ran 'rails c --no-sandbox'
assert_ran 'rails c'
assert_ran 'bundle exec rails c -e production'
# Options neither Rails command takes are refused rather than passed through.
assert_blocked 'rails c --no-such-option'   'allowlisted'
assert_blocked 'rails runner -f Model.foo'  'allowlisted'
assert_blocked 'rails c -w'                 'allowlisted'
# regression: `-s` reaches neither parser as anything useful. The rule that
# matters -- the sandbox denial is scoped to the console -- is pinned by
# `rake -s` above and `rails c -s` below.
assert_blocked 'rails runner -s Model.foo'  'allowlisted'

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

# ============================================================ denial records
# The denial banner reaches only the operator's terminal, so without these the
# only durable trace of a blocked command is Heroku's api:dyno record, which
# cannot tell a guard denial from an application error.
cg_section "denials are recorded durably"
cg_build report CONSOLE_GUARD_DYNO_METADATA_FILE="$CG_TMP_ROOT/report/dyno-metadata.json"
cg_write_metadata '{"dyno":{"id":"dyno-uuid-1","name":"run.1234"},"app":{"id":"aid","name":""},"release":{"id":117}}'

assert_reported 'a profile denial is POSTed'  'bash'  '"event":"command_denied"'
assert_reported 'names the rule that refused' 'bash'  '"rule":"command_not_allowed"'
assert_reported 'carries the command'         'psql'  '"command":"psql"'
assert_reported 'carries the operator'        'bash'  '"operator":"becky"'
assert_reported 'carries the reason'          'bash'  '"reason":"testing"'
# The join key for the api:dyno cross-check, taken from the metadata file rather
# than from HEROKU_DYNO_ID, which `heroku run -e` can set to anything.
assert_reported 'carries the trusted dyno id' 'bash'  '"dyno_id":"dyno-uuid-1"'
assert_reported 'marks the denial enforced'   'bash'  '"enforced":true'
# Without `app` the cross-check queries, which scope on @app to reach both log
# sources at once, skip every denial record. See guard/denial_report.sh.
cg_env 'HEROKU_APP_NAME=some-app'
assert_reported 'carries the app, so @app reaches this record' 'bash' \
  '"app":"some-app"'
# ...and nothing else attributional: the proxy derives service from the
# credential, which is the half an operator cannot forge.
#
# Matched with the leading comma and trailing colon, because `"version"` is a
# substring of the `guard_version` field that is legitimately there.
cg_env 'HEROKU_APP_NAME=some-app DD_ENV=lies DD_SERVICE=lies DD_VERSION=lies'
assert_not_reported_field 'sends no env'     'bash' ',"env":'
cg_env 'HEROKU_APP_NAME=some-app DD_ENV=lies DD_SERVICE=lies DD_VERSION=lies'
assert_not_reported_field 'sends no service' 'bash' ',"service":'
cg_env 'HEROKU_APP_NAME=some-app DD_ENV=lies DD_SERVICE=lies DD_VERSION=lies'
assert_not_reported_field 'sends no version' 'bash' ',"version":'
cg_run_reporting 'bash'
assert_true 'goes to the configured endpoint' \
  grep -q "example.invalid/webhooks/console_audit" "$CG_CURL_LOG"

# The wrapper's denials are half of them, and a trail with only the other half
# would report every argument-policy block as a clean session.
assert_reported 'a wrapper denial is POSTed too' 'rails "dbconsole"' \
  '"rule":"raw_database_session"'
assert_reported 'the wrapper reports post-expansion argv' 'rails "dbconsole"' \
  '"command":"rails dbconsole"'
# The identity gate is the denial CI hits, and "who tried to run what" is the
# whole content of that record.
cg_env 'CONSOLE_USER='
assert_reported 'an unidentified session still names the command' 'rails c' \
  '"rule":"identity_missing"'

# A permitted command is not a denial.
assert_not_reported 'a permitted command reports nothing' 'rails c'

# Nothing configured means nothing sent -- the state of every app before rollout
# reaches it.
: > "$CG_CURL_LOG"
cg_run 'bash'
assert_true 'no endpoint configured means no POST' test ! -s "$CG_CURL_LOG"

# The command is judged and recorded without the CLI's marker, so a CI denial
# record reads as the command the caller wrote.
assert_reported 'the --exit-code marker is not in the record' \
  "psql${CG_MARKER}" '"command":"psql"'

# A record has to survive JSON.parse in datadog-proxy, and the command string is
# operator-controlled: quotes, backslashes, newlines and control characters all
# have to be escaped or the whole record is unparseable.
cg_run_reporting $'psql "a\\"b\\\\c" \t\n z'
assert_true 'the record is valid JSON even with a hostile command' \
  perl -MJSON::PP -ne 'decode_json($1) if /^BODY (.*)$/' "$CG_CURL_LOG"

# ...and a JSON string has to be valid UTF-8, so a command carrying bytes that
# are not would cost the whole record -- rule, operator and dyno_id with it.
cg_run_reporting $'psql \xc3\xa9 \x8b \xff'
assert_true 'the record is valid JSON even with invalid UTF-8 in the command' \
  perl -MJSON::PP -ne 'decode_json($1) if /^BODY (.*)$/' "$CG_CURL_LOG"
assert_true 'the record is pure ASCII, whatever bytes went in' \
  perl -ne 'exit 1 if /[^\x00-\x7f]/' "$CG_CURL_LOG"
assert_reported 'a non-ASCII byte is recorded as U+FFFD' \
  $'psql \xc3\xa9' '"command":"psql \ufffd\ufffd"'
# The reason is operator-controlled too, and unlike the command it is not vetted
# by anything upstream. No space in the value: cg_env word-splits.
cg_env $'CONSOLE_REASON=caf\xc3\xa9-\x8b'
assert_reported 'and so is one in the reason' 'psql' \
  '"reason":"caf\ufffd\ufffd-\ufffd"'

# The endpoint URL carries the Basic credential. curl reports failures by quoting
# the URL, so its stderr must never reach the operator.
CG_REPORT_URL="https://reporter:${CG_REPORT_CRED}@example.invalid/fail-me"
cg_run_reporting 'bash'
if [[ "$CG_OUT" != *"$CG_REPORT_CRED"* && "$CG_OUT" == *"denial not recorded"* ]]; then
  _cg_report true 'a failed report says so without leaking the credential'
else
  _cg_report false 'a failed report says so without leaking the credential' \
    'expected a "denial not recorded" warning and no credential in it'
fi

# ============================================================ permit mode records
# Phase 1 exists to measure what enforcement would block. That is only measurable
# if the would-be denials are recorded.
cg_build permit-report CONSOLE_GUARD_DYNO_METADATA_FILE="$CG_TMP_ROOT/permit-report/dyno-metadata.json"
CG_REPORT_URL="https://reporter:${CG_REPORT_CRED}@example.invalid/webhooks/console_audit"
cg_env_sticky 'CONSOLE_BLOCK_ENFORCE=false'
assert_reported 'permit mode records the would-be denial' 'bash' '"enforced":false'
assert_reported 'permit mode records wrapper denials too' 'rails "dbconsole"' \
  '"enforced":false'
cg_run_reporting 'bash'
assert_true 'permit mode still permits the command' test -n "$CG_OUT"
cg_env_sticky

# ============================================================ compile
cg_section "bin/compile"
assert_false 'fails when BUILD_DIR is missing'    "$CG_ROOT/bin/compile"
assert_false 'fails when BUILD_DIR is unwritable' "$CG_ROOT/bin/compile" /proc/nonexistent/app
assert_true  'installs the profile script' test -f "$CG_APP/.profile.d/zzz_console_guard.sh"
assert_true  'installs the rails wrapper'   test -x "$CG_APP/.console-guard/bin/rails"
assert_true  'installs the rake wrapper'    test -x "$CG_APP/.console-guard/bin/rake"
assert_true  'installs the bundle wrapper'  test -x "$CG_APP/.console-guard/bin/bundle"
assert_true  'installs the denial reporter' test -f "$CG_APP/.console-guard/lib/denial_report.sh"
assert_true  'generated denial reporter is valid bash' \
  bash -n "$CG_APP/.console-guard/lib/denial_report.sh"
assert_true  'generated bundle wrapper is valid bash' \
  bash -n "$CG_APP/.console-guard/bin/bundle"
assert_false 'leaves no unsubstituted placeholders' \
  grep -rq '@@CG_' "$CG_APP/.profile.d" "$CG_APP/.console-guard"
assert_true  'generated profile script is valid bash' \
  bash -n "$CG_APP/.profile.d/zzz_console_guard.sh"
assert_true  'generated wrapper is valid bash' bash -n "$CG_APP/.console-guard/bin/rails"
assert_true  'build log records the guard version' grep -q 'Installing console guard' "$CG_BUILD_LOG"

cg_finish
