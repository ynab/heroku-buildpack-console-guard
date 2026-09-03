# frozen_string_literal: true

require_relative 'helper'

# ConsoleGuard::Gate -- the profile half.
#
# The gate reports back through its exit status, because that is the only
# channel a child process has to a parent that must then modify its own
# environment. What the login shell *does* with each status is
# test/run_tests.sh's subject; what produces each status is this one's.
class GateTest < GuardTest
  NOT_APPLICABLE = 0
  DENIED = 1
  AUDITED = 10
  GATED = 20
  GATED_ANONYMOUS = 21

  def test_a_permitted_command_gates_the_dyno
    assert_equal GATED, gate('rails c').status
    assert_equal GATED, gate('rake db:migrate').status
    assert_equal GATED, gate('bundle exec rake db:migrate').status
  end

  # ---------------------------------------------------------------- identity

  def test_both_variables_are_required
    assert_denied gate('rails c', env: { 'CONSOLE_USER' => '' }), 'CONSOLE_USER is not set'
    assert_denied gate('rails c', env: { 'CONSOLE_REASON' => '' }), 'CONSOLE_REASON is not set'
  end

  def test_a_whitespace_only_value_counts_as_unset
    assert_denied gate('rails c', env: { 'CONSOLE_USER' => '   ' }), 'CONSOLE_USER is not set'
    assert_denied gate('rails c', env: { 'CONSOLE_REASON' => "\t " }), 'CONSOLE_REASON is not set'
  end

  def test_the_denial_names_only_the_missing_variable
    # "both are required" sends an operator checking the variable that was
    # already fine, and the usual cause -- a failed `heroku whoami` substituting
    # an empty string -- looks like neither was set.
    result = gate('rails c', env: { 'CONSOLE_USER' => '' })
    refute_includes result.output, 'CONSOLE_REASON is not set'

    both = gate('rails c', env: { 'CONSOLE_USER' => '', 'CONSOLE_REASON' => '' })
    assert_includes both.output, 'CONSOLE_USER and CONSOLE_REASON are not set'
  end

  # ---------------------------------------------------------------- allowlist

  def test_only_rails_rake_and_bundle_are_permitted
    %w[bash sh irb psql printenv].each do |command|
      assert_denied gate(command), 'not permitted'
    end
    assert_denied gate('ruby -e 1'), 'not permitted'
    assert_denied gate('curl https://example.com'), 'not permitted'
  end

  def test_the_name_must_be_unqualified
    # Naming a path skips the PATH lookup that reaches the command wrapper, and
    # the wrapper is where argument policy is enforced.
    ['bin/rails c', './bin/rails c', '/app/bin/rails c'].each do |command|
      assert_denied gate(command), 'must be unqualified'
    end
  end

  def test_a_leading_assignment_is_refused
    # `PATH=/app/bin rails c` would take the wrapper out of the picture.
    assert_denied gate('FOO=1 rails c'), 'must be unqualified'
    assert_denied gate('PATH=/usr/bin rails c'), 'must be unqualified'
  end

  def test_the_denial_echoes_what_was_parsed
    # An operator's screenshot is then enough to tell whether the gate objected
    # to the command that was typed or to something else.
    assert_denied gate('/app/bin/rails c'), '/app/bin/rails c'
    assert_denied gate('bundle exec rails c; bash'), 'bundle exec rails c; bash'
  end

  # ---------------------------------------------------------------- compounds

  def test_compound_statements_and_redirections_are_refused
    ['rails runner "1"; bash', 'rails c && bash', 'rails c | tee /tmp/x',
     'rails runner `whoami`', 'rails runner $(whoami)',
     "rails runner Model.foo\nbash"].each do |command|
      assert_denied gate(command), 'Compound'
    end
  end

  def test_redirections_are_refused
    # Same reason the wrapper rejects a bare `-`: the command string names a
    # file rather than the code that runs.
    ['rails c < /app/script.rb', 'rake some:task <<< "x"',
     'rails runner Model.foo > /tmp/o', 'rails runner Model.foo 2>/tmp/o'].each do |command|
      assert_denied gate(command), 'redirections'
    end
  end

  # ---------------------------------------------------------------- exit marker

  # `heroku run --exit-code` appends this and reads the line it produces off
  # stdout. Without special handling every CI caller is denied as a compound
  # statement, and every denial exits 0 because the appended echo never runs.
  SENTINEL = "\uFFFF"
  MARKER = %(; echo "#{SENTINEL} heroku-command-exit-status: $?")

  def test_the_marker_is_stripped_before_the_command_is_vetted
    assert_equal GATED, gate("rake db:version#{MARKER}").status
    assert_equal GATED, gate("rails runner 1#{MARKER}").status
    assert_equal GATED, gate("bundle exec rake db:version#{MARKER}").status
  end

  def test_what_precedes_the_marker_is_still_vetted_in_full
    assert_denied gate("psql#{MARKER}"), 'not permitted'
    assert_denied gate("rails c ; bash#{MARKER}"), 'Compound'
  end

  def test_the_marker_is_stripped_at_most_once
    assert_denied gate("rails c#{MARKER}#{MARKER}"), 'Compound'
  end

  def test_the_match_is_an_exact_literal
    # A loose rule such as s/;.*exit-status.*$// strips these back to `rails c`
    # and lets a shell out.
    assert_denied gate('rails c ; bash # heroku-command-exit-status'), 'Compound'
    assert_denied gate('rails c ; bash ; echo "heroku-command-exit-status: $?"'), 'Compound'
  end

  def test_a_denial_emits_a_failing_marker_when_exit_code_was_used
    # On stdout, because that is the stream the CLI parses. Without this a
    # denied CI job exits 0 and the pipeline goes green.
    result = gate("psql#{MARKER}")
    assert_includes result.stdout, "#{SENTINEL} heroku-command-exit-status: 1".b
  end

  def test_the_identity_gate_emits_it_too
    # The denial CI is likeliest to hit.
    result = gate("rake db:version#{MARKER}", env: { 'CONSOLE_USER' => '' })
    assert_includes result.stdout, "#{SENTINEL} heroku-command-exit-status: 1".b
  end

  def test_no_marker_is_invented_for_a_caller_that_never_asked
    refute_includes gate('psql').stdout, 'heroku-command-exit-status'
  end

  # ---------------------------------------------------------------- unreadable

  def test_a_login_shell_with_no_dash_c_payload_is_refused
    # Not the allowlist denial: there is no command string here, and reporting
    # one invented from the whole argv sends the operator hunting for a command
    # they never typed.
    result = gate(argv: %w[bash -l])
    assert_denied result, 'Could not determine the dyno command'
    assert_includes result.output, 'Login shell argv:'
    refute_includes result.output, 'not permitted on one-off dynos'
  end

  def test_an_empty_argv_is_refused
    assert_denied gate(argv: []), 'Could not read the dyno command'
  end

  def test_combined_short_forms_are_understood
    # `bash -lc <command>` means the same thing to the shell as `bash -c`.
    assert_equal GATED, gate(argv: ['bash', '-lc', 'rails c']).status
    assert_denied gate(argv: ['bash', '-lc', 'psql']), 'not permitted'
  end

  # ---------------------------------------------------------------- wrapper

  def test_a_missing_wrapper_refuses_the_session
    # All argument policy lives in the wrapper. Without it the gate cannot
    # enforce anything meaningful, so it refuses rather than running half a gate.
    %w[rails bundle].each do |name|
      path = File.join(ConsoleGuardTest::APP, '.console-guard/bin', name)
      File.rename(path, "#{path}.bak")
      begin
        assert_denied gate('rails c'), 'command wrapper is missing'
      ensure
        File.rename("#{path}.bak", path)
      end
    end

    assert_equal GATED, gate('rails c').status
  end

  # ---------------------------------------------------------------- dyno family

  def test_scheduler_and_release_dynos_are_audited_but_not_gated
    # There is no interactive operator to supply a user or a reason, and the
    # command comes from app configuration.
    write_metadata('dyno' => { 'id' => 'x', 'name' => 'scheduler.9' })
    assert_equal AUDITED, gate('psql', env: { 'DYNO' => 'scheduler.9' }).status

    write_metadata('dyno' => { 'id' => 'x', 'name' => 'release.9' })
    assert_equal AUDITED, gate('psql', env: { 'DYNO' => 'release.9' }).status
  end

  def test_long_running_dynos_are_left_alone
    %w[web.1 worker.1 clock.1].each do |name|
      write_metadata('dyno' => { 'id' => 'x', 'name' => name })
      assert_equal NOT_APPLICABLE, gate('psql', env: { 'DYNO' => name }).status
    end
  end

  def test_an_absent_dyno_name_is_treated_as_a_one_off_dyno
    # Rather than letting a command through ungated.
    write_metadata('not json at all')
    assert_denied gate('bash', env: { 'DYNO' => '' }), 'not permitted'
  end

  # ---------------------------------------------------------------- metadata

  def test_dyno_metadata_beats_a_spoofed_dyno_variable
    # `heroku run -e DYNO=web.1` would otherwise let an operator skip the gate.
    # The metadata file is written inside the dyno and `-e` cannot touch it.
    assert_denied gate('bash', env: { 'DYNO' => 'web.1' }), 'does not match this dyno'
    assert_denied gate('rails c', env: { 'DYNO' => 'web.1' }), 'does not match this dyno'
    assert_denied gate('bash', env: { 'DYNO' => 'run.9999' }), 'does not match this dyno'
  end

  def test_a_spoofed_dyno_name_is_fatal_in_permit_mode_too
    # Not a command-policy decision an operator can be warned about; it is an
    # attempt to change which dyno the guard believes it is running on.
    assert_denied gate('bash', env: { 'DYNO' => 'web.1', 'CONSOLE_BLOCK_ENFORCE' => 'false' }),
                  'does not match this dyno'
  end

  def test_the_dyno_object_is_addressed_rather_than_searched
    # The real file carries three objects, each with its own name and id, and
    # app.name is empty. A greedy parser reads that instead of dyno.name and
    # silently falls back to trusting $DYNO.
    write_metadata('{"dyno":{"id":"de7c25da-uuid","name":"run.1234"},' \
                   '"app":{"id":"0d276459-uuid","name":""},' \
                   '"release":{"id":117,"commit":"9eb6f0d7"}}')
    assert_equal GATED, gate('rails c').status
    assert_denied gate('rails c', env: { 'DYNO' => 'web.1' }), 'does not match this dyno'
  end

  def test_unparseable_metadata_degrades_to_the_dyno_fallback
    write_metadata('not json at all')
    assert_equal GATED, gate('rails c').status
    assert_includes gate('rails c').output, 'dyno metadata is not enabled'
  end

  def test_no_warning_when_metadata_is_present
    refute_includes gate('rails c').output, 'dyno metadata is not enabled'
  end

  # ---------------------------------------------------------------- dry-run mode

  def test_permit_mode_warns_and_permits
    result = gate('bash', env: { 'CONSOLE_BLOCK_ENFORCE' => 'false' })
    assert_equal GATED, result.status
    assert_includes result.output, 'WILL BE BLOCKED'
  end

  def test_permit_mode_asks_for_a_placeholder_operator
    # console1984 raises MissingUsername on an empty CONSOLE_USER, so leaving it
    # empty kills the console even in dry-run mode -- exactly the breakage permit
    # mode exists to avoid. The distinct status is how the login shell is told.
    result = gate('rails c', env: { 'CONSOLE_USER' => '', 'CONSOLE_BLOCK_ENFORCE' => 'false' })
    assert_equal GATED_ANONYMOUS, result.status

    whitespace = gate('rails c', env: { 'CONSOLE_USER' => '   ', 'CONSOLE_BLOCK_ENFORCE' => 'false' })
    assert_equal GATED_ANONYMOUS, whitespace.status
  end

  def test_a_supplied_identity_needs_no_placeholder
    assert_equal GATED, gate('rails c', env: { 'CONSOLE_BLOCK_ENFORCE' => 'false' }).status
  end

  def test_enforcement_defaults_to_blocking
    ['0', '', 'False', 'true'].each do |value|
      assert_denied gate('bash', env: { 'CONSOLE_BLOCK_ENFORCE' => value })
    end
  end
end
