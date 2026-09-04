# frozen_string_literal: true

require_relative "helper"

# ConsoleGuard::Command -- all argument policy.
#
# These drive the wrapper with an argv directly, which is what it gets from the
# shell after expansion. That the *shell* delivers the expanded argv here --
# rather than the quoted, globbed or interpolated spelling the operator typed --
# is the property test/run_tests.sh exists to pin, and is not re-checked in
# every case below.
class CommandTest < GuardTest
  def test_permitted_commands_run
    assert_ran wrapper("rails", "c"), "rails c"
    assert_ran wrapper("rails", "console"), "rails console"
    assert_ran wrapper("rake", "some_task:some_action"), "rake some_task:some_action"
    assert_ran wrapper("rails", "runner", "Model.some_method"), "rails runner Model.some_method"
    assert_ran wrapper("rails", "db:migrate"), "rails db:migrate"
    assert_ran wrapper("rake", "db:migrate"), "rake db:migrate"
  end

  def test_quoted_inline_code_survives
    # The wrapper exists so that policy can be enforced without banning quotes:
    # by here the shell has already removed them.
    assert_ran wrapper("rails", "runner", "Model.some_method(1, 2)"),
      "rails runner Model.some_method(1, 2)"
  end

  def test_destructive_db_tasks_are_not_gated_here
    # This guard is about making sure what runs is logged, not about preventing
    # damage, and blocking these impedes on-call. They still reach an api:dyno
    # webhook, and the app is the right place for a task-level guard.
    assert_ran wrapper("rake", "db:drop"), "rake db:drop"
    assert_ran wrapper("rails", "db:migrate:reset"), "rails db:migrate:reset"
    assert_ran wrapper("rake", "db:rollback", "STEP=99"), "rake db:rollback STEP=99"
    assert_ran wrapper("rake", "db:seed")
  end

  # ---------------------------------------------------------------- bundle exec

  # Heroku rewrites `rake <task>` on a one-off dyno to `bundle exec rake <task>`
  # before the login shell runs, so `bundle` must be permitted or no rake task
  # works at all. `bundle exec` also unshifts Bundler's bin directory onto PATH,
  # which puts the real rails/rake ahead of the wrapper -- so the `bundle`
  # wrapper is the only place the argument rules can be applied.
  def test_bundle_exec_is_permitted
    assert_ran wrapper("bundle", "exec", "rake", "db:migrate"), "bundle exec rake db:migrate"
    assert_ran wrapper("bundle", "exec", "rails", "c"), "bundle exec rails c"
    assert_ran wrapper("bundle", "exec", "rails", "runner", "Model.some_method")
  end

  def test_bundle_does_not_admit_what_it_can_wrap
    assert_denied wrapper("bundle", "exec", "bash"), "not permitted"
    assert_denied wrapper("bundle", "exec", "sh", "-c", "id"), "not permitted"
    assert_denied wrapper("bundle", "exec", "irb"), "not permitted"
    assert_denied wrapper("bundle", "exec", "bin/rails", "c"), "unqualified"
  end

  def test_bundle_without_exec_is_refused
    assert_denied wrapper("bundle", "install"), "Ruby buildpack produces"
    assert_denied wrapper("bundle"), "Ruby buildpack produces"
    assert_denied wrapper("bundle", "exec"), "may be run under"
  end

  def test_every_rule_applies_through_bundle_too
    # This is now the only wrapper the command reaches, so a rule that is not
    # duplicated here is not enforced at all.
    assert_denied wrapper("bundle", "exec", "rails", "dbconsole"), "raw database session"
    assert_denied wrapper("bundle", "exec", "rails", "credentials:edit"), "editor"
    assert_denied wrapper("bundle", "exec", "rails", "runner", "-"), "stdin"
    assert_denied wrapper("bundle", "exec", "rails", "runner", "script.rb"), "exists on disk"
    assert_denied wrapper("bundle", "exec", "rake", "-c"), "flag is not permitted"
    assert_denied wrapper("bundle", "exec", "rake", "-e", "1"), "allowlisted"
    assert_denied wrapper("bundle", "exec", "rails", "c", "--sandbox"), "unlogged"
  end

  # ---------------------------------------------------------------- deny list

  def test_raw_database_sessions_are_refused
    # Drops to a raw psql session; no statement is seen by the Rails console hook.
    assert_denied wrapper("rails", "dbconsole"), "raw database session"
    assert_denied wrapper("rails", "db"), "raw database session"
  end

  def test_editor_escapes_are_refused
    # $EDITOR is operator-controlled, so these are a shell escape.
    assert_denied wrapper("rails", "credentials:edit"), "editor"
    assert_denied wrapper("rails", "credentials:show"), "editor"
    assert_denied wrapper("rails", "encrypted:edit", "config/x"), "editor"
  end

  def test_a_bare_dash_is_refused_in_any_position
    # `rails runner -` reads the program from stdin, so the executed code
    # appears neither in the dyno command string nor in an ARGV capture.
    assert_denied wrapper("rails", "runner", "-"), "stdin"
    assert_denied wrapper("rake", "some:task", "-"), "stdin"
  end

  def test_dash_c_is_refused_in_any_position
    # `-c` reaches a shell. `rails c` is unaffected: that argument is `c`.
    assert_denied wrapper("rails", "-c", "foo"), "flag is not permitted"
    assert_denied wrapper("rake", "some:task", "-c"), "flag is not permitted"
    assert_ran wrapper("rails", "c")
  end

  # ---------------------------------------------------------------- sandbox

  # A sandboxed console rolls back its transaction on exit, and a
  # database-backed ActiveJob queue on the primary database puts the audit
  # enqueue inside it -- so the rollback discards the audit trail and the
  # session runs entirely unlogged.
  def test_sandboxed_consoles_are_refused
    ["--sandbox", "-s"].each do |flag|
      ["console", "c"].each do |subcommand|
        assert_denied wrapper("rails", subcommand, flag), "unlogged"
      end
    end
  end

  def test_the_equals_spellings_are_refused_whatever_the_value
    # Thor takes `--flag=value` for a boolean, so these have to be denied by this
    # rule and not merely by the option allowlist -- otherwise adding a
    # sandbox-ish entry to the console's allowlist reopens the bypass with the
    # whole suite green. Deciding which values Thor reads as true is modelling
    # the parser, so `false` is denied too.
    ["--sandbox=true", "--sandbox=1", "--sandbox=false", "-s=true"].each do |flag|
      assert_denied wrapper("rails", "c", flag), "unlogged"
    end
  end

  def test_the_sandbox_denial_names_the_spelling_that_works
    assert_denied wrapper("rails", "c", "--sandbox=true"), "`--no-sandbox` is permitted"
  end

  def test_the_sandbox_rule_is_scoped_to_the_console
    # -s is rake's silent flag, and --no-sandbox is the safe direction. Neither
    # is collateral damage.
    assert_ran wrapper("rake", "-s", "some:task")
    assert_ran wrapper("rails", "c", "--no-sandbox")
  end

  # ---------------------------------------------------------------- runner file

  def test_runner_may_not_read_its_program_from_a_file
    assert_denied wrapper("rails", "runner", "--file=/app/script.rb"), "from a file"
    assert_denied wrapper("rails", "runner", "--file", "script.rb"), "from a file"
  end

  def test_a_runner_argument_that_exists_on_disk_is_refused
    # The same decision Rails itself makes, so there is no heuristic on how the
    # argument looks.
    assert_denied wrapper("rails", "runner", "script.rb"), "exists on disk"
    assert_denied wrapper("rails", "runner", "./script.rb"), "exists on disk"
    assert_denied wrapper("rails", "r", "payload.rb"), "exists on disk"
  end

  def test_a_device_or_fd_path_is_refused_too
    # Rails checks File.exist? and then Kernel.load, and loading /dev/stdin
    # reads the program from stdin -- the same gap the bare `-` rule closes.
    # Neither of these is a regular file, so File.file? would let them through.
    assert_denied wrapper("rails", "runner", "/dev/stdin"), "exists on disk"
    assert_denied wrapper("rails", "runner", "/dev/fd/0"), "exists on disk"
  end

  def test_inline_code_that_merely_looks_like_a_path_is_permitted
    assert_ran wrapper("rails", "runner", "Model.where(x: 1).rb")
    assert_ran wrapper("rails", "runner", "no_such_file.rb")
  end

  # ---------------------------------------------------------------- options

  # `rake -e/-p/-E CODE` evaluates CODE inside Rake's own option parser, before
  # the Rakefile is loaded and without booting Rails, and then exits. Nothing it
  # does reaches the console audit hook.
  def test_rake_code_evaluating_options_are_refused
    [["-e", "1"], ["--execute", "1"], ["-p", "1+1"], ["-E", "1"],
      ["--execute-print", "1"], ["--execute-continue", "1"], ["--execute=1"]].each do |args|
      assert_denied wrapper("rake", *args), "allowlisted"
    end
  end

  def test_short_options_are_matched_whole
    # Rake bundles short options, so a deny list would have to model which of
    # them take an argument in order to know where `-Ne` stops being flags. The
    # allowlist matches whole tokens instead, which refuses `-se` without
    # reasoning about bundling at all.
    assert_denied wrapper("rake", "-Ne", "1"), "allowlisted"
    assert_denied wrapper("rake", "-se", "1"), "allowlisted"
    assert_denied wrapper("rake", "-qsNe", "1"), "allowlisted"
    # ...which also means a bundle of two permitted flags is refused. Cheap.
    assert_denied wrapper("rake", "-sq", "some:task"), "matched whole"
  end

  def test_abbreviated_long_forms_are_refused
    # Rake accepts these; the allowlist does not.
    assert_denied wrapper("rake", "--exec", "1"), "allowlisted"
    assert_denied wrapper("rake", "--ex", "1"), "allowlisted"
    assert_denied wrapper("rake", "--task"), "allowlisted"
  end

  def test_options_that_name_a_path_are_refused
    [["-f", "Rakefile", "some:task"], ["-r", "./payload", "some:task"], ["-I", "/app", "some:task"],
      ["-R", "/app", "some:task"], ["-C", "/app", "some:task"], ["--require", "./payload"],
      ["--rakefile", "Rakefile"]].each do |args|
      assert_denied wrapper("rake", *args), "allowlisted"
    end
  end

  def test_options_that_change_which_rakefile_is_found_are_refused
    # `--system` loads tasks from $HOME/.rake, and $HOME is /app on a dyno. The
    # allowlist refuses these without anyone having had to think of them.
    [["-g", "some:task"], ["-G", "some:task"], ["-N", "some:task"], ["--system", "some:task"],
      ["--suppress-backtrace", "x"], ["--no-such-option"]].each do |args|
      assert_denied wrapper("rake", *args), "allowlisted"
    end
  end

  def test_rails_reaches_rakes_parser_too
    # Rails hands a command it does not recognise to that same parser, argv and
    # all, so the same options arrive by way of `rails`.
    assert_denied wrapper("rails", "-e", "1"), "allowlisted"
    assert_denied wrapper("rails", "db:migrate", "-e", "1"), "allowlisted"
  end

  def test_the_option_denial_is_self_service
    assert_denied wrapper("rake", "--no-such-option"), "--tasks"
    assert_denied wrapper("rake", "--no-such-option"), "`rake --no-such-option` is not permitted"
    assert_denied wrapper("rails", "db:migrate", "--no-such-option"),
      "Permitted after `rails db:migrate`"
  end

  def test_the_permitted_rake_options_still_work
    [["-T"], ["-T", "db"], ["-Tdb"], ["--tasks=db"], ["-D", "db"], ["-W", "some:task"], ["-P"],
      ["-s", "some:task"], ["-q", "some:task"], ["-n", "some:task"], ["-t", "some:task"],
      ["-v", "some:task"], ["-V"], ["-A", "-T"], ["-B", "some:task"], ["-m", "some:task"],
      ["-j", "4", "some:task"], ["-j4", "some:task"], ["-X", "some:task"], ["--trace", "some:task"],
      ["--trace=stderr", "some:task"], ["--backtrace", "some:task"], ["--dry-run", "some:task"],
      ["--all", "--tasks"], ["--comments", "--tasks"], ["--rules"], ["--job-stats", "some:task"],
      ["--silent", "some:task"], ["--version"]].each do |args|
      assert_ran wrapper("rake", *args)
    end
  end

  def test_task_names_and_assignments_are_not_options
    assert_ran wrapper("rake", "db:rollback", "STEP=99"), "rake db:rollback STEP=99"
    assert_ran wrapper("rake", "some:task[a,b]")
    assert_ran wrapper("rake", "-s", "db:migrate", "STEP=1")
  end

  # The two Rails commands parse their own options and never reach Rake, so `-e`
  # there is the environment -- but they get a list of their own rather than
  # being waved through, because a mistake in a list is a denial while a mistake
  # in an exemption is a silent bypass.
  def test_the_commands_rails_parses_itself_get_their_own_list
    assert_ran wrapper("rails", "runner", "-e", "production", "Model.foo")
    assert_ran wrapper("rails", "runner", "--environment", "production", "Model.foo")
    assert_ran wrapper("rails", "runner", "-w", "Model.foo")
    assert_ran wrapper("rails", "c", "-e", "production")
    assert_ran wrapper("rails", "console", "--environment", "production")
    assert_ran wrapper("bundle", "exec", "rails", "c", "-e", "production")
  end

  def test_options_neither_rails_command_takes_are_refused
    assert_denied wrapper("rails", "c", "--no-such-option"), "allowlisted"
    assert_denied wrapper("rails", "runner", "-f", "Model.foo"), "allowlisted"
    assert_denied wrapper("rails", "c", "-w"), "allowlisted"
    # `-s` reaches neither parser as anything useful. The rule that matters --
    # the sandbox denial is scoped to the console -- is pinned above.
    assert_denied wrapper("rails", "runner", "-s", "Model.foo"), "allowlisted"
  end

  # ---------------------------------------------------------------- enforcement

  def test_enforcement_defaults_to_blocking
    # Only the exact string `false` opts into dry-run mode, so a typo or an empty
    # value fails closed.
    ["0", "", "False", "true"].each do |value|
      assert_denied wrapper("rails", "dbconsole", env: {"CONSOLE_BLOCK_ENFORCE" => value})
    end
  end

  def test_permit_mode_warns_and_runs
    result = wrapper("rails", "dbconsole", env: {"CONSOLE_BLOCK_ENFORCE" => "false"})
    assert_ran result
    assert_includes result.output, "WILL BE BLOCKED"
  end

  def test_the_resolved_path_is_never_handed_to_a_shell
    # Ruby's `exec` picks its own dispatch: a single string is scanned for shell
    # metacharacters and falls back to `/bin/sh -c`. A permitted command with no
    # arguments is exactly that single-string case, and the path is assembled
    # from the operator-settable PATH -- so the array form in Command#run is
    # what stops a directory name from becoming a shell escape.
    result = wrapper("rails", env: {"PATH" => ConsoleGuardTest::HOSTILE_BIN})

    assert_ran result, "rails"
    refute_includes result.output, "PWNED"
  end

  def test_denials_name_the_guard_version
    # So an operator's report identifies the deployed guard exactly.
    assert_denied wrapper("rails", "dbconsole"), "console-guard "
  end
end
