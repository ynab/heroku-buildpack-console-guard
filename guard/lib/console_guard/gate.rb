# frozen_string_literal: true

module ConsoleGuard
  # The profile half of the guard: everything that can be decided before the
  # login shell has expanded the operator's command.
  #
  # It sees the dyno command only as a *string*, before quote removal, parameter
  # expansion and pathname expansion, so a policy expressed as a string
  # comparison here is comparing something other than what `rails` will actually
  # receive:
  #
  #   rails "dbconsole"          -> string has `"dbconsole"`, argv has `dbconsole`
  #   rails runner "$P"  (P=-)   -> string has `"$P"`,        argv has `-`
  #   rails runner *.r?          -> string has the glob,      argv has a filename
  #
  # So this half checks only what is sound to check on a raw string: which dyno
  # this is, whether the caller is identified, whether the command is free of
  # compound statements and redirections, and whether argv[0] is literally
  # `rails`, `rake` or `bundle`. Everything about the *arguments* is in
  # ConsoleGuard::Command, which runs after expansion.
  #
  # argv[0] is the one thing this half can check soundly, because quoting or
  # expanding it makes it stop matching the allowlist and so fails closed. That
  # is what guarantees control reaches the command wrapper.
  class Gate
    include Denials

    # The contract with profile/console_guard.sh. It can only act on an exit
    # status, so each distinct thing the login shell has to do to its own
    # environment gets a code of its own.
    #
    # Two independent things can apply to a dyno, and the code says which:
    #
    #   gated    the guard vets the command before it runs. This is what
    #            requires CONSOLE_USER and CONSOLE_REASON, applies the command
    #            and argument policy, and refuses the session.
    #   audited  CONSOLE_AUDIT_ENABLED is exported, so the console_audit gem
    #            inside the app records what the session does. It refuses
    #            nothing: it is the record, not the control.
    #
    # Gating implies auditing -- a vetted session is worth a record. Auditing
    # does not imply gating, and AUDITED below is that case.

    # Not a console at all: a long-running dyno (web, worker, or any other
    # app-defined process type). Nothing applies.
    NOT_APPLICABLE = 0

    # A one-off dyno whose command nobody typed: Heroku Scheduler and release
    # phase. Recorded, but not vetted, for two reasons.
    #
    # Gating asks "who are you and why", and there is nobody there to answer --
    # Scheduler and release commands run unattended, so requiring CONSOLE_USER
    # would refuse every scheduled job on the app rather than protecting
    # anything.
    #
    # And the command is not an operator's to choose. It is whatever the app's
    # Scheduler entry or Procfile release line says, which is changed by a
    # deploy or a dashboard edit -- a different access path, with its own
    # controls, and not one a console gate is in front of.
    #
    # What is left worth having is the record: a rake task run by Scheduler can
    # touch the same data a console can, so the gem still logs it.
    AUDITED = 10

    # An operator's `heroku run`, vetted and permitted.
    GATED = 20

    # As GATED, and the login shell must also supply a placeholder CONSOLE_USER.
    # Only reachable in permit mode; see require_identity for why it is needed
    # and why it is a status rather than something this process can do.
    GATED_ANONYMOUS = 21

    # Refused. The banner is printed, the record sent, and the CLI's
    # exit-status marker emitted, before this is returned.
    DENIED = 1

    # `heroku run --exit-code` appends
    #
    #   ; echo "<U+FFFF> heroku-command-exit-status: $?"
    #
    # to the dyno command and reads the resulting line off stdout to decide what
    # to exit with. It is the only way `heroku run` reports failure, so every CI
    # caller that can tell a broken migration from a good one uses it.
    #
    # That matters here twice over. The appended text makes the command a
    # compound statement, which the check below would otherwise reject; and a
    # denial exits during .profile.d, so the appended `echo` never runs, no
    # marker reaches stdout, and the CLI reports success for a command it never
    # ran.
    EXIT_SENTINEL = "\uFFFF"
    EXIT_MARKER = %(; echo "\uFFFF heroku-command-exit-status: $?").b

    SHELLS = %w[bash sh zsh dash].freeze
    # `-c`, and the combined short forms such as `-lc` that mean the same thing.
    COMBINED_DASH_C = /\A-[^-].*c\z/

    TRAILING_SPACE = /[ \t\n\r\f\v]+\z/n

    USAGE = 'heroku run -e "CONSOLE_USER=$(heroku whoami);CONSOLE_REASON=test" rails c -a app_name'

    def initialize(cmdline_path: ENV['CONSOLE_GUARD_CMDLINE'].to_s)
      @dyno = Dyno.resolve
      # Read up front: both the marker check and the command parsing need it, and
      # a denial needs the marker answer from the very first call site -- the
      # identity gate is the denial CI is most likely to hit.
      @argv = read_cmdline(cmdline_path)
      # True only when the caller passed --exit-code, so a plain `heroku run` is
      # not given a stray marker line it never asked for.
      @exit_marker_seen = @argv.any? { |arg| arg.end_with?(EXIT_MARKER) }
      @command, @command_read = extract_command
      @anonymous = false
    end

    def run
      refuse_spoofed_dyno if @dyno.spoofed?
      return NOT_APPLICABLE unless @dyno.audited?
      return AUDITED unless @dyno.gated?

      require_wrapper
      require_identity
      require_readable_command
      refuse_compound_statement
      check_command_allowlist
      warn_without_metadata

      @anonymous ? GATED_ANONYMOUS : GATED
    end

    # What this half judged: the pre-expansion command string, falling back to
    # the login shell's whole argv when there was no command to extract.
    def denial_command
      @command.empty? ? @argv.join(' ') : @command
    end

    def dyno_id
      @dyno.id
    end

    # Stand in for the `echo` the CLI appended, which exiting skips. On stdout,
    # because that is the stream the CLI parses -- the banner goes to stderr and
    # is invisible to it. Without this a denied CI job exits 0 and the pipeline
    # goes green.
    def before_exit
      return unless @exit_marker_seen

      $stdout.write("#{EXIT_SENTINEL} heroku-command-exit-status: 1\n")
      $stdout.flush
    end

    private

    # Heroku executes the one-off command through a login shell, which is the
    # process that sources the profile script, so its argv is
    # `bash -c <the dyno command>`.
    def read_cmdline(path)
      return [] if path.empty?

      raw = File.binread(path)
      parts = raw.split("\0".b, -1)
      parts.pop if raw.end_with?("\0".b)
      parts
    rescue StandardError
      []
    end

    def extract_command
      return [''.b, false] if @argv.empty?
      return [''.b, false] unless SHELLS.include?(File.basename(@argv[0]))

      (1...@argv.length).each do |index|
        arg = @argv[index]
        next unless arg == '-c' || COMBINED_DASH_C.match?(arg)

        return [strip_exit_marker(@argv[index + 1].to_s.b), true]
      end

      [''.b, false]
    end

    # Removed before anything vets or reports the command, so `heroku run
    # --exit-code rake foo` is judged -- and recorded -- as `rake foo` rather
    # than as the compound the CLI made of it.
    #
    # Exact literal, anchored to the end, removed at most once. A looser pattern
    # is a shell escape: `rails c ; bash # heroku-command-exit-status` would be
    # stripped back to `rails c` and permitted. Two markers leave one behind,
    # which the compound check then rejects.
    #
    # If Heroku changes the marker this stops matching and CI is denied again --
    # noisy, but the safe direction to fail in.
    def strip_exit_marker(command)
      candidate = command.sub(TRAILING_SPACE, '')
      return command unless candidate.end_with?(EXIT_MARKER)

      candidate[0, candidate.bytesize - EXIT_MARKER.bytesize].sub(TRAILING_SPACE, '')
    end

    def refuse_spoofed_dyno
      Banner.render(
        ["$DYNO (#{@dyno.claimed_name}) does not match this dyno's metadata",
         "(#{@dyno.metadata_name}). Refusing to run."],
        enforcing: true
      )
      # Recorded with the metadata's dyno id, not $DYNO's, so the record files
      # under the dyno this actually is.
      Reporter.report(rule: 'dyno_name_spoofed', command: "$DYNO=#{@dyno.claimed_name}",
                      enforced: true, dyno_id: @dyno.metadata_id)

      # Fatal in both enforcement modes. This is not a command-policy decision an
      # operator can be warned about; it is an attempt to change which dyno the
      # guard believes it is running on.
      exit DENIED
    end

    # All argument policy lives in the wrapper. If it is missing this half cannot
    # enforce anything meaningful, so refuse rather than run half a gate.
    def require_wrapper
      return if WRAPPER_NAMES.all? { |name| File.executable?(File.join(ConsoleGuard.wrapper_dir, name)) }

      deny 'wrapper_missing',
           'The console guard command wrapper is missing from this dyno.',
           '',
           "Expected: #{ConsoleGuard.wrapper_dir}/{rails,rake,bundle}",
           '',
           'This is a build problem, not an operator mistake. Redeploy the',
           'app; if it persists the buildpack is misconfigured.'
    end

    def require_identity
      # Name the one that is missing. "both are required" sends an operator
      # checking the variable that was already fine, and the usual cause -- a
      # failed `heroku whoami` substituting an empty string -- looks like neither
      # was set.
      missing = []
      missing << 'CONSOLE_USER' if ConsoleGuard.blank?(ENV['CONSOLE_USER'])
      missing << 'CONSOLE_REASON' if ConsoleGuard.blank?(ENV['CONSOLE_REASON'])

      unless missing.empty?
        described = if missing.length == 2
                      'CONSOLE_USER and CONSOLE_REASON are'
                    else
                      "#{missing.first} is"
                    end

        deny 'identity_missing',
             "#{described} not set.",
             '',
             'Both are required on one-off dynos. CONSOLE_USER must be your',
             '`heroku whoami` value, so that console records can be compared',
             "against Heroku's own audit trail.",
             '',
             'If you built CONSOLE_USER from `heroku whoami`, check that it',
             'succeeded -- an expired login makes it print an error and return',
             'an empty string, which arrives here as unset.',
             '',
             'Usage:',
             "  #{USAGE}"
      end

      # console1984 raises MissingUsername on an empty CONSOLE_USER
      # (ask_for_username_if_empty defaults to false), so leaving it empty kills
      # the console even in permit mode -- which is exactly the breakage permit
      # mode exists to avoid during phase 1. The profile script supplies a
      # placeholder instead; see GATED_ANONYMOUS.
      #
      # Only in permit mode. When enforcing, the denial above has already exited.
      @anonymous = true if !enforcing? && ConsoleGuard.blank?(ENV['CONSOLE_USER'])
    end

    # Positioned after the identity gate, so that a CI caller who is missing a
    # reason is told that rather than told the gate could not parse its command.
    def require_readable_command
      if @argv.empty?
        # Fail closed: if we cannot read the command, we cannot vet it.
        deny 'command_unreadable',
             'Could not read the dyno command.',
             '',
             '/proc/$$/cmdline is empty or unreadable, and the console gate',
             'cannot vet a command it cannot see, so the session is refused.',
             '',
             'This is a platform or build problem, not an operator mistake.'
      elsif !@command_read || ConsoleGuard.blank?(@command)
        # No `-c` payload means this is not the `bash -c <command>` shape the
        # gate is built on: the login shell was invoked some other way, or the
        # command arrives on stdin. There is no command string to vet, so refuse
        # -- and say so.
        @command_read = false
        deny 'command_not_bash_c',
             'Could not determine the dyno command.',
             '',
             "The gate expects this session's login shell to have been invoked",
             'as `bash -c <command>`. It was not, so there is no command',
             'string to vet and the session is refused.',
             '',
             'Login shell argv:',
             "  #{Banner.show(@argv.join(' '))}",
             '',
             'This is a platform or build problem, not an operator mistake.'
      end
    end

    # The allowlist below matches argv[0] only, so without this an operator could
    # append a second command -- eg `rails runner "1"; bash` -- and reach a
    # shell.
    #
    # Redirections are rejected for the same reason the wrapper rejects a bare
    # `-`: `rails c < /app/payload.rb` feeds a program in through stdin, so the
    # command string names a file rather than the code that runs.
    #
    # Best effort: `rails runner 'system("bash")'` contains none of these and
    # still shells out.
    COMPOUND = /[;&|`<>\n]|\$\(/n

    def refuse_compound_statement
      return unless @command_read
      return unless COMPOUND.match?(@command)

      deny 'compound_statement',
           'Compound statements and redirections are not permitted on one-off',
           'dynos.',
           '',
           'The command may not contain any of:  ;  &  |  `  $(  <  >  newline',
           '',
           'Command:',
           "  #{Banner.show(@command)}",
           '',
           'Run each command as its own `heroku run`.'
    end

    # Only `rails`, `rake` and `bundle` are permitted, because those are the only
    # paths that enter a Rails process where the console audit hook can observe
    # what runs. Everything else -- bash, sh, zsh, irb, ruby, node, python, psql,
    # pg_dump, pg_restore, pgcli, curl, wget, nc, ssh, scp, env, printenv, cat --
    # is blocked by falling through this allowlist.
    #
    # `bundle` is here because Heroku's Ruby buildpack rewrites `rake <task>` on
    # a one-off dyno to `bundle exec rake <task>` before this runs, so without it
    # no rake task works at all. It is admitted only as far as the wrapper: the
    # `bundle` wrapper permits `bundle exec rails|rake` and nothing else, so
    # `bundle exec bash` still dies -- on `bash`, one layer later.
    #
    # The name must be unqualified. `bin/rails` and `/app/bin/rails` are rejected
    # even though they are the same program, because naming a path bypasses the
    # PATH lookup that reaches the command wrapper, and the wrapper is where
    # argument policy is enforced. A leading `VAR=value` assignment is rejected
    # for the same reason: `PATH=/app/bin rails c` would take the wrapper out of
    # the picture.
    def check_command_allowlist
      return unless @command_read

      # Split on whitespace only. Nothing here is glob-expanded or re-quoted:
      # the first word is the whole question.
      first_word = @command.split(/[ \t\n]+/n).reject(&:empty?).first.to_s
      return if WRAPPER_NAMES.include?(first_word)

      deny 'command_not_allowed',
           'This command is not permitted on one-off dynos.',
           '',
           'Command:',
           "  #{Banner.show(@command)}",
           'Rejected because its first word is:',
           "  #{Banner.show(first_word)}",
           '',
           'Allowed:',
           '  rails <task>',
           '  rake <task>',
           '  bundle exec rails|rake <task>',
           '',
           'The name must be unqualified -- `rails`, not `bin/rails` --',
           'and may not be preceded by a VAR=value assignment.',
           '',
           'Example:',
           "  #{USAGE}"
    end

    # A configuration error on the app, not an operator mistake, so it warns
    # rather than blocks.
    def warn_without_metadata
      return if @dyno.correlatable?

      app = ENV['HEROKU_APP_NAME'].to_s
      app = 'app_name' if app.empty?

      $stderr.puts <<~WARNING

        WARNING: dyno metadata is not enabled on this app, so this session
                 cannot be correlated with Heroku's audit trail, and the gate
                 is relying on $DYNO, which an operator can set.
                 Enable it:
                   heroku labs:enable runtime-dyno-metadata -a #{app}

      WARNING
    end
  end
end
