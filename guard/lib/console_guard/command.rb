# frozen_string_literal: true

module ConsoleGuard
  # The command-wrapper half of the guard. Reached as `rails`, `rake` or
  # `bundle` from a directory the profile script prepends to PATH.
  #
  # WHY THIS HALF EXISTS
  #
  # The profile half can only see the dyno command as a *string*, before the
  # shell has performed quote removal, parameter expansion and pathname
  # expansion. Any policy expressed as a string comparison there is therefore
  # comparing something other than what `rails` will actually receive. This half
  # runs after the shell has finished expanding, so its argv is exactly the argv
  # `rails` would have seen, and every deny-list rule lives here rather than
  # there.
  #
  # The division of labour is:
  #
  #   ConsoleGuard::Gate     ->  is this a gated dyno; is the caller identified;
  #                              is the command free of compound statements and
  #                              redirections; is argv[0] literally `rails`,
  #                              `rake` or `bundle`
  #   this class             ->  everything about the arguments
  class Command
    include Denials

    def initialize(program, argv)
      @program = program
      # Captured before `bundle exec` rewriting narrows what policy looks at, so
      # a denial record shows what was invoked.
      @argv = argv.map { |arg| arg.to_s.b }
      @dyno = Dyno.resolve
    end

    def run
      real = resolve_real
      refuse_without_real_binary unless real

      program, args = policy_target
      apply_policy(program, args)

      # The [command, argv0] form, so a path containing shell metacharacters can
      # never be handed to a shell.
      exec([real, real], *@argv)
    end

    # The post-expansion argv, which is what this half actually judged -- the
    # profile half's copy is the pre-expansion string, and the two differ in
    # exactly the cases this class exists for.
    def denial_command
      "#{@program} #{@argv.join(' ')}"
    end

    def dyno_id
      @dyno.id
    end

    private

    # PATH still contains this wrapper's directory, so a plain `exec rails` would
    # re-enter the wrapper. Walk PATH and take the first match that is not in it.
    #
    # Directories are compared resolved, so that a duplicate or symlinked PATH
    # entry pointing at the wrapper directory cannot send us back here.
    def resolve_real
      self_dir = realpath(ConsoleGuard.wrapper_dir)

      ENV['PATH'].to_s.split(File::PATH_SEPARATOR).each do |entry|
        entry = '.' if entry.empty?
        dir = realpath(entry)
        next if dir.nil? || dir == self_dir

        candidate = File.join(dir, @program)
        return candidate if File.executable?(candidate) && !File.directory?(candidate)
      end

      nil
    end

    def realpath(path)
      File.realpath(path)
    rescue StandardError
      nil
    end

    # Fail closed and loudly: silently doing nothing would look like a broken app
    # rather than a guard problem.
    def refuse_without_real_binary
      $stderr.puts <<~MESSAGE

        console-guard: could not find the real `#{@program}` on PATH.
                       PATH=#{ENV['PATH']}
                       This is a buildpack bug, not an operator mistake.

      MESSAGE
      exit 1
    end

    # Invoked as `bundle`, the interesting command is the one bundler will exec,
    # not bundler itself.
    #
    # Heroku's Ruby buildpack rewrites `rake <task>` on a one-off dyno to
    # `bundle exec rake <task>` before the login shell runs, so `bundle` has to
    # be on the allowlist for any rake task to work at all. It cannot simply be
    # waved through: `bundle exec` unshifts Bundler's own bin directory onto
    # PATH, so the rails/rake wrapper is NOT reached afterwards and this is the
    # only place the argument rules below can be applied.
    def policy_target
      return [@program, @argv] unless @program == 'bundle'

      unless @argv[0] == 'exec'
        deny 'bundle_not_exec',
             "`bundle #{@argv[0]}` is not permitted on one-off dynos.",
             '',
             'Only `bundle exec rails` and `bundle exec rake` are allowed,',
             "because those are the forms Heroku's Ruby buildpack produces for",
             'a permitted command.'
      end

      program = @program
      # Unqualified, for the same reason the profile half requires it of the
      # command itself: a path names a program this wrapper has not vetted.
      case @argv[1]
      when 'rails', 'rake'
        program = @argv[1]
      else
        deny 'bundle_exec_not_allowed',
             "`bundle exec #{@argv[1]}` is not permitted on one-off dynos.",
             '',
             'Only `rails` and `rake` may be run under `bundle exec`,',
             'and the name must be unqualified.'
      end

      [program, @argv.drop(2)]
    end

    def apply_policy(program, args)
      subcommand = args[0].to_s

      refuse_raw_database_session(program, subcommand)
      refuse_editor_escape(program, subcommand)
      refuse_unloggable_arguments(args)
      refuse_sandboxed_console(program, subcommand, args)
      refuse_runner_file(program, subcommand, args)
      check_option_allowlist(program, subcommand, args)
    end

    # `rails dbconsole` / `rails db` drop to a raw psql session; no statement is
    # ever seen by the console audit hook.
    def refuse_raw_database_session(program, subcommand)
      return unless %w[dbconsole db].include?(subcommand)

      deny 'raw_database_session',
           "`#{program} #{subcommand}` is not permitted on one-off dynos.",
           '',
           'It opens a raw database session, so no statement reaches the',
           'console audit hook.'
    end

    # `rails credentials:edit` and `rails encrypted:edit` spawn $EDITOR, which is
    # operator-controlled (`heroku run -e EDITOR=bash`) and therefore a shell.
    # The profile script also unsets EDITOR and VISUAL; this is the second layer.
    def refuse_editor_escape(program, subcommand)
      return unless subcommand.start_with?('credentials:', 'encrypted:')

      deny 'editor_escape',
           "`#{program} #{subcommand}` is not permitted on one-off dynos.",
           '',
           'These commands spawn an editor, which is a shell escape.'
    end

    def refuse_unloggable_arguments(args)
      args.each do |arg|
        # A bare `-` makes `rails runner` read the program from stdin, so the
        # code that runs appears in no log at all -- not the dyno command string,
        # not the api:dyno webhook, not an in-app ARGV capture.
        if arg == '-'
          deny 'stdin_program',
               'Reading the program from stdin is not permitted.',
               '',
               'A bare `-` argument means the executed code never appears in',
               'any audit record. Pass the code inline instead.'
        end

        # `-c` would reach a shell (`bash -c`, `sh -c`). No legitimate rails/rake
        # invocation uses it. `rails c` -- the console shorthand -- is
        # unaffected, because that argument is `c`, not `-c`.
        next unless arg == '-c'

        deny 'dash_c_flag',
             'The `-c` flag is not permitted on one-off dynos.',
             '',
             'Use `rails c` for a console.'
      end
    end

    # `rails console --sandbox` wraps the whole session in a transaction that is
    # rolled back on exit. The audit records are enqueued through ActiveJob, and
    # a database-backed queue on the primary database (eg Solid Queue) puts that
    # enqueue inside the same transaction -- so the rollback discards the audit
    # trail along with the operator's changes, leaving an interactive console
    # with no record of a single statement.
    #
    # Scoped to `console`/`c` rather than applied to every argv, because `-s` is
    # `rake`'s silent flag and legitimate there. `--no-sandbox` must keep
    # working.
    #
    # Thor parses `--sandbox=true` as well as the bare flag, so the `=` forms are
    # denied whatever value they carry. Enumerating Thor's boolean vocabulary
    # would be modelling the parser, which is the thing the option allowlist
    # below exists to avoid; `--no-sandbox` is the spelling that opts out.
    #
    # The console_audit gem sets Rails' own `config.disable_sandbox = true` when
    # auditing is active, which is a second layer over the same dynos: it holds
    # even if the command never reaches this wrapper.
    def refuse_sandboxed_console(program, subcommand, args)
      return unless program == 'rails' && %w[console c].include?(subcommand)

      args.drop(1).each do |arg|
        next unless arg == '--sandbox' || arg == '-s' ||
                    arg.start_with?('--sandbox=', '-s=')

        deny 'sandbox_console',
             "`rails #{subcommand} #{arg}` is not permitted on one-off dynos.",
             '',
             'A sandboxed console rolls back its transaction on exit, which',
             'discards the queued audit records with it -- the session would',
             'run entirely unlogged.',
             '',
             "Use `rails #{subcommand}` instead. It is audited.",
             '`--no-sandbox` is permitted and means the same thing.'
      end
    end

    # `rails runner` reading its program from a file has the same shape as
    # reading from stdin: the command string names a path rather than the code
    # that runs.
    #
    # Rails decides file-vs-inline-code by whether the path exists on disk. We
    # are past expansion here, so we can apply that same test rather than
    # guessing from how the argument looks.
    def refuse_runner_file(program, subcommand, args)
      return unless program == 'rails' && %w[runner r].include?(subcommand)

      args.drop(1).each do |arg|
        if arg == '--file' || arg.start_with?('--file=')
          deny 'runner_file',
               '`rails runner` may not read its program from a file.',
               '',
               'Pass the code inline instead.'
        end

        next unless file?(arg)

        deny 'runner_file',
             '`rails runner` may not read its program from a file.',
             '',
             "`#{arg}` exists on disk, so Rails would execute the",
             'file rather than the argument. The command string would then',
             'name a path rather than the code that runs, and the executed',
             'code would never be audited.',
             '',
             'Pass the code inline instead.'
      end
    end

    def file?(path)
      File.file?(path)
    rescue StandardError
      false
    end

    # ---------- option allowlist ----------
    # `rake -e/-p/-E CODE` evaluates CODE inside Rake's own option parser --
    # before the Rakefile is loaded and without booting Rails -- and then exits.
    # Nothing the code does reaches the console audit hook, so it is weaker even
    # than the `rails runner 'system("bash")'` case the README accepts as best
    # effort, where Rails at least boots and the invocation is recorded.
    # `-f/-r/-I/-R/-C/-g` name a path rather than the code that runs, which is
    # what blocks a bare `-` above.
    #
    # Rails hands any command it does not recognise to that same parser with the
    # whole argv, so `rails -e CODE` and `rails db:migrate -e CODE` reach it too.
    #
    # Allowlisted rather than screened. A deny list has to model which of Rake's
    # short options take an argument, in order to know where a bundle such as
    # `-Ne` stops being flags -- get that wrong for one option, in this version
    # of Rake or a later one, and the bundle hides an `-e`. An allowlist fails
    # the other way: an option nobody listed is refused, so the cost of being
    # wrong is a denial rather than an unlogged shell.
    #
    # Every command gets a list; none is exempt. The two Rails commands below
    # parse their own options and never reach Rake, so `-e` there is the
    # environment -- but they are given a list of their own rather than being
    # waved through, because a mistake in a list is a denial while a mistake in
    # an exemption is a bypass, silently and with no failing test.
    #
    # exact  options taking no value: the token must match exactly, so `-se` is
    #        refused rather than read as a bundle
    # value  options taking one: exactly, or with the value attached
    #        (`-T db`, `-Tdb`, `--tasks=db`)
    RAILS_PARSED_WHY = [
      'Options are allowlisted here, so one nobody vetted is refused',
      'rather than passed through to Rails.'
    ].freeze

    CONSOLE_OPTIONS = {
      exact: %w[--no-sandbox -h --help],
      value: %w[-e --environment],
      why: RAILS_PARSED_WHY,
      extras: ''
    }.freeze

    RUNNER_OPTIONS = {
      exact: %w[-w --skip-executor -h --help],
      value: %w[-e --environment],
      why: [
        'Options are allowlisted here, so one nobody vetted is refused',
        'rather than passed through to Rails. The code to run is not an',
        'option and needs no entry.'
      ].freeze,
      extras: ''
    }.freeze

    # Rake's read-only and output-shaping options. Absent, deliberately:
    # -e/-E/-p (evaluate code), -f/-r/-I/-R/-C (name a path), and -g/-G/-N,
    # which change which Rakefile is found -- `--system` loads tasks from
    # $HOME/.rake, and $HOME is /app on a dyno.
    RAKE_OPTIONS = {
      exact: %w[-A -B -m -n -P -q -s -t -v -V -X -h -H
                --all --build-all --multitask --dry-run --prereqs
                --quiet --silent --verbose --version --comments --rules
                --no-deprecation-warnings --help],
      value: %w[-T -D -W -j
                --tasks --describe --where --jobs --trace --backtrace
                --job-stats],
      why: [
        'Options are allowlisted here. Rake evaluates `-e/-p/-E CODE` in',
        'its own option parser, before the Rakefile is loaded and without',
        'booting Rails, so nothing that code does reaches the console audit',
        'hook -- and Rails hands any command it does not recognise to that',
        'same parser. Options naming a path are excluded for the reason a',
        'bare `-` is.'
      ].freeze,
      extras: 'task names, VAR=value assignments, and:'
    }.freeze

    OPTIONS = {
      %w[rails console] => CONSOLE_OPTIONS,
      %w[rails c] => CONSOLE_OPTIONS,
      %w[rails runner] => RUNNER_OPTIONS,
      %w[rails r] => RUNNER_OPTIONS
    }.freeze

    # The width the permitted set is wrapped to for the denial banner.
    WRAP_AT = 58

    def check_option_allowlist(program, subcommand, args)
      allowed = OPTIONS.fetch([program, subcommand], RAKE_OPTIONS)

      args.each do |arg|
        # A bare `-` is handled above, with a message about stdin that says more
        # than this one would.
        next if arg == '-'
        next unless arg.start_with?('-')
        next if permitted?(arg, allowed)

        # Only when it names a command; for `rake -e 1` the "subcommand" is the
        # rejected option itself.
        context = program.dup
        context << " #{subcommand}" if !subcommand.empty? && !subcommand.start_with?('-')

        extras = allowed[:extras].empty? ? '' : " #{allowed[:extras]}"

        deny 'option_not_allowed',
             "`#{program} #{arg}` is not permitted on one-off dynos.",
             '',
             *allowed[:why],
             '',
             "Permitted after `#{context}`:#{extras}",
             *wrap_allowed(allowed),
             '',
             'Short options are matched whole, so pass them separately rather',
             'than bundled into one argument.'
      end
    end

    def permitted?(token, allowed)
      return true if allowed[:exact].include?(token)

      allowed[:value].any? do |name|
        next true if token == name

        if name.start_with?('--')
          token.start_with?("#{name}=")
        else
          token.start_with?(name) && token.bytesize > name.bytesize
        end
      end
    end

    # Wrap the permitted set for the denial banner. Derived from the lists above
    # rather than written out again, so the two cannot drift apart.
    def wrap_allowed(allowed)
      lines = []
      line = +''

      (allowed[:value] + allowed[:exact]).each do |word|
        if line.length + word.length + 1 > WRAP_AT
          lines << "  #{line}"
          line = +word
        else
          line << ' ' unless line.empty?
          line << word
        end
      end
      lines << "  #{line}" unless line.empty?

      lines
    end
  end
end
