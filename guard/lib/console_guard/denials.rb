# frozen_string_literal: true

module ConsoleGuard
  # How both halves of the guard refuse a command.
  #
  # Including classes supply `denial_command` -- what that half actually judged,
  # which differs between them and is the point of the split -- and `dyno_id`.
  module Denials
    # <rule> is a short stable identifier for the check that refused. It is what
    # a monitor groups by, because denial messages get reworded and rule names
    # do not.
    #
    # `fatal` refuses in dry-run mode too, for a refusal that is not a
    # command-policy decision an operator could usefully be warned about.
    # `command` and `dyno_id` override what the record says, for a refusal about
    # something other than the command this half judged.
    def deny(rule, *lines, fatal: false, command: denial_command, dyno_id: self.dyno_id)
      enforced = enforcing? || fatal

      Banner.render(lines, enforcing: enforced)

      # Before the exit, and in dry-run mode too: phase 1 exists to measure what
      # enforcement would block, which is only measurable if the would-be
      # denials are recorded.
      Reporter.report(rule: rule, command: command, enforced: enforced,
        dyno_id: dyno_id)

      return unless enforced

      before_exit
      exit 1
    end

    def enforcing?
      ConsoleGuard.enforcing?
    end

    # Hook for anything a half must do on its way out. Only the profile half has
    # one; see ConsoleGuard::Gate.
    def before_exit
    end
  end
end
