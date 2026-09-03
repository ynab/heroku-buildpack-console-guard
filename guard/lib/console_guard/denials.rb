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
    def deny(rule, *lines)
      Banner.render(lines, enforcing: enforcing?)

      # Before the exit, and in dry-run mode too: phase 1 exists to measure what
      # enforcement would block, which is only measurable if the would-be
      # denials are recorded.
      Reporter.report(rule: rule, command: denial_command, enforced: enforcing?,
                      dyno_id: dyno_id)

      return unless enforcing?

      before_exit
      exit 1
    end

    def enforcing?
      ConsoleGuard.enforcing?
    end

    # Hook for anything a half must do on its way out. Only the profile half has
    # one; see ConsoleGuard::Gate.
    def before_exit; end
  end
end
