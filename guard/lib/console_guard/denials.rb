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
    # `command` and `dyno_id` override what the record says, for a refusal about
    # something other than the command this half judged.
    def deny(rule, *lines, command: denial_command, dyno_id: self.dyno_id)
      Banner.render(lines)
      Reporter.report(rule: rule, command: command, dyno_id: dyno_id)
      before_exit
      exit 1
    end

    # Hook for anything a half must do on its way out. Only the profile half has
    # one; see ConsoleGuard::Gate.
    def before_exit
    end
  end
end
