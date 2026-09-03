# frozen_string_literal: true

# Entry point for the profile half of the guard. Judges the dyno command
# *before* the shell has expanded it, and runs nothing: it returns a verdict as
# an exit status, and .profile.d/zzz_console_guard.sh acts on it. See
# ConsoleGuard::Gate for what each code means.
#
# The other half, run_command.rb, does execute the command.
#
# No shebang: it is always invoked as `<ruby> --disable=gems,rubyopt <this file>`
# so that the interpreter and its flags are chosen by the caller rather than by
# a PATH lookup an operator can influence.

require_relative '../lib/console_guard'

exit ConsoleGuard::Gate.new.run
