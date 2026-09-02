# frozen_string_literal: true

# Entry point for the profile half of the guard. Run by
# .profile.d/zzz_console_guard.sh, which acts on the exit status; see
# ConsoleGuard::Gate for what each code means.
#
# No shebang: it is always invoked as `<ruby> --disable=gems,rubyopt <this file>`
# so that the interpreter and its flags are chosen by the caller rather than by
# a PATH lookup an operator can influence.

require_relative '../lib/console_guard'

exit ConsoleGuard::Gate.new.run
