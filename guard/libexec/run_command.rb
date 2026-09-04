# frozen_string_literal: true

# Entry point for the command-wrapper half of the guard. Judges the *expanded*
# argv and then, if it passes, `exec`s the real rails/rake/bundle -- so this
# process goes on to be the operator's command. It does not hand a verdict back
# to anyone: a denial exits non-zero from here, which is the command failing.
#
# The other half, run_gate.rb, decides and returns rather than executing.
#
# Run by .console-guard/bin/{rails,rake,bundle}, which passes the name it was
# invoked under as the first argument -- that is what distinguishes the three,
# and $0 stops carrying it once the interpreter takes over.
#
# No shebang, for the reason given in run_gate.rb.

require_relative "../lib/console_guard"

ConsoleGuard::Command.new(ARGV.shift.to_s, ARGV).run
