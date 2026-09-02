# frozen_string_literal: true

# Entry point for the command-wrapper half of the guard. Run by
# .console-guard/bin/{rails,rake,bundle}, which passes the name it was invoked
# under as the first argument -- $0 is what distinguishes the three, and it is
# lost once the interpreter takes over.
#
# No shebang, for the reason given in run_gate.rb.

require_relative '../lib/console_guard'

ConsoleGuard::Command.new(ARGV.shift.to_s, ARGV).run
