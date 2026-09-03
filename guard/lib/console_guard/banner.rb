# frozen_string_literal: true

module ConsoleGuard
  # The denial banner an operator sees on their terminal.
  module Banner
    RULE = "=" * 42

    # Lines may carry the operator's own command, which need not be valid UTF-8,
    # so they are written rather than interpolated into one string.
    def self.render(lines, enforcing:, io: $stderr)
      io.write("\n", RULE, "\n")
      lines.each { |line| io.write("  ", line.to_s, "\n") }
      unless enforcing
        io.write("\n")
        io.write("  CONSOLE_BLOCK_ENFORCE=false -- dry-run mode, permitting anyway.\n")
        io.write("  This command WILL BE BLOCKED once enforcement is enabled.\n")
      end
      io.write("  console-guard ", VERSION, "\n")
      io.write(RULE, "\n\n")
      io.flush
    end

    # Denials echo the command back. Without it a denial cannot be diagnosed from
    # the operator's side -- "this command is not permitted" says nothing about
    # which part of the string the gate objected to, or whether it even parsed
    # the string the operator typed.
    SHOW_MAX = 300

    def self.show(text)
      bytes = text.to_s.b
      return bytes if bytes.bytesize <= SHOW_MAX

      "#{bytes[0, SHOW_MAX]} [truncated]"
    end
  end
end
