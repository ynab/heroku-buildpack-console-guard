# frozen_string_literal: true

module ConsoleGuard
  # Substituted by bin/compile at build time. Every build-time value the guard
  # needs is here, so there is one file to check for an unsubstituted
  # placeholder.
  VERSION = "@@CG_VERSION@@"
  DYNO_METADATA_FILE = "@@CG_DYNO_METADATA_FILE@@"

  # The command wrapper is installed under all three names. `bundle` is one of
  # them because Heroku's Ruby buildpack rewrites `rake <task>` on a one-off
  # dyno to `bundle exec rake <task>`.
  WRAPPER_NAMES = ["rails", "rake", "bundle"].freeze

  # Only the exact string opts into dry-run mode, so a typo or an empty value
  # fails closed.
  def self.enforcing?
    ENV["CONSOLE_BLOCK_ENFORCE"] != "false"
  end

  def self.home
    home = ENV["HOME"].to_s
    home.empty? ? "/app" : home
  end

  def self.root
    File.join(home, ".console-guard")
  end

  # Prepended to PATH by the profile script, which is what guarantees a
  # permitted command reaches the wrapper.
  def self.wrapper_dir
    File.join(root, "bin")
  end

  # A value that is entirely whitespace is treated the same as an unset one.
  # Compared as bytes: CONSOLE_REASON and the dyno command are both
  # operator-controlled and need not be valid UTF-8.
  def self.blank?(value)
    value.to_s.b.strip.empty?
  end
end
