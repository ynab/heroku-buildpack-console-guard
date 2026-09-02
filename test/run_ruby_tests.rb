# frozen_string_literal: true

# Policy tests for heroku-buildpack-console-guard.
#
#   ruby test/run_ruby_tests.rb
#
# Runs anywhere Ruby does, macOS included: the guard's two entry points are
# driven as subprocesses with a fabricated login-shell argv, so nothing here
# needs procfs or a Heroku stack.
#
# What these do NOT cover is everything the *shell* does around the guard --
# sourcing .profile.d, expanding the operator's command before the wrapper sees
# it, prepending PATH, and acting on the gate's exit status. That needs a real
# login shell and lives in test/run_tests.sh.

require_relative 'helper'

Dir[File.join(__dir__, '*_test.rb')].sort.each { |suite| require suite }
