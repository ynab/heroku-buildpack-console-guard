# frozen_string_literal: true

# Console guard, Ruby half. Loaded by both entry points and by nothing else.
#
# The two entry points -- libexec/gate.rb and libexec/command.rb -- are reached
# from thin bash stubs, because a few things can only be done by the login shell
# itself. Everything that is a policy decision is here.
#
# HARDENING THE INTERPRETER
#
# The guard decides whether operator-influenced code may enter a Rails process,
# so nothing the operator controls may reach the guard's own interpreter first.
# `heroku run -e` can set any variable, and three of them are code injection:
#
#   RUBYOPT   closed by `--disable=rubyopt` on the command line of both stubs
#   RubyGems  closed by `--disable=gems`, which also closes GEM_HOME/GEM_PATH
#   RUBYLIB   closed below
#
# RUBYLIB is prepended to $LOAD_PATH, so `require 'json'` could otherwise be
# answered by an operator's file. Its entries are dropped before the first
# require. Our own files are reached with require_relative, which never consults
# $LOAD_PATH at all.
ENV["RUBYLIB"].to_s.split(File::PATH_SEPARATOR).each do |dir|
  next if dir.empty?

  $LOAD_PATH.delete(dir)
  $LOAD_PATH.delete(File.expand_path(dir))
end

require "json"
require "net/http"
require "uri"

require_relative "console_guard/config"
require_relative "console_guard/banner"
require_relative "console_guard/reporter"
require_relative "console_guard/denials"
require_relative "console_guard/dyno"
require_relative "console_guard/gate"
require_relative "console_guard/command"
