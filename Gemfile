# frozen_string_literal: true

# Development only. Nothing here reaches a dyno: bin/compile installs the files
# under guard/ and nothing else, and the guard runs on stdlib with
# `--disable=gems`, so it cannot load a gem even if one were present.
source "https://rubygems.org"

gem "rubocop", "~> 1.88.2", require: false # Must satisfy standard's rubocop pin
gem "standard", require: false
