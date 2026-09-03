# frozen_string_literal: true

# Shared setup for the guard's Ruby test suites.
#
# The policy is compiled once, by bin/compile, into a temporary slug -- so these
# suites test the same rendered files a dyno gets, placeholders substituted, and
# not the templates in guard/.
#
# The two entry points are then driven as subprocesses. That is deliberate: both
# halves refuse by calling `exit`, and the wrapper ends in `exec`, so testing
# them in process would mean adding a seam to the guard that exists only for the
# tests -- and a seam is exactly where a bypass hides. A subprocess is what a
# dyno runs.
#
# What the shell does around them -- sourcing .profile.d, expanding the command,
# prepending PATH, finding the wrapper -- is not covered here. That is
# test/run_tests.sh, which needs a Linux login shell for it.

require "minitest/autorun"
require "English"
require "fileutils"
require "json"
require "rbconfig"
require "tmpdir"

module ConsoleGuardTest
  ROOT = File.expand_path("..", __dir__)
  TMP = Dir.mktmpdir("console-guard-test")

  APP = File.join(TMP, "app")
  METADATA = File.join(TMP, "dyno-metadata.json")
  FAKE_BIN = File.join(TMP, "fakebin")
  # The same fakes in a directory whose name is a shell metacharacter, for the
  # case where the resolved binary's path must not reach a shell.
  HOSTILE_BIN = File.join(TMP, "fake;echo PWNED")
  # Two files a test can name where one has to exist on disk, for the `rails
  # runner <path>` rule -- which turns on exactly that, as Rails' own does.
  ON_DISK = ["script.rb", "payload.rb"].freeze

  RUBY = RbConfig.ruby
  GATE = File.join(APP, ".console-guard/libexec/run_gate.rb")
  WRAPPER = File.join(APP, ".console-guard/libexec/run_command.rb")

  RECORD_LOG = File.join(TMP, "records.log")
  RECORD_PORT_FILE = File.join(TMP, "recorder.port")
  RECORD_PATH = "/webhooks/console_audit"
  # In the URL as it is in the real config var, so a test can prove it never
  # reaches the operator.
  RECORD_CRED = "s3cr3t-not-for-operators"

  # The environment a gated `heroku run` arrives with. Individual tests override
  # what they are about and inherit the rest, so a case reads as its own subject.
  BASE_ENV = {
    "HOME" => APP,
    "DYNO" => "run.1234",
    "CONSOLE_USER" => "becky",
    "CONSOLE_REASON" => "testing",
    "PATH" => "#{FAKE_BIN}:/usr/local/bin:/usr/bin:/bin"
  }.freeze

  Result = Struct.new(:status, :stdout, :stderr) do
    def output
      "#{stdout}#{stderr}"
    end

    def denied?
      status == 1
    end

    def ran?
      stdout.include?("RAN ")
    end
  end

  class << self
    def setup!
      build!
      fake_binaries!
      start_recorder!
    end

    def build!
      env_dir = File.join(TMP, "env")
      FileUtils.mkdir_p([APP, env_dir, File.join(TMP, "cache")])
      File.write(File.join(env_dir, "CONSOLE_GUARD_DYNO_METADATA_FILE"), METADATA)

      log = IO.popen([File.join(ROOT, "bin/compile"), APP, File.join(TMP, "cache"), env_dir],
        err: [:child, :out], &:read)
      raise "bin/compile failed:\n#{log}" unless $CHILD_STATUS.success?

      ON_DISK.each { |name| FileUtils.touch(File.join(APP, name)) }
    end

    # Stand in for the real rails/rake/bundle the wrapper execs into, so a test
    # can tell "blocked" from "ran, with exactly these arguments".
    def fake_binaries!
      [FAKE_BIN, HOSTILE_BIN].each do |dir|
        FileUtils.mkdir_p(dir)
        ["rails", "rake", "bundle"].each do |name|
          path = File.join(dir, name)
          File.write(path, "#!/bin/sh\necho \"RAN #{name} $*\"\n")
          File.chmod(0o755, path)
        end
      end
    end

    def start_recorder!
      File.write(RECORD_LOG, "")
      @recorder = spawn(RUBY, File.join(ROOT, "test/lib/recorder.rb"),
        RECORD_LOG, RECORD_PORT_FILE)

      40.times do
        break if File.size?(RECORD_PORT_FILE)

        sleep 0.05
      end
      raise "the denial recorder did not start" unless File.size?(RECORD_PORT_FILE)

      @port = File.read(RECORD_PORT_FILE).strip
    end

    attr_reader :port

    def report_url(path = RECORD_PATH)
      "http://reporter:#{RECORD_CRED}@127.0.0.1:#{@port}#{path}"
    end

    def teardown!
      Process.kill("TERM", @recorder) if @recorder
      FileUtils.remove_entry(TMP)
    rescue StandardError
      nil
    end
  end
end

ConsoleGuardTest.setup!
Minitest.after_run { ConsoleGuardTest.teardown! }

# Base class for both entry-point suites.
class GuardTest < Minitest::Test
  include ConsoleGuardTest

  def setup
    # Present unless a test says otherwise, so the metadata-absent path is never
    # reached by accident and read as a pass.
    write_metadata("dyno" => {"id" => "dyno-uuid-1", "name" => "run.1234"},
      "app" => {"id" => "aid", "name" => ""},
      "release" => {"id" => 117})
    File.write(ConsoleGuardTest::RECORD_LOG, "")
  end

  def write_metadata(value)
    File.write(ConsoleGuardTest::METADATA, value.is_a?(String) ? value : JSON.generate(value))
  end

  # Run the profile half against a fabricated login-shell argv.
  #
  # `command` is the dyno command as Heroku would pass it, i.e. the payload of
  # `bash -c`. Pass `argv:` instead to control the whole login-shell argv, which
  # is what the "the gate cannot read this" cases are about.
  def gate(command = nil, env: {}, argv: nil)
    argv ||= ["bash", "-c", command]
    cmdline = File.join(ConsoleGuardTest::TMP, "cmdline.bin")
    File.binwrite(cmdline, argv.map { |a| "#{a}\0" }.join)

    run_guard(ConsoleGuardTest::GATE, [], env.merge("CONSOLE_GUARD_CMDLINE" => cmdline))
  end

  # Run the command-wrapper half. `program` is the name it was invoked under,
  # which is what distinguishes rails from rake from bundle.
  def wrapper(program, *args, env: {})
    run_guard(ConsoleGuardTest::WRAPPER, [program, *args], env)
  end

  def run_guard(entry_point, args, env)
    out_path = File.join(ConsoleGuardTest::TMP, "stdout")
    err_path = File.join(ConsoleGuardTest::TMP, "stderr")

    child_env = ConsoleGuardTest::BASE_ENV.merge(env)
    # nil means "unset this", which is a different thing from empty and is the
    # difference several cases turn on.
    child_env.each_key { |key| child_env[key] = nil if child_env[key].nil? }

    pid = spawn(child_env,
      # The flags the shell stubs pass, so the tests run the
      # interpreter the way a dyno does.
      ConsoleGuardTest::RUBY, "--disable=gems,rubyopt", entry_point, *args,
      unsetenv_others: true, chdir: ConsoleGuardTest::APP,
      out: out_path, err: err_path)
    Process.wait(pid)

    # Read as bytes. A dyno runs in the C locale, so Encoding.default_external
    # is US-ASCII there and File.read would hand back an invalidly-tagged string
    # the moment the guard writes the exit-status sentinel or scrubs a byte.
    Result.new($CHILD_STATUS.exitstatus, File.binread(out_path), File.binread(err_path))
  end

  # ---------------------------------------------------------------- assertions

  def assert_denied(result, expected = nil, message = nil)
    refute result.ran?, "expected a denial, but the command ran:\n#{result.output}"
    assert_equal 1, result.status,
      "expected exit 1, got #{result.status}:\n#{result.output}"
    return unless expected

    assert_includes result.output, expected.b, message
  end

  def assert_permitted(result)
    refute_equal 1, result.status, "expected the command to be permitted:\n#{result.output}"
  end

  # The wrapper ends in `exec`, so "permitted" is observable as the fake binary
  # reporting the argv it received.
  def assert_ran(result, expected_argv = nil)
    assert result.ran?, "expected the command to run:\n#{result.output}"
    return unless expected_argv

    assert_includes result.stdout, "RAN #{expected_argv}".b
  end

  # ---------------------------------------------------------------- records

  def reporting_env(path = ConsoleGuardTest::RECORD_PATH)
    {"CONSOLE_LOGGING_DATADOG_PROXY_URL" => ConsoleGuardTest.report_url(path)}
  end

  # The denial records POSTed since this test started, as parsed JSON.
  def records
    File.binread(ConsoleGuardTest::RECORD_LOG)
      .lines
      .filter_map { |line| JSON.parse(line.delete_prefix("BODY ")) if line.start_with?("BODY ") }
  end

  def raw_records
    File.binread(ConsoleGuardTest::RECORD_LOG)
  end

  def assert_one_record
    found = records
    assert_equal 1, found.length, "expected exactly one denial record, got: #{found.inspect}"
    found.first
  end
end
