# frozen_string_literal: true

require_relative 'helper'

# ConsoleGuard::Reporter -- the durable record of a denial.
#
# The record is the only trace of a blocked command that reaches Datadog. The
# banner goes to the operator's terminal over the rendezvous connection and
# nowhere else, and Heroku's own api:dyno record cannot tell a guard denial from
# an application error.
#
# Sent from both halves, because a trail with only one half would report every
# argument-policy block as a clean session.
class ReporterTest < GuardTest
  def test_a_gate_denial_is_posted
    gate('bash', env: reporting_env)
    record = assert_one_record

    assert_equal 'command_denied', record['event']
    assert_equal 'command_not_allowed', record['rule']
    assert_equal 'bash', record['command']
    assert_equal 'becky', record['operator']
    assert_equal 'testing', record['reason']
    assert_equal true, record['enforced']
  end

  def test_a_wrapper_denial_is_posted_too
    wrapper('rails', 'dbconsole', env: reporting_env)
    record = assert_one_record

    assert_equal 'raw_database_session', record['rule']
    # The post-expansion argv, which is what that half judged.
    assert_equal 'rails dbconsole', record['command']
  end

  def test_the_option_allowlist_denial_names_its_rule
    # The widest of the wrapper's rules, so a denial from it is the one most
    # likely to be a false positive worth seeing in the trail.
    wrapper('rake', '--no-such-option', env: reporting_env)
    record = assert_one_record

    assert_equal 'option_not_allowed', record['rule']
    assert_equal 'rake --no-such-option', record['command']
  end

  def test_an_unidentified_session_still_names_the_command
    # The denial CI hits, and "who tried to run what" is the whole content of
    # that record.
    gate('rails c', env: reporting_env.merge('CONSOLE_USER' => ''))
    record = assert_one_record

    assert_equal 'identity_missing', record['rule']
    assert_equal 'rails c', record['command']
  end

  def test_the_dyno_id_comes_from_the_metadata_file
    # The join key against the api:dyno webhook. Taken from the file rather than
    # from HEROKU_DYNO_ID, which `heroku run -e` can set to anything.
    gate('bash', env: reporting_env.merge('HEROKU_DYNO_ID' => 'forged'))
    assert_equal 'dyno-uuid-1', assert_one_record['dyno_id']
  end

  def test_a_spoofed_dyno_name_files_under_the_dyno_it_actually_is
    gate('bash', env: reporting_env.merge('DYNO' => 'web.1'))
    record = assert_one_record

    assert_equal 'dyno_name_spoofed', record['rule']
    assert_equal 'dyno-uuid-1', record['dyno_id']
  end

  def test_a_permitted_command_reports_nothing
    gate('rails c', env: reporting_env)
    wrapper('rails', 'c', env: reporting_env)

    assert_empty records
  end

  def test_nothing_configured_means_nothing_sent
    # The state of every app before rollout reaches it.
    gate('bash')
    assert_empty raw_records
  end

  def test_it_goes_to_the_configured_endpoint
    gate('bash', env: reporting_env)
    assert_includes raw_records, "PATH #{ConsoleGuardTest::RECORD_PATH}".b
  end

  # ---------------------------------------------------------------- attribution

  # The gem sends service/env/app/version and stamps them on its worker, because
  # `heroku run -e` can rewrite all four. There is no worker here, so nothing
  # sent from the dyno carries that guarantee -- but omitting these two is
  # worse, because the cross-check queries scope on them.
  def test_the_app_is_sent_so_at_app_reaches_this_record
    gate('bash', env: reporting_env.merge('HEROKU_APP_NAME' => 'some-app'))
    assert_equal 'some-app', assert_one_record['app']
  end

  def test_the_service_is_sent_so_at_app_service_matches_the_gem
    # Sent under `service`; datadog-proxy renames it to `app_service` on the way
    # to Datadog, because Datadog's JSON preprocessing would otherwise promote a
    # `service` key onto the reserved facet.
    gate('bash', env: reporting_env.merge('DD_SERVICE' => 'some-service'))
    assert_equal 'some-service', assert_one_record['service']
  end

  def test_no_service_is_sent_when_the_app_sets_none
    # Absent for the same reason it would be absent from a gem record. Never
    # absent because a denial produced it.
    gate('bash', env: reporting_env)
    refute_includes assert_one_record.keys, 'service'
  end

  def test_nothing_else_attributional_is_sent
    # `env` scopes monitors, so forging it is the one case where tampering buys
    # what suppression does not; the proxy infers it from the delivery topology
    # instead. Nothing reads `version`.
    gate('bash', env: reporting_env.merge('DD_ENV' => 'lies', 'DD_VERSION' => 'lies'))
    record = assert_one_record

    refute_includes record.keys, 'env'
    refute_includes record.keys, 'version'
    assert_includes record.keys, 'guard_version'
  end

  # ---------------------------------------------------------------- permit mode

  def test_permit_mode_records_the_would_be_denial
    # Phase 1 exists to measure what enforcement would block, which is only
    # measurable if the would-be denials are recorded.
    gate('bash', env: reporting_env.merge('CONSOLE_BLOCK_ENFORCE' => 'false'))
    assert_equal false, assert_one_record['enforced']

    File.write(ConsoleGuardTest::RECORD_LOG, '')
    wrapper('rails', 'dbconsole', env: reporting_env.merge('CONSOLE_BLOCK_ENFORCE' => 'false'))
    assert_equal false, assert_one_record['enforced']
  end

  # ---------------------------------------------------------------- hostile bytes

  # A record has to survive JSON.parse in datadog-proxy, and the command is
  # operator-controlled.
  def test_the_record_survives_a_hostile_command
    wrapper('rails', 'dbconsole', %(a"b\\c), "\t\n", env: reporting_env)
    assert_includes assert_one_record['command'], 'rails dbconsole'
  end

  def test_the_record_survives_invalid_utf8
    # One stray byte would otherwise cost the whole record -- rule, operator and
    # dyno_id with it -- and cost it invisibly, since the only warning goes to
    # the terminal of the operator who was just blocked.
    wrapper('rails', 'dbconsole', "\xC3\xA9".b, "\x8B".b, "\xFF".b, env: reporting_env)
    record = assert_one_record

    assert_equal 'raw_database_session', record['rule']
    assert_equal 'dyno-uuid-1', record['dyno_id']
  end

  def test_every_byte_over_7f_is_recorded_as_u_fffd
    # The price is fidelity: enough to see that something non-ASCII was there,
    # which is all the command field is for.
    wrapper('rails', 'dbconsole', "\xC3\xA9".b, env: reporting_env)
    assert_equal "rails dbconsole ��", assert_one_record['command']
  end

  def test_the_wire_format_is_pure_ascii
    wrapper('rails', 'dbconsole', "\xC3\xA9".b, env: reporting_env)
    assert_match(/\A[\x00-\x7f]*\z/n, raw_records)
  end

  def test_the_reason_is_scrubbed_too
    # Operator-controlled, and unlike the command it is not vetted by anything
    # upstream.
    gate('bash', env: reporting_env.merge('CONSOLE_REASON' => "caf\xC3\xA9-\x8B".b))
    assert_equal "caf��-�", assert_one_record['reason']
  end

  def test_a_long_command_is_truncated
    wrapper('rake', "--#{'x' * 400}", env: reporting_env)
    command = assert_one_record['command']

    assert command.end_with?(' [truncated]'), "not truncated: #{command[0, 40]}..."
    assert_equal 300 + ' [truncated]'.length, command.length
  end

  # ---------------------------------------------------------------- failure

  def test_a_failed_report_says_so_without_leaking_the_credential
    # The endpoint URL carries the Basic credential, and an exception from the
    # reporter can quote it, so a failure is reported as a status and nothing
    # else.
    result = gate('bash', env: reporting_env('/fail-me'))

    assert_includes result.output, 'denial not recorded'
    refute_includes result.output, ConsoleGuardTest::RECORD_CRED
  end

  def test_an_unreachable_endpoint_does_not_hold_up_the_denial
    # Refusing the command is the control; recording it must not be able to
    # block that.
    url = 'http://reporter:s3cr3t@127.0.0.1:1/webhooks/console_audit'
    result = gate('bash', env: { 'CONSOLE_LOGGING_DATADOG_PROXY_URL' => url })

    assert_denied result, 'not permitted'
    assert_includes result.output, 'denial not recorded'
    refute_includes result.output, 's3cr3t'
  end

  def test_a_percent_encoded_credential_is_decoded_first
    # curl percent-decodes userinfo before using it, so a credential containing
    # a reserved character has to arrive at the proxy the same way it used to.
    url = "http://reporter:p%40ss%3Aword@127.0.0.1:#{ConsoleGuardTest.port}#{ConsoleGuardTest::RECORD_PATH}"
    gate('bash', env: { 'CONSOLE_LOGGING_DATADOG_PROXY_URL' => url })

    assert_includes raw_records, "AUTH Basic #{['reporter:p@ss:word'].pack('m0')}".b
  end

  def test_an_endpoint_with_no_userinfo_still_posts
    url = "http://127.0.0.1:#{ConsoleGuardTest.port}#{ConsoleGuardTest::RECORD_PATH}"
    gate('bash', env: { 'CONSOLE_LOGGING_DATADOG_PROXY_URL' => url })

    assert_equal 'command_not_allowed', assert_one_record['rule']
    assert_includes raw_records, "AUTH \n".b
  end

  def test_the_credential_is_sent_as_basic_auth
    # curl takes it from the URL's userinfo; Net::HTTP does not, so the reporter
    # has to lift it out and set the header itself.
    gate('bash', env: reporting_env)
    expected = ['reporter', ConsoleGuardTest::RECORD_CRED].join(':')

    assert_includes raw_records, "AUTH Basic #{[expected].pack('m0')}".b
  end
end
