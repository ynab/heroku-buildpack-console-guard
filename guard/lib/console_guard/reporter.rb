# frozen_string_literal: true

module ConsoleGuard
  # Durable record of a console-guard denial.
  #
  # WHY THIS FILE EXISTS
  #
  # The denial banner is written to the operator's terminal over the rendezvous
  # connection. It is not in the app's log stream, and it never reaches Datadog.
  # So a blocked command leaves behind only Heroku's own `api:dyno` record, which
  # shows that a command was attempted but cannot distinguish a guard denial from
  # an application error -- and the cross-check queries have to read "no console
  # record for this dyno" as "blocked, or lost", which is not an audit trail.
  #
  # One record per denial closes that. The queries then read a missing console
  # record as lost, full stop.
  #
  # WHERE IT GOES
  #
  # The same endpoint and the same credential as the console_audit gem:
  # CONSOLE_LOGGING_DATADOG_PROXY_URL, carrying HTTP Basic userinfo. One endpoint,
  # one credential to issue and rotate, one Datadog source, and the join keys the
  # proxy already derives (`dyno_id`, and `console_identity` from `operator`)
  # apply to these records unchanged. `event` is what tells them apart.
  #
  # ATTRIBUTION: `app` AND `service`
  #
  # The gem sends `service` / `env` / `app` / `version` and stamps them on the
  # *worker*, because `heroku run -e` can rewrite every one of them and a record
  # tagged `env:staging` would keep flowing to Datadog while dropping quietly out
  # of a production-scoped monitor. There is no worker here, so nothing sent from
  # this side can carry that guarantee.
  #
  # `app` and `service` are sent anyway, because the tampering argument does not
  # transfer to them. An operator who wants their denial record gone can unset the
  # endpoint above and delete it outright, so forging either field is strictly
  # weaker than what they can already do, and neither one scopes a monitor. What
  # tampering would actually buy is closed where suppression is impossible, which
  # is the gem's position and not this one.
  #
  # Sending them is what keeps a denial record reachable. The cross-check queries
  # scope on `@app` to span both log sources at once, so without it they skip every
  # denial silently. `@service` is the same problem one rung down: the gem stamps
  # it, so a query that filters on it would return sessions and drop the denials
  # beside them. Send it when the app sets DD_SERVICE, and the attribute means one
  # thing on both record kinds -- absent because the app has no DD_SERVICE, never
  # because of which half of the audit trail produced the record.
  #
  # `service` goes under that name, not the `app_service` it lands in Datadog as.
  # datadog-proxy does the renaming (Datadog's JSON preprocessing would otherwise
  # promote a `service` key onto the reserved facet), and one sender contract beats
  # two. It follows that the proxy must have that rename deployed before this does.
  #
  # `env` stays unsent, and the asymmetry is deliberate: it is a reserved facet that
  # scopes monitors, so forging it is the one case where tampering buys something
  # suppression does not. datadog-proxy infers it from the delivery topology, which
  # nothing in this dyno can reach. `version` stays unsent because nothing reads it.
  #
  # LIMITATION
  #
  # Fail-open, and not sufficient on its own. The URL variable is inherited by the
  # one-off dyno, so an operator who knows about this can suppress their own
  # denial record with `heroku run -e CONSOLE_LOGGING_DATADOG_PROXY_URL=`. What
  # survives that is the `api:dyno` webhook and the exit status. See the README.
  module Reporter
    URL_VAR = "CONSOLE_LOGGING_DATADOG_PROXY_URL"
    EVENT = "command_denied"
    OPEN_TIMEOUT = 2
    MAX_TIME = 4
    # Matches the denial banner, so the record and the banner agree on what the
    # guard was judging.
    COMMAND_MAX = 300

    # rule      short stable identifier for the check that refused -- the field to
    #           group a monitor by, because denial *messages* get reworded
    # command   what the guard was judging, as the banner shows it
    # enforced  Sent in dry-run mode as well: phase 1 exists to measure what
    #           enforcement would block, which is only measurable if the would-be
    #           denials are recorded.
    # dyno_id   the join key against the api:dyno webhook
    def self.report(rule:, command:, enforced:, dyno_id:)
      url = ENV[URL_VAR].to_s
      # Nothing configured: an app that has not been given the endpoint is not
      # one this can report for. Silent, because it is also the state of every
      # app before rollout reaches it.
      return if url.empty?

      post(url, body(rule: rule, command: command, enforced: enforced, dyno_id: dyno_id))
    end

    def self.body(rule:, command:, enforced:, dyno_id:)
      fields = {
        "event" => EVENT,
        "enforced" => enforced,
        "rule" => ascii(rule.to_s.empty? ? "unknown" : rule),
        "command" => ascii(truncate(command)),
        "operator" => ascii(ENV["CONSOLE_USER"]),
        "reason" => ascii(ENV["CONSOLE_REASON"]),
        # Resolved from the dyno metadata file, which the profile script refuses
        # a session for when $DYNO disagrees with it. HEROKU_DYNO_ID is the
        # fallback and is `-e`-settable, so it is only as good as the app's
        # metadata being enabled.
        "dyno_id" => ascii(dyno_id),
        # Attribution, so `@app` and `@app_service` reach this record too.
        "app" => ascii(ENV["HEROKU_APP_NAME"]),
        "service" => ascii(ENV["DD_SERVICE"]),
        "guard_version" => ascii(VERSION),
        # datadog-proxy claims `timestamp` as the log's official date, exactly as
        # it does for the gem's records, so a denial is filed at the moment it
        # happened.
        "timestamp" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%S.000Z")
      }
      # Omitted rather than null so that a missing operator reads as absent in
      # Datadog rather than as the string "null".
      fields.reject! { |_, value| value.is_a?(String) && value.empty? }

      # ascii_only, so every string in the record is pure ASCII and a byte
      # scrubbed to U+FFFD below is written as an escape rather than as raw bytes.
      JSON.generate(fields, ascii_only: true)
    end

    def self.truncate(command)
      bytes = command.to_s.b
      return bytes if bytes.bytesize <= COMMAND_MAX

      "#{bytes[0, COMMAND_MAX]} [truncated]"
    end

    # Replace every byte >= 0x80 with U+FFFD.
    #
    # A JSON string has to be valid UTF-8, and both the command and the reason
    # are operator-controlled bytes. One stray byte would cost the entire record
    # -- rule, operator and dyno_id with it -- and it would be lost where nobody
    # auditing can see it, because the only warning goes to the terminal of the
    # operator who was just blocked.
    #
    # The cost is fidelity: `puts 'héllo'` is recorded with two replacement
    # characters, and the leftover exit-status sentinel in the two-marker case
    # reads as three. Enough to see that something non-ASCII was there.
    def self.ascii(value)
      value.to_s.b.gsub(/[^\x00-\x7f]/n) { "\xEF\xBF\xBD".b }.force_encoding(Encoding::UTF_8)
    end

    # One attempt, short timeouts, no retry: the dyno is about to exit, and the
    # operator should not wait on the audit pipeline to be told they were denied.
    def self.post(url, json)
      endpoint, user, password = split_userinfo(url)
      uri = URI.parse(endpoint)

      request = Net::HTTP::Post.new(uri.request_uri, "Content-Type" => "application/json")
      # curl takes Basic credentials from the URL's userinfo; Net::HTTP does not.
      request.basic_auth(user, password.to_s) if user
      request.body = json

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = OPEN_TIMEOUT
      http.read_timeout = MAX_TIME
      http.write_timeout = MAX_TIME

      response = http.start { |connection| connection.request(request) }
      return if response.is_a?(Net::HTTPSuccess)

      failed(response.code)
    rescue StandardError => e
      # The class, never the message: an exception from here can quote the URL,
      # which carries the Basic credential.
      failed("no response (#{e.class})")
    end

    # Loud, because a denial that was not recorded is the gap this file exists to
    # close. Never fatal: refusing the command is the control, and recording it
    # must not be able to hold that up.
    def self.failed(detail)
      warn "console-guard: denial not recorded (#{URL_VAR} returned #{detail})"
    end

    # `URI.parse` is strict about what a userinfo may contain and the credential
    # here is whatever the proxy issued, so it is lifted out before parsing
    # rather than parsed and read back off.
    USERINFO = %r{\A(?<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?<userinfo>[^/@]*)@(?<rest>.*)\z}m

    def self.split_userinfo(url)
      match = USERINFO.match(url)
      return [url, nil, nil] unless match

      user, _, password = match[:userinfo].partition(":")
      ["#{match[:scheme]}#{match[:rest]}", unescape(user), unescape(password)]
    end

    def self.unescape(value)
      value.gsub(/%([0-9A-Fa-f]{2})/) { ::Regexp.last_match(1).hex.chr }
    end
  end
end
