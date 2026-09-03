# frozen_string_literal: true

module ConsoleGuard
  # Which dyno this is, and what the guard therefore applies to it.
  #
  # $DYNO is an environment variable, and `heroku run -e DYNO=web.1` would
  # otherwise let an operator skip the gate entirely. Dyno metadata also writes
  # the dyno's name and UUID to a file inside the dyno, which `-e` cannot touch,
  # so that is preferred and a mismatch is treated as tampering.
  class Dyno
    attr_reader :name, :id, :claimed_name, :metadata_name, :metadata_id

    def self.resolve(path = DYNO_METADATA_FILE)
      new(**read_metadata(path))
    end

    # Anything unparseable is treated as absent rather than as an error, so a
    # change in the file's shape degrades to the $DYNO fallback.
    #
    # The file carries several objects, each with its own name and id (dyno, app,
    # release), so the dyno object is addressed rather than searched: app.name is
    # empty on a real dyno, and reading it instead would silently defeat the
    # spoof check below.
    def self.read_metadata(path)
      dyno = JSON.parse(File.read(path))["dyno"]
      return {} unless dyno.is_a?(Hash)

      {metadata_name: dyno["name"].to_s, metadata_id: dyno["id"].to_s}
    rescue StandardError
      {}
    end

    def initialize(metadata_name: "", metadata_id: "")
      @metadata_name = metadata_name
      @metadata_id = metadata_id
      @claimed_name = ENV["DYNO"].to_s

      if metadata_seen?
        @name = metadata_name
        @id = metadata_id.empty? ? ENV["HEROKU_DYNO_ID"].to_s : metadata_id
      else
        @name = @claimed_name
        @id = ENV["HEROKU_DYNO_ID"].to_s
      end
    end

    def metadata_seen?
      !@metadata_name.empty?
    end

    def spoofed?
      metadata_seen? && !@claimed_name.empty? && @claimed_name != @metadata_name
    end

    # The dyno UUID is what correlates a console audit record with Heroku's own
    # api:dyno webhook record for the same session, and the metadata file is what
    # makes the dyno name un-spoofable. Without dyno metadata neither is
    # available.
    def correlatable?
      metadata_seen? && !@id.empty?
    end

    # Which dyno families the guard applies to. See ConsoleGuard::Gate for what
    # gated and audited each mean, and why the two are not the same question.
    #
    #   run.N        `heroku run` / `heroku run:detached` -- gated and audited
    #   scheduler.N  Heroku Scheduler        -- audited only
    #   release.N    release phase           -- audited only
    #   anything else                        -- neither
    def gated?
      # No dyno name from either source. Assume a one-off dyno and gate it,
      # rather than letting a command through ungated.
      @name.start_with?("run.") || @name.empty?
    end

    def audited?
      gated? || @name.start_with?("scheduler.", "release.")
    end
  end
end
