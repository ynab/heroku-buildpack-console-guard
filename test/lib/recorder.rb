# frozen_string_literal: true

# Stands in for datadog-proxy, so a test can see the denial record the guard
# POSTs without a network.
#
#   ruby recorder.rb <log path> <port file>
#
# Appends one `PATH <request path>` and one `BODY <request body>` line per
# request, and answers 202 -- the real endpoint's success code -- unless the
# request path says to fail, which is how the "a failed report never leaks the
# credential" test is arranged.
#
# Deliberately a raw TCPServer: the suite runs on whatever Ruby the stack image
# has, with no gems and no webrick.

require 'socket'

log_path, port_path = ARGV
abort 'usage: recorder.rb <log path> <port file>' unless log_path && port_path

server = TCPServer.new('127.0.0.1', 0)
File.write(port_path, server.addr[1].to_s)

log = File.open(log_path, 'a')
log.sync = true

loop do
  socket = server.accept
  begin
    request_line = socket.gets.to_s
    path = request_line.split(' ')[1].to_s

    length = 0
    while (header = socket.gets)
      break if header.strip.empty?

      length = ::Regexp.last_match(1).to_i if header =~ /\AContent-Length:\s*(\d+)/i
    end
    body = length.positive? ? socket.read(length).to_s : ''

    log.write("PATH #{path}\n")
    log.write("BODY #{body}\n")

    status = path.include?('fail-me') ? '500 Internal Server Error' : '202 Accepted'
    socket.write("HTTP/1.1 #{status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
  rescue StandardError
    # A malformed or abandoned request must not take the recorder down and turn
    # every later assertion into a lie about the guard.
    nil
  ensure
    socket.close
  end
end
