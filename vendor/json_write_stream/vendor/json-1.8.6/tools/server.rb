#!/usr/bin/env ruby
# frozen_string_literal: true

require "webrick"
include WEBrick
$LOAD_PATH.unshift "ext"
$LOAD_PATH.unshift "lib"
require "json"

class JSONServlet < HTTPServlet::AbstractServlet
  @@count = 1

  def do_GET(_req, res)
    obj = {
      "TIME" => Time.now.strftime("%FT%T"),
      "foo" => "Bär",
      "bar" => "© ≠ €!",
      "a" => 2,
      "b" => 3.141,
      "COUNT" => @@count += 1,
      "c" => "c",
      "d" => [1, "b", 3.14],
      "e" => { "foo" => "bar" },
      "g" => "松本行弘",
      "h" => 1000.0,
      "i" => 0.001,
      "j" => "\xf0\xa0\x80\x81"
    }
    res.body = JSON.generate obj
    res["Content-Type"] = "application/json"
  end
end

def create_server(err, dir, port)
  dir = File.expand_path(dir)
  err.puts "Surf to:", "http://#{Socket.gethostname}:#{port}"

  s = HTTPServer.new(
    Port: port,
    DocumentRoot: dir,
    Logger: WEBrick::Log.new(err),
    AccessLog: [
      [err, WEBrick::AccessLog::COMMON_LOG_FORMAT],
      [err, WEBrick::AccessLog::REFERER_LOG_FORMAT],
      [err, WEBrick::AccessLog::AGENT_LOG_FORMAT]
    ]
  )
  s.mount("/json", JSONServlet)
  s
end

default_dir = File.expand_path(File.join(File.dirname(__FILE__), "..", "data"))
dir = ARGV.shift || default_dir
port = (ARGV.shift || 6666).to_i
s = create_server($stderr, dir, 6666)
t = Thread.new { s.start }
trap(:INT) do
  s.shutdown
  t.join
  exit
end
sleep