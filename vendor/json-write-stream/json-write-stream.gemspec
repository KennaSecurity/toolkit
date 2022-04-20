# frozen_string_literal: true

$LOAD_PATH.unshift File.join(File.dirname(__FILE__), "lib")
require "json-write-stream/version"

Gem::Specification.new do |s|
  s.name     = "json-write-stream"
  s.version  = ::JsonWriteStream::VERSION
  s.authors  = ["Cameron Dutro"]
  s.email    = ["camertron@gmail.com"]
  s.homepage = "http://github.com/camertron"

  s.description = s.summary = "An easy, streaming way to generate JSON."

  s.platform = Gem::Platform::RUBY

  s.require_path = "lib"
  s.files = Dir["{lib,spec}/**/*", "Gemfile", "History.txt", "README.md", "Rakefile", "json-write-stream.gemspec"]
  s.metadata["rubygems_mfa_required"] = "true"
end
