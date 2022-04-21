# frozen_string_literal: true

$LOAD_PATH.unshift File.join(File.dirname(__FILE__), "lib")
require "json_write_stream/version"

Gem::Specification.new do |s|
  s.required_ruby_version = ">= 3.1.2"
  s.name                  = "json_write_stream"
  s.version               = ::JsonWriteStream::VERSION
  s.authors               = ["Cameron Dutro"]
  s.email                 = ["camertron@gmail.com"]
  s.homepage              = "http://github.com/camertron"

  s.description = s.summary = "An easy, streaming way to generate JSON."

  s.platform = Gem::Platform::RUBY

  s.require_path = "lib"
  s.files = Dir["{lib,spec}/**/*", "Gemfile", "History.txt", "README.md", "Rakefile", "json_write_stream.gemspec"]
  s.metadata["rubygems_mfa_required"] = "true"
end
