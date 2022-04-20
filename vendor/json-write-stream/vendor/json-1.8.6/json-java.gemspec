#!/usr/bin/env jruby
# frozen_string_literal: true

require "rubygems"

spec = Gem::Specification.new do |s|
  s.name = "json"
  s.version = File.read("VERSION").chomp
  s.summary = "JSON implementation for JRuby"
  s.description = "A JSON implementation as a JRuby extension."
  s.author = "Daniel Luz"
  s.email = "dev+ruby@mernen.com"
  s.homepage = "http://json-jruby.rubyforge.org/"
  s.platform = "java"
  s.rubyforge_project = "json-jruby"
  s.licenses = ["Ruby"]

  s.files = Dir["{docs,lib,tests}/**/*"]

  if s.respond_to? :specification_version
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new("1.2.0")
      s.add_development_dependency("rake", [">= 0"])
      s.add_development_dependency("test-unit", ["~> 2.0"])
    else
      s.add_dependency("rake", [">= 0"])
      s.add_dependency("test-unit", ["~> 2.0"])
    end
  else
    s.add_dependency("rake", [">= 0"])
    s.add_dependency("test-unit", ["~> 2.0"])
  end
  s.metadata["rubygems_mfa_required"] = "true"
end

if $PROGRAM_NAME == __FILE__
  Gem::Builder.new(spec).build
else
  spec
end
