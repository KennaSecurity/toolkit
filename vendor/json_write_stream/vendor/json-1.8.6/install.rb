#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
include FileUtils::Verbose
require "rbconfig"
include\
  begin
    RbConfig
  rescue NameError
    Config
  end

sitelibdir = CONFIG["sitelibdir"]
cd "lib" do
  install("json.rb", sitelibdir)
  mkdir_p File.join(sitelibdir, "json")
  Dir["json/**/*}"].each do |file|
    d = File.join(sitelibdir, file)
    mkdir_p File.dirname(d)
    install(file, d)
  end
end
warn " *** Installed PURE ruby library."
