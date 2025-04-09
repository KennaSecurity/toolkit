# frozen_string_literal: true

require 'bundler'
Bundler.setup(:default, :test)
require 'pry-byebug'

require 'simplecov'
SimpleCov.start do # Must come before application code is loaded
  add_filter ['/initialize/', '/scripts/', '/spec/', '/util/', '/lib/http.rb']
end
if ENV['CI']
  require 'simplecov-cobertura'
  SimpleCov.formatter = SimpleCov::Formatter::CoberturaFormatter # Format for Codecov by Sentry
end

require_relative "../lib/toolkit"

require "timecop"
require 'vcr'
require 'webmock/rspec'

RSpec.configure do |config|
  # Use the GitHub Annotations formatter for CI
  if ENV['GITHUB_ACTIONS'] == 'true'
    require 'rspec/github'
    config.add_formatter RSpec::Github::Formatter
  end

  config.before(:each) do
    stub_request(:any, 'http://169.254.169.254/latest/metadata/').to_raise(RestClient::Exceptions::OpenTimeout)
  end
end

VCR.configure do |config|
  config.cassette_library_dir = "spec/fixtures/vcr_cassettes"
  config.hook_into :webmock
  config.allow_http_connections_when_no_cassette = false
  %w[
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    GITHUB_TOKEN
    SNYK_API_TOKEN
  ].each do |key|
    config.filter_sensitive_data("<#{key}>") { ENV[key] }
  end
  config.debug_logger = File.open("log/vcr_debug.log", "w")
end

module Kenna
  module Toolkit
    module KdiAccumulatorSpy
      attr_reader :vuln_defs, :assets

      def clear_data_arrays; end
    end
  end
end

aws_credentials_class = begin
  "Aws::Credentials".constantize
rescue StandardError
  nil
end
if aws_credentials_class
  module Aws
    class Credentials
      # I want to test equality in specs, but the AWS CLI doesn't define it properly
      def ==(other)
        to_yaml == other.to_yaml
      end
    end
  end
end
