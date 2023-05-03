# frozen_string_literal: true

require 'bundler'
Bundler.setup(:default, :test)
require 'pry-byebug'

require_relative "../lib/toolkit"

require "timecop"
require 'vcr'
require 'webmock/rspec'

VCR.configure do |config|
  config.cassette_library_dir = "spec/fixtures/vcr_cassettes"
  config.hook_into :webmock
  config.allow_http_connections_when_no_cassette = false
  %w[
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
  ].each do |key|
    config.filter_sensitive_data("<#{key}>") { ENV[key] }
  end
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
