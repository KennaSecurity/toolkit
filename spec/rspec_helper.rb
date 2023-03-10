# frozen_string_literal: true

require 'bundler'
# Bundler.setup(:default, :test)
require 'pry-byebug'

require_relative "../lib/toolkit"

require "timecop"
require 'webmock/rspec'

RSpec.configure do |config|
  config.before(:each) do
    stub_request(:any, 'http://169.254.169.254/latest/metadata/').to_raise(RestClient::Exceptions::OpenTimeout)
  end
end

module Kenna
  module Toolkit
    module KdiAccumulatorSpy
      attr_reader :vuln_defs
      attr_reader :assets

      def clear_data_arrays; end
    end
  end
end
