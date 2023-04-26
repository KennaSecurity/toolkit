# frozen_string_literal: true

require 'rspec_helper'
require 'webmock/rspec' # We don't have access to Wiz, so we can't make VCR recordings.

RSpec.describe Kenna::Toolkit::Wiz::Client do
  subject(:client) { described_class.new(nil, nil, 'http://api.example.com/', nil, nil, nil, nil, nil, nil) }
  let(:empty_response) { { 'data' => { 'vulnerabilityFindings' => { 'pageInfo' => {} } } } }
  before do
    stub_request(:post, "api.example.com/").to_return_json(body: { access_token: 'foo' }, status: 200)
  end

  describe "#paged_vulns" do
    it "includes detectionMethod in its query" do
      expect(client).to receive(:api_request).with(/detectionMethod/).and_return(empty_response)
      client.paged_vulns { nil }
    end

    it "includes detailedName in its query" do
      expect(client).to receive(:api_request).with(/detailedName/).and_return(empty_response)
      client.paged_vulns { nil }
    end
  end
end
