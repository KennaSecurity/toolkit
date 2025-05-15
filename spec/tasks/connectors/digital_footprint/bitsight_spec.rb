# frozen_string_literal: true

require "rspec_helper"
require "timecop"

RSpec.describe Kenna::Toolkit::BitsightTask do
  let(:options) { { bitsight_api_key: "1234" } }
  let(:aws_host_params) do
    {
      method: :get,
      timeout: 1,
      url: "http://169.254.169.254/latest/metadata/"
    }
  end
  let(:validate_key_expected_params) do
    {
      method: :get,
      url: "https://api.bitsighttech.com/"
    }
  end
  let(:portafolio_expected_params) do
    {
      method: :get,
      url: "https://1234:@api.bitsighttech.com/portfolio"
    }
  end
  let(:findings1_expected_params) do
    {
      method: :get,
      url: 'https://api.bitsighttech.com/ratings/v1/companies/01bkac90-0000-3333-8888-c333faf7f50t/findings?limit=100&last_seen_gte=2023-08-01'
    }
  end
  let(:findings2_expected_params) do
    {
      method: :get,
      url: 'https://api.bitsighttech.com/ratings/v1/companies/01bkac90-0000-3333-8888-c333faf7f50t/findings?last_seen_gte=2023-08-01&limit=100&offset=100'
    }
  end
  let(:validate_key_json_file) { File.read 'spec/fixtures/digital_footprint/bitsight_validate_key.json' }
  let(:validate_key_response) { double(body: validate_key_json_file) }
  let(:portafolio_json_file) { File.read 'spec/fixtures/digital_footprint/bitsight_portafolio.json' }
  let(:portafolio_response) { double(body: portafolio_json_file) }
  let(:findings1_json_file) { File.read 'spec/fixtures/digital_footprint/bitsight_findings_page_1.json' }
  let(:findings2_json_file) { File.read 'spec/fixtures/digital_footprint/bitsight_findings_page_2.json' }
  let(:findings1_response) { double(body: findings1_json_file) }
  let(:findings2_response) { double(body: findings2_json_file) }

  describe "#run" do
    before do
      Timecop.freeze(DateTime.parse("2023-10-30T00:00:00+00:00"))

      allow(RestClient::Request)
        .to receive(:execute)
        .with(hash_including(aws_host_params)).twice

      allow(RestClient::Request)
        .to receive(:execute)
        .with(hash_including(validate_key_expected_params))
        .and_return(validate_key_response)

      allow(RestClient::Request)
        .to receive(:execute)
        .with(hash_including(portafolio_expected_params))
        .and_return(portafolio_response)

      allow(RestClient::Request)
        .to receive(:execute)
        .with(hash_including(findings2_expected_params))
        .and_return(findings2_response)

      allow(RestClient::Request)
        .to receive(:execute)
        .with(hash_including(findings1_expected_params))
        .and_return(findings1_response)
    end

    after do
      Timecop.return
      $stdout = STDOUT
    end

    it "does a full run" do
      stdout = StringIO.new
      $stdout = stdout

      subject.run(options)

      last_stdout = stdout.string.split("\n").last
      expect(last_stdout).to match(/Attempting to run Kenna Connector at api.kennasecurity.com/)
      $stdout = STDOUT
    end
  end
end
