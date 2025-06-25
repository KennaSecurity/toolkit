# frozen_string_literal: true

require "rspec_helper"
require "timecop"

RSpec.describe Kenna::Toolkit::BitsightTask do
  def read_fixture_file(filename)
    File.read(File.join(%w[spec tasks connectors digital_footprint fixtures], filename))
  end
  let(:options) { { bitsight_api_key: "1234" } }
  let(:validate_key_json) { read_fixture_file 'bitsight_validate_key.json' }
  let(:portfolio_json) { read_fixture_file 'bitsight_portfolio.json' }
  let(:findings1_json) { read_fixture_file 'bitsight_findings_page_1.json' }
  let(:findings2_json) { read_fixture_file 'bitsight_findings_page_2.json' }

  describe "#run" do
    before do
      Timecop.freeze(DateTime.parse("2023-10-30T00:00:00+00:00"))

      stub_request(:get, "https://api.bitsighttech.com/")
        .to_return_json(body: validate_key_json)

      stub_request(:get, "https://api.bitsighttech.com/portfolio")
        .to_return_json(body: portfolio_json)

      stub_request(:get, "https://api.bitsighttech.com/ratings/v1/companies/01bkac90-0000-3333-8888-c333faf7f50t/findings")
        .with(query: { last_seen_gte: "2023-08-01", limit: "100" })
        .to_return_json(body: findings1_json)

      stub_request(:get, "https://api.bitsighttech.com/ratings/v1/companies/01bkac90-0000-3333-8888-c333faf7f50t/findings")
        .with(query: { last_seen_gte: "2023-08-01", limit: "100", offset: "100" })
        .to_return_json(body: findings2_json)
    end

    after do
      Timecop.return
    end

    it "does a full run" do
      expect do
        subject.run(options)
      end.to output(/Attempting to run Kenna Connector at api.kennasecurity.com/).to_stdout
    end
  end
end
