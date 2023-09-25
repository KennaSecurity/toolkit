# frozen_string_literal: true

require "rspec_helper"

RSpec.describe Kenna::Toolkit::NTTSentinelDynamic::ApiClient do
  subject(:api_client) { described_class.new(api_key: "0xdeadbeef") }

  describe "#vulns" do
    context "when given query conditions" do
      let(:query) { { "query_severity" => 2 } }

      it "includes the condition in the API request" do
        response = { collection: [] }.to_json
        expect(Kenna::Toolkit::Helpers::Http).to receive(:http_get).with(anything, { params: hash_including(query) }, anything).and_return(response)
        api_client.vulns(query).to_a
      end
    end
  end

  describe '#assets' do
    let(:json_file) { File.read 'spec/fixtures/ntt_sentinel_dynamic/v2_assets1.json' }
    let(:response) { JSON.parse(json_file).to_json }

    context 'when given query conditions' do
      it 'gets the assets' do
        expect(Kenna::Toolkit::Helpers::Http).to receive(:http_get).with(anything, anything, anything).and_return(response)
        assets = api_client.assets.to_a
        expect(assets.size).to eq(2)
        assets.each do |asset|
          expect(asset[:subID]).to be_a(Integer) # site id
          expect(asset[:id]).to be_a(Integer)
          expect(asset[:name]).to be_a(String) # label
          expect(asset[:tags]).to be_a(Array)
          expect(asset[:customAssetID]).to be_a(String)
          expect(asset[:assetOwnerName]).to be_a(String)
        end
      end
    end
  end
end
