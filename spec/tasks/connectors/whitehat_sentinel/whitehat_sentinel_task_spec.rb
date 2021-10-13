# frozen_string_literal: true

require "rspec_helper"

RSpec.describe Kenna::Toolkit::WhitehatSentinelTask do
  subject(:task) { described_class.new }

  describe "#run" do
    let(:api_client) { instance_double(Kenna::Toolkit::WhitehatSentinel::ApiClient, api_key_valid?: valid, sites: {}, vulns: [], assets: []) }
    let(:key) { "0xdeadbeef" }
    let(:options) { { whitehat_api_key: key } }
    let(:valid) { true }

    before do
      allow(Kenna::Toolkit::WhitehatSentinel::ApiClient).to receive(:new) { api_client }
    end

    it "succeeds" do
      expect { task.run(options) }.to_not raise_error
    end

    context "when the API key is wrong" do
      let(:valid) { false }

      it "exits the script" do
        expect { task.run(options) }.to raise_error(SystemExit)
      end
    end
  end

  describe "#tags_for" do
    let(:asset) do
      {
        custom_asset_id: whitehat_custom_id,
        label: whitehat_label,
        asset_owner_name: whitehat_owner,
        tags: whitehat_tags
      }
    end
    let(:whitehat_custom_id) { "custom id" }
    let(:whitehat_tags) { %w[tag_one tag_two] }
    let(:whitehat_label) { "label" }
    let(:whitehat_owner) { "owner" }

    it "includes the asset's tags from Whitehat" do
      expect(task.tags_for(asset)).to include(*whitehat_tags)
    end

    it "includes the asset's label from Whitehat" do
      expect(task.tags_for(asset)).to include(whitehat_label)
    end

    it "includes the asset's owner name from Whitehat" do
      expect(task.tags_for(asset)).to include(whitehat_owner)
    end

    it "includes the asset's custom id from Whitehat" do
      expect(task.tags_for(asset)).to include(whitehat_custom_id)
    end

    context "when there are no tags" do
      let(:whitehat_tags) { [] }

      it "includes the other fields" do
        expect(task.tags_for(asset)).to contain_exactly(whitehat_label, whitehat_owner, whitehat_custom_id)
      end
    end

    context "when a field is blank" do
      let(:whitehat_owner) { "" }

      it "excludes the empty string" do
        expect(task.tags_for(asset)).to_not include("")
      end
    end

    context "when a field is nil" do
      let(:whitehat_label) { nil }

      it "excludes the nil" do
        expect(task.tags_for(asset)).to_not include(nil)
      end
    end

    context "when a field is missing" do
      before do
        asset.delete(:custom_asset_id)
      end

      it "includes the other fields" do
        expect(task.tags_for(asset)).to contain_exactly(*[whitehat_tags, whitehat_label, whitehat_owner].flatten)
      end
    end
  end
end
