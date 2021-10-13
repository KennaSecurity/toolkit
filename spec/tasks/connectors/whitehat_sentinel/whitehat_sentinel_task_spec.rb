# frozen_string_literal: true

require "rspec_helper"

RSpec.describe Kenna::Toolkit::WhitehatSentinelTask do
  describe "#run" do
    let(:api_client) { instance_double(Kenna::Toolkit::WhitehatSentinel::ApiClient, api_key_valid?: valid, sites: {}) }
    let(:key) { "0xdeadbeef" }
    let(:options) { { whitehat_api_key: key } }
    let(:valid) { true }

    subject(:task) { described_class.new }

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
end
