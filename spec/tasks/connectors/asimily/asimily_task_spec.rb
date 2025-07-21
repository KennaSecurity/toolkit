# frozen_string_literal: true

require 'rspec_helper'

RSpec.describe Kenna::Toolkit::Asimily::Task do
  let(:task) { described_class.new }
  let(:valid_options) do
    {
      asimily_api_endpoint: "https://example.asimily.com",
      asimily_user: "test_user",
      asimily_password: "test_password",
      asimily_page_size: 100,
      asimily_filter: "",
      kenna_api_host: "api.kennasecurity.com",
      kenna_api_key: "test_api_key",
      kenna_connector_id: 123,
      kenna_batch_size: 1000,
      output_directory: "output/asimily"
    }
  end

  describe '.metadata' do
    it 'returns correct task metadata' do
      metadata = described_class.metadata

      expect(metadata[:id]).to eq("asimily")
      expect(metadata[:name]).to eq("Asimily")
      expect(metadata[:description]).to eq("Pulls assets and vulnerabilities from Asimily")
      expect(metadata[:options]).to be_an(Array)
      expect(metadata[:options].length).to eq(10)
    end
  end

  describe '#run' do
    let(:client_double) { instance_double(Kenna::Toolkit::Asimily::Client) }

    before do
      allow(Kenna::Toolkit::Asimily::Client).to receive(:new).and_return(client_double)
      allow(client_double).to receive(:fetch_devices).and_return([[], false])
      allow(task).to receive(:kdi_connector_kickoff)
    end

    it 'initializes client with correct parameters' do
      expect(Kenna::Toolkit::Asimily::Client).to receive(:new).with(
        "https://example.asimily.com",
        "test_user",
        "test_password",
        100
      )

      task.run(valid_options)
    end

    it 'handles API errors gracefully' do
      allow(Kenna::Toolkit::Asimily::Client).to receive(:new).and_raise(
        Kenna::Toolkit::Asimily::Client::ApiError, "API connection failed"
      )

      expect(task).to receive(:fail_task).with("API connection failed")

      task.run(valid_options)
    end

    it 'handles standard errors gracefully' do
      allow(Kenna::Toolkit::Asimily::Client).to receive(:new).and_raise(
        StandardError, "Unexpected error"
      )

      expect(task).to receive(:fail_task).with("An error occurred: Unexpected error")

      task.run(valid_options)
    end
  end

  describe '#string_to_hash' do
    it 'converts string to hash correctly' do
      result = task.send(:string_to_hash, "key1=value1,key2=value2")
      expect(result).to eq({ "key1" => "value1", "key2" => "value2" })
    end

    it 'returns empty hash for blank input' do
      result = task.send(:string_to_hash, "")
      expect(result).to eq({})
    end
  end
end
