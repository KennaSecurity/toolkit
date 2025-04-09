# frozen_string_literal: true

require "rspec_helper"

RSpec.describe Kenna::Toolkit::SynackTask do
  subject(:task) { described_class.new }

  describe "#run" do
    let(:options) do
      {
        synack_api_host: 'api.synack.com',
        synack_api_token: 'abc123',
        kenna_api_key: 'api_key',
        kenna_api_host: 'kenna.example.com',
        kenna_connector_id: '12'
      }
    end
    let(:connector_run_success) { true }
    let(:kenna_client) do
      instance_double(
        Kenna::Api::Client,
        upload_to_connector: { 'data_file' => 12 },
        run_files_on_connector: { 'success' => connector_run_success },
        get_connector_runs: { results: [{ success: true, start_time: Time.now.to_s }] }
      )
    end
    let(:filter) { '' }

    before do
      stub_request(:get, "https://#{options[:synack_api_host]}/v1/vulnerabilities")
        .with(query: hash_including)
        .to_return do |request|
          page_number = WebMock::Util::QueryMapper.query_to_values(URI(request.uri).query)["page"]["number"]
          { body: read_fixture_file("response-#{page_number}.json") }
        end
      allow(Kenna::Api::Client).to receive(:new) { kenna_client }
      spy_on_accumulators
    end

    it 'succeeds' do
      expect { task.run(options) }.to_not raise_error
    end

    context 'when the required param is missed' do
      let(:options) { {} }

      it 'exits the script' do
        expect { task.run(options) }.to raise_error(SystemExit) { |e| expect(e.status).to_not be_zero }
      end
    end

    it 'creates assets with vulnerabilities' do
      task.run(options)
      expect(task.assets).to include(
        {
          "application" => "SYNACK-DEMO-W002",
          "ip_address" => "248.252.142.161",
          "tags" => [],
          "vulns" => [
            { "closed_at" => "2024-06-12-18:30:17",
              "created_at" => "2023-10-19-12:28:39",
              "last_seen_at" => "2025-04-09",
              "scanner_identifier" => "synack-demo-w002-2",
              "scanner_score" => 6,
              "scanner_type" => "Synack",
              "status" => "closed",
              "vuln_def_name" =>
                "Insufficient Authorization Controls on Employee Document URLs" }
          ]
        }
      )
    end

    it 'creates vuln_defs' do
      task.run(options)
      expect(task.vuln_defs).to include(
        hash_including(
          "name" => "Insufficient Authorization Controls on Employee Document URLs",
          "scanner_identifier" => "synack-demo-w002-2",
          "scanner_type" => "Synack",
          "scanner_score" => 6,
          "description" =>
            a_string_including("There is an Insecure Direct Object Reference vulnerability due to"),
          "solution" =>
            a_string_including("The /api/empl_document/17/ endpoint should check that the user requesting a document")
        )
      )
    end

    it 'creates the output file with the correct number of assets and vulnerabilities' do
      task.run(options)
      expect(File).to exist("output/synack/synack_batch_1.json")
      output = JSON.parse(File.read("output/synack/synack_batch_1.json"))
      assets = output['assets']
      expect(assets).to be_an(Array)
      expect(assets.size).to eq(46)
      expect(assets.sum { |asset| asset['vulns'].size }).to eq(48)
    end

    context 'when batch_size is set' do
      let(:options_with_batch_size) do
        options.merge(batch_size: 2)
      end

      it 'uses it in the page[size] query param for the API request' do
        task.run(options_with_batch_size)
        expect(a_request(:get, "https://#{options[:synack_api_host]}/v1/vulnerabilities")
          .with(query: hash_including("page" => { "size" => "2", "number" => "1" }))).to have_been_made
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end

  def read_fixture_file(filename)
    File.read(File.join(%w[spec tasks connectors synack fixtures], filename))
  end
end
