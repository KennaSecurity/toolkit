# frozen_string_literal: true

require 'rspec_helper'

RSpec.describe Kenna::Toolkit::CyleraTask do
  subject(:task) { described_class.new }

  describe '#run' do
    let(:options) do
      {
        cylera_api_host: 'cylera.host',
        cylera_api_user: 'api_user',
        cylera_api_password: 'api_pass',
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

    before { allow(Kenna::Api::Client).to receive(:new) { kenna_client } }

    it 'succeeds' do
      expect { task.run(options) }.to_not raise_error
    end

    context 'when the required param is missed' do
      let(:options) { {} }

      it 'exits the script' do
        expect { task.run(options) }.to raise_error(SystemExit) { |e| expect(e.status).to_not be_zero }
      end
    end

    context 'when the connector run fails' do
      let(:connector_run_success) { false }

      it 'exits the script' do
        expect { task.run(options) }.to raise_error(SystemExit) { |e| expect(e.status).to_not be_zero }
      end
    end

    context 'when the API errors' do
      before { allow_any_instance_of(Kenna::Toolkit::Cylera::Client).to receive(:http_get) }

      it 'exits the script' do
        expect { task.run(options) }.to raise_error(SystemExit) { |e| expect(e.status).to_not be_zero }
      end
    end

    context 'when time value is an unexpected format' do
      it 'exits the script' do
        expect { task.run(options.merge(cylera_last_seen_after: '60m')) }.to raise_error(RuntimeError)
      end
    end

    context 'when the incremental param present' do
      it 'calls the connector runs endpoint' do
        expect(kenna_client).to receive(:get_connector_runs)
        expect { task.run(options.merge(incremental: true)) }.to_not raise_error
      end
    end
  end
end
