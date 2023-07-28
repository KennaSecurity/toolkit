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
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { 'data_file' => 12 }, run_files_on_connector: { 'success' => connector_run_success }) }

    before do
      allow(Kenna::Api::Client).to receive(:new) { kenna_client }
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
      let(:options) do
        {
          cylera_api_host: 'cylera.host',
          cylera_api_user: 'api_user',
          cylera_api_password: 'api_pass',
          kenna_api_key: 'api_key',
          kenna_api_host: 'kenna.example.com',
          kenna_connector_id: '12',
          cylera_last_seen_after: '60m'
        }
      end

      it 'exits the script' do
        expect { task.run(options) }.to raise_error(RuntimeError)
      end
    end
  end
end
