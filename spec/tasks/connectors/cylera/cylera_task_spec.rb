# frozen_string_literal: true

require 'rspec_helper'

RSpec.describe Kenna::Toolkit::CyleraTask do
  subject(:task) { described_class.new }

  describe '#run' do
    let(:api_client) { instance_double(Kenna::Toolkit::Cylera::Client, get_risk_vulnerabilities: { 'vulnerabilities' => [vuln], 'total' => 100, 'page' => 0 }, get_risk_mitigations: { 'mitigations' => [] }) }
    let(:vuln) do
      {
        'ip_address' => '10.125.51.5',
        'mac_address' => '5c:f3:fc:8b:50:00',
        'model' => 'SoftLab Laboratory Information System',
        'type' => 'Laboratory Information System',
        'vendor' => 'SCC Soft Computer',
        'class' => 'Medical',
        'vulnerability_name' => 'CVE-2000-0761',
        'vulnerability_category' => 'Security',
        'first_seen' => 1651505826,
        'last_seen' => 1651505826,
        'severity' => 'Medium',
        'status' => 'Open',
        'confidence' => 'High'
      }
    end
    let(:key) { SecureRandom.hex }
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
      allow(Kenna::Toolkit::Cylera::Client).to receive(:new) { api_client }
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
      before { allow(api_client).to receive(:get_risk_vulnerabilities).and_raise(Kenna::Toolkit::Cylera::Client::ApiError) }

      it 'exits the script' do
        expect { task.run(options) }.to raise_error(SystemExit) { |e| expect(e.status).to_not be_zero }
      end
    end
  end
end
