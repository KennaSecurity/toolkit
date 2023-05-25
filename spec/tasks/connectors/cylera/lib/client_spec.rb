# frozen_string_literal: true

require 'rspec_helper'

RSpec.describe Kenna::Toolkit::Cylera::Client do
  let(:api_host) { 'cylera.host' }
  let(:api_user) { 'api_user' }
  let(:api_password) { 'api_password' }

  subject(:client) { described_class.new(api_host, api_user, api_password) }

  describe '#get_risk_vulnerabilities' do
    let(:params) { { page_size: 20 } }

    context 'when API request is successfull' do
      it 'returns a response with vulnerabilities' do
        expect(client.get_risk_vulnerabilities(params)['vulnerabilities']).to be_present
      end
    end

    context 'when API request is failed' do
      before { allow(client).to receive(:http_get) }

      it 'raises an error' do
        expect { client.get_risk_vulnerabilities(params) }.to raise_error(described_class::ApiError)
      end
    end
  end

  describe '#get_risk_mitigations' do
    let(:vulnerability_name) { 'CVE-123' }

    context 'when API request is successfull' do
      it 'returns a response with mitigations' do
        expect(client.get_risk_mitigations(vulnerability_name)['mitigations']).to be_present
      end
    end

    context 'when API request is failed' do
      before { allow(client).to receive(:http_get) }

      it 'raises an error' do
        expect { client.get_risk_mitigations(vulnerability_name) }.to raise_error(described_class::ApiError)
      end
    end
  end
end
