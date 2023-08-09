# frozen_string_literal: true

require 'rspec_helper'

RSpec.describe Kenna::Toolkit::Cylera::Client do
  let(:api_host) { 'cylera.host' }
  let(:api_user) { 'api_user' }
  let(:api_password) { 'api_password' }

  subject(:client) { described_class.new(api_host, api_user, api_password) }

  describe '#get_inventory_devices' do
    let(:params) { { page: 0, page_size: 100 } }

    context 'when API request is successful' do
      it 'returns a response with devices' do
        VCR.use_cassette('cylera') do
          expect(client.get_inventory_devices(params)['devices']).to be_present
        end
      end
    end

    context 'when API request is failed' do
      it 'raises an error' do
        VCR.use_cassette('cylera') do
          allow(client).to receive(:http_get)
          expect { client.get_inventory_devices(params) }.to raise_error(described_class::ApiError)
        end
      end
    end
  end

  describe '#get_risk_vulnerabilities' do
    let(:params) { { page: 0, page_size: 100 } }

    context 'when API request is successful' do
      it 'returns a response with vulnerabilities' do
        VCR.use_cassette('cylera') do
          expect(client.get_risk_vulnerabilities(params)['vulnerabilities']).to be_present
        end
      end
    end

    context 'when API request is failed' do
      it 'raises an error' do
        VCR.use_cassette('cylera') do
          allow(client).to receive(:http_get)
          expect { client.get_risk_vulnerabilities(params) }.to raise_error(described_class::ApiError)
        end
      end
    end
  end

  describe '#get_risk_mitigations' do
    let(:vulnerability_name) { 'CVE-2000-0761' }

    context 'when API request is successful' do
      it 'returns a response with mitigations' do
        VCR.use_cassette('cylera') do
          expect(client.get_risk_mitigations(vulnerability_name)['mitigations']).to be_present
        end
      end
    end

    context 'when API request is failed' do
      it 'raises an error' do
        VCR.use_cassette('cylera') do
          allow(client).to receive(:http_get)
          expect { client.get_risk_mitigations(vulnerability_name) }.to raise_error(described_class::ApiError)
        end
      end
    end
  end
end
