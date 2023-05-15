# frozen_string_literal: true

require 'rspec_helper'
require 'webmock/rspec'

RSpec.describe Kenna::Toolkit::Cylera::Client do
  let(:api_host) { 'cylera.host' }
  let(:api_user) { 'api_user' }
  let(:api_password) { 'api_password' }
  let(:token) { SecureRandom.hex }
  let(:headers) do
    {
      accept: 'application/json',
      Authorization: "Bearer #{token}"
    }
  end

  subject(:client) { described_class.new(api_host, api_user, api_password) }

  before do
    stub_request(:post, "https://#{api_host}/auth/login_user")
      .with(body: { email: api_user, password: api_password })
      .to_return_json(body: { token: }, status: 200)
  end

  describe '#get_risk_vulnerabilities' do
    let(:params) { { page_size: 20 } }

    before do
      expect(client).to receive(:http_get)
        .with("https://#{api_host}/risk/vulnerabilities?#{params.to_query}", headers)
        .and_return(response)
    end

    context 'when API request is successfull' do
      let(:response) { { vulnerabilities: [], total: 100, page: 0 }.to_json }

      it 'returns a response with vulnerabilities' do
        expect(client.get_risk_vulnerabilities(params)).to eq(JSON.parse(response))
      end
    end

    context 'when API request is failed' do
      let(:response) { nil }

      it 'raises an error' do
        expect { client.get_risk_vulnerabilities(params) }.to raise_error(described_class::ApiError)
      end
    end
  end

  describe '#get_risk_mitigations' do
    let(:vulnerability_name) { 'CVE-123' }

    before do
      expect(client).to receive(:http_get)
        .with("https://#{api_host}/risk/mitigations?vulnerability=#{vulnerability_name}", headers)
        .and_return(response)
    end

    context 'when API request is successfull' do
      let(:response) { { mitigations: [] }.to_json }

      it 'returns a response with mitigations' do
        expect(client.get_risk_mitigations(vulnerability_name)).to eq(JSON.parse(response))
      end
    end

    context 'when API request is failed' do
      let(:response) { nil }

      it 'raises an error' do
        expect { client.get_risk_mitigations(vulnerability_name) }.to raise_error(described_class::ApiError)
      end
    end
  end
end
