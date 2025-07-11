# frozen_string_literal: true

require 'rspec_helper'

RSpec.describe Kenna::Toolkit::Ssc::Client do
  let(:key) { 'Ssc-key' }
  let(:baseapi) { 'https://api.securityscorecard.io' }

  subject(:client) { described_class.new(key) }

  describe "#successfully_authenticated?" do
    context "when api endpoint return successful portfolios data with entries" do
      before do
        response_body = '{"entries":[{"id":"123", "name":"random_name"}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns true" do
        expect(client.successfully_authenticated?).to be true
      end
    end

    context "when api endpoint return json without entries" do
      before do
        response_body = '{"some_key": "wrong_value"}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns false" do
        expect(client.successfully_authenticated?).to be false
      end
    end

    context "when api endpoint return nil" do
      before do
        allow(client).to receive(:http_get).and_return(nil)
      end

      it "returns false" do
        expect(client.successfully_authenticated?).to be false
      end
    end
  end

  describe "#portfolios" do
    context "when API request is successful" do
      before do
        response_body = '{"entries":[{"id":"123", "name":"test_portfolio"}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns parsed JSON response" do
        result = client.portfolios
        expect(result).to eq({ "entries" => [{ "id" => "123", "name" => "test_portfolio" }] })
      end
    end

    context "when API returns nil" do
      before do
        allow(client).to receive(:http_get).and_return(nil)
      end

      it "returns nil" do
        expect(client.portfolios).to be_nil
      end
    end
  end

  describe "#companies_by_portfolio" do
    let(:portfolio_id) { '123' }

    context "When API request is successful" do
      before do
        response_body = '{"entries":[{"domain":"test1.com","name":"Test Company"}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns response with entries and domains" do
        expect(client.companies_by_portfolio(portfolio_id)).to eq({ "entries" => [{ "domain" => "test1.com", "name" => "Test Company" }] })
      end
    end

    context "When API return empty array" do
      before do
        response_body = '{"entries": []}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "return response but with empty array" do
        expect(client.companies_by_portfolio(portfolio_id)).to eq({ "entries" => [] })
      end
    end

    context "When API returns malformed response body" do
      before do
        response_body = 'bad response body'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns error hash instead of raising exception" do
        result = client.companies_by_portfolio(portfolio_id)
        expect(result).to eq({ "error" => "Invalid JSON response", "raw_body" => "bad response body" })
      end
    end
  end

  describe "#issues_by_type_for_company" do
    let(:company_id) { '123' }
    let(:itype) { "patching_cadence_low" }

    context "when API request is successful" do
      before do
        response_body = '{"entries": [{"key":"value","key2":"value2"}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "return response with entries" do
        result = client.issues_by_type_for_company(company_id, itype)
        expect(result).to eq({ "entries" => [{ "key" => "value", "key2" => "value2" }] })
      end
    end

    context "When API return empty array" do
      before do
        response_body = '{"entries": []}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "return response but with empty array" do
        expect(client.issues_by_type_for_company(company_id, itype)).to eq({ "entries" => [] })
      end
    end

    context "when API returns nil" do
      before do
        allow(client).to receive(:http_get).and_return(nil)
      end

      it "returns nil" do
        expect(client.issues_by_type_for_company(company_id, itype)).to be_nil
      end
    end
  end

  describe "#issues_by_factors" do
    let(:detail_url) { 'https://api.securityscorecard.io/companies/123/factors/patching_cadence/issues' }

    context "when API request is successful" do
      before do
        response_body = '{"entries": [{"issue_type":"patching_cadence_low","severity":"high","count":5}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns response with entries" do
        result = client.issues_by_factors(detail_url)
        expect(result).to eq({ "entries" => [{ "issue_type" => "patching_cadence_low", "severity" => "high", "count" => 5 }] })
      end
    end

    context "when API returns empty array" do
      before do
        response_body = '{"entries": []}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns response but with empty array" do
        expect(client.issues_by_factors(detail_url)).to eq({ "entries" => [] })
      end
    end

    context "when API returns nil" do
      before do
        allow(client).to receive(:http_get).and_return(nil)
      end

      it "returns nil" do
        expect(client.issues_by_factors(detail_url)).to be_nil
      end
    end
  end

  describe "#types_by_factors" do
    let(:company_id) { '123' }

    context "when API request is successful" do
      before do
        response_body = '{"entries":[{"issue_summary":[{"type":"patching_cadence_low","severity":"high"},{"type":"ssl_certificate_low","severity":"medium"}]},{"issue_summary":[{"type":"network_security_low","severity":"low"}]}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns array of issue types from all factors" do
        result = client.types_by_factors(company_id)
        expected_types = [
          { "type" => "patching_cadence_low", "severity" => "high" },
          { "type" => "ssl_certificate_low", "severity" => "medium" },
          { "type" => "network_security_low", "severity" => "low" }
        ]
        expect(result).to eq(expected_types)
      end
    end

    context "when API returns factors with empty issue_summary" do
      before do
        response_body = '{"entries":[{"issue_summary":[]},{"issue_summary":[]}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns empty array" do
        expect(client.types_by_factors(company_id)).to eq([])
      end
    end

    context "when API returns factors without issue_summary" do
      before do
        response_body = '{"entries":[{"other_field":"value"},{"another_field":"value2"}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns empty array" do
        expect(client.types_by_factors(company_id)).to eq([])
      end
    end

    context "when API returns empty entries" do
      before do
        response_body = '{"entries":[]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns empty array" do
        expect(client.types_by_factors(company_id)).to eq([])
      end
    end

    context "when API returns nil" do
      before do
        allow(client).to receive(:http_get).and_return(nil)
      end

      it "returns empty array" do
        expect(client.types_by_factors(company_id)).to eq([])
      end
    end
  end

  describe "#issue_types_list" do
    let(:ssc_exclude_severity) { ['low'] }

    context "when API request is successful" do
      before do
        response_body = '{"entries":[{"key":"patching_cadence_low","severity":"high"},{"key":"ssl_certificate_low","severity":"medium"},{"key":"network_security_low","severity":"low"},{"key":"malware_detection","severity":"critical"}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns array of keys excluding specified severities" do
        result = client.issue_types_list(ssc_exclude_severity)
        expected_keys = ["patching_cadence_low", "ssl_certificate_low", "malware_detection"]
        expect(result).to eq(expected_keys)
      end
    end

    context "when excluding multiple severities" do
      let(:ssc_exclude_severity) { ['low', 'medium'] }

      before do
        response_body = '{"entries":[{"key":"patching_cadence_low","severity":"high"},{"key":"ssl_certificate_low","severity":"medium"},{"key":"network_security_low","severity":"low"},{"key":"malware_detection","severity":"critical"}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns array of keys excluding all specified severities" do
        result = client.issue_types_list(ssc_exclude_severity)
        expected_keys = ["patching_cadence_low", "malware_detection"]
        expect(result).to eq(expected_keys)
      end
    end

    context "when excluding all severities" do
      let(:ssc_exclude_severity) { ['low', 'medium', 'high', 'critical'] }

      before do
        response_body = '{"entries":[{"key":"patching_cadence_low","severity":"high"},{"key":"ssl_certificate_low","severity":"medium"},{"key":"network_security_low","severity":"low"},{"key":"malware_detection","severity":"critical"}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns empty array" do
        result = client.issue_types_list(ssc_exclude_severity)
        expect(result).to eq([])
      end
    end

    context "when not excluding any severities" do
      let(:ssc_exclude_severity) { [] }

      before do
        response_body = '{"entries":[{"key":"patching_cadence_low","severity":"high"},{"key":"ssl_certificate_low","severity":"medium"}]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns all keys" do
        result = client.issue_types_list(ssc_exclude_severity)
        expected_keys = ["patching_cadence_low", "ssl_certificate_low"]
        expect(result).to eq(expected_keys)
      end
    end

    context "when API returns empty entries" do
      before do
        response_body = '{"entries":[]}'
        mock_response = double("response", body: response_body)
        allow(client).to receive(:http_get).and_return(mock_response)
      end

      it "returns empty array" do
        expect(client.issue_types_list(ssc_exclude_severity)).to eq([])
      end
    end
  end
end