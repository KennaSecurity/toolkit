require 'rspec_helper'

RSpec.describe Kenna::Toolkit::Ssc::Client do 
  let(:key) {'Ssc-key'}
  let(:baseapi) {'https://api.securityscorecard.io'}

  subject(:client) { described_class.new(key) }

  describe "#successfully_authenticated?" do
    context "when api endpoint return successul potforlios data with entries" do
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

        it "return false" do 
            expect(client.successfully_authenticated?).to be false
        end
    end

    context "when api endpoint return nil" do 
        before do 
            allow(client).to receive(:http_get).and_return(nil)
        end

        it "return false" do 
            expect(client.successfully_authenticated?).to be false
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
            expect(client.companies_by_portfolio(portfolio_id)).to eq({"entries" => [{"domain" => "test1.com", "name" => "Test Company"}]})
        end
    end

    context "When API return empty array" do 
        before do 
            response_body = '{"entries": []}'
            mock_response = double("response", body: response_body)
            allow(client).to receive(:http_get).and_return(mock_response)
        end

        it "return response but with empty array" do
            expect(client.companies_by_portfolio(portfolio_id)).to eq({"entries" => []})
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
            expect(result).to eq({"error" => "Invalid JSON response", "raw_body" => "bad response body"})
        end
    end
  end

  describe "#issues_by_type_for_company" do
    let(:company_id) { '123' }
    let(:itype) {"patching_cadence_low"}

    context "when API request is successful" do
         before do 
            response_body = '{"entries": [{"key":"value","key2":"value2"}]}'
            mock_response = double("response", body: response_body)
            allow(client).to receive(:http_get).and_return(mock_response)
        end

        it "return response with entries" do 
            result = client.issues_by_type_for_company(company_id, itype)
            expect(result).to eq({"entries" => [{"key" => "value","key2" => "value2"}]})
        end
    end
  end

end


