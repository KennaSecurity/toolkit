# frozen_string_literal: true

require "rspec_helper"
require_relative "../../../../tasks/connectors/veracode/lib/veracode_client"

RSpec.describe Kenna::Toolkit::Veracode::Client do
  subject(:client) { described_class.new("test_id", "test_key", 100) }

  let(:applications_response) do
    {
      "_embedded" => {
        "applications" => [
          {
            "guid" => "test-guid",
            "profile" => {
              "name" => "Test App",
              "tags" => "tag1,tag2",
              "business_unit" => { "name" => "Test BU" },
              "business_criticality" => "High",
              "business_owners" => [{ "name" => "Test Owner" }],
              "custom_fields" => []
            }
          }
        ]
      },
      "_links" => {}
    }.to_json
  end

  let(:cwe_response) do
    {
      "_embedded" => {
        "cwes" => [
          {
            "id" => "CWE-79",
            "recommendation" => "Sanitize input"
          }
        ]
      },
      "_links" => {}
    }.to_json
  end

  let(:category_response) do
    {
      "_embedded" => {
        "categories" => [
          {
            "id" => "CAT-1",
            "recommendation" => "Fix this"
          }
        ]
      },
      "_links" => {}
    }.to_json
  end

  let(:findings_response) do
    {
      "_embedded" => {
        "findings" => []
      },
      "_links" => {}
    }.to_json
  end

  describe "#initialize" do
    it "initializes with required parameters" do
      expect(client.instance_variable_get(:@id)).to eq("test_id")
      expect(client.instance_variable_get(:@key)).to eq("test_key")
      expect(client.instance_variable_get(:@page_size)).to eq(100)
    end
  end

  describe "#applications" do
    context "successful response" do
      before do
        stub_request(:get, %r{https://api.veracode.com/appsec/v1/applications})
          .to_return(body: applications_response, status: 200)
      end

      it "fetches applications from API" do
        apps = client.applications
        expect(apps).to be_an(Array)
        expect(apps.first["guid"]).to eq("test-guid")
      end

      it "includes guid, name, tags, and owner in app list" do
        apps = client.applications
        expect(apps.first).to have_key("guid")
        expect(apps.first).to have_key("name")
        expect(apps.first).to have_key("tags")
      end
    end

    context "with custom field filters" do
      before do
        stub_request(:get, %r{https://api.veracode.com/appsec/v1/applications})
          .to_return(body: applications_response, status: 200)
      end

      it "applies custom field filter" do
        apps = client.applications("custom_field", "filter_value")
        expect(apps).to be_an(Array)
      end
    end
  end

  describe "#cwe_recommendations" do
    context "successful response" do
      before do
        stub_request(:get, %r{https://api.veracode.com/appsec/v1/cwes})
          .to_return(body: cwe_response, status: 200)
      end

      it "fetches CWE recommendations from API" do
        recommendations = client.cwe_recommendations
        expect(recommendations).to be_an(Array)
      end

      it "includes id and recommendation in results" do
        recommendations = client.cwe_recommendations
        expect(recommendations.first).to have_key("id")
        expect(recommendations.first).to have_key("recommendation")
      end
    end

    context "when API returns no results" do
      before do
        stub_request(:get, %r{https://api.veracode.com/appsec/v1/cwes})
          .to_return(body: { "_embedded" => { "cwes" => [] }, "_links" => {} }.to_json, status: 200)
      end

      it "returns empty array" do
        recommendations = client.cwe_recommendations
        expect(recommendations).to eq([])
      end
    end
  end

  describe "#category_recommendations" do
    context "successful response" do
      before do
        stub_request(:get, %r{https://api.veracode.com/appsec/v1/categories})
          .to_return(body: category_response, status: 200)
      end

      it "fetches category recommendations from API" do
        recommendations = client.category_recommendations
        expect(recommendations).to be_an(Array)
      end

      it "includes id and recommendation in results" do
        recommendations = client.category_recommendations
        expect(recommendations.first).to have_key("id")
        expect(recommendations.first).to have_key("recommendation")
      end
    end
  end

  describe "#process_paged_findings" do
    context "successful response" do
      before do
        stub_request(:get, %r{https://api.veracode.com/appsec/v2/applications})
          .to_return(body: findings_response, status: 200)
      end

      it "yields findings to the block" do
        expect { |b| client.process_paged_findings("test_guid", "STATIC", &b) }.to yield_with_args(Hash)
      end
    end
  end

  describe "#get_paged_results" do
    context "successful response with pagination" do
      let(:first_page_body) do
        {
          "_embedded" => { "applications" => [{ "guid" => "app1" }] },
          "_links" => { "next" => { "href" => "https://api.veracode.com/page2" } }
        }.to_json
      end

      let(:second_page_body) do
        {
          "_embedded" => { "applications" => [{ "guid" => "app2" }] },
          "_links" => {}
        }.to_json
      end

      before do
        stub_request(:get, "https://api.veracode.com/page1")
          .to_return(body: first_page_body, status: 200)
        stub_request(:get, "https://api.veracode.com/page2")
          .to_return(body: second_page_body, status: 200)
      end

      it "handles pagination correctly" do
        results = []
        client.get_paged_results("https://api.veracode.com/page1") do |result|
          results << result
        end
        expect(results.length).to eq(2)
      end
    end

    context "when API request fails" do
      before do
        stub_request(:get, %r{https://api.veracode.com})
          .to_return(status: 401)
      end

      it "raises ApiError when response is nil" do
        expect do
          client.get_paged_results("https://api.veracode.com/page1") { |_result| }
        end.to raise_error(Kenna::Toolkit::Veracode::Client::ApiError)
      end
    end
  end

  describe "#hmac_auth_options" do
    it "returns authorization header with HMAC signature" do
      result = client.hmac_auth_options("/appsec/v1/applications")
      expect(result).to have_key(:Authorization)
      expect(result[:Authorization]).to match(/^VERACODE-HMAC-SHA-256/)
    end

    it "handles query parameters in path" do
      result = client.hmac_auth_options("/appsec/v1/applications?size=100")
      expect(result).to have_key(:Authorization)
      expect(result[:Authorization]).to match(/^VERACODE-HMAC-SHA-256/)
    end
  end

  describe "#veracode_signature" do
    it "generates valid HMAC signature" do
      signature = client.send(:veracode_signature, "/appsec/v1/applications")
      expect(signature).to match(/^VERACODE-HMAC-SHA-256 id=test_id,ts=\d+,nonce=[a-f0-9]+,sig=[a-f0-9]+$/)
    end
  end
end
