# frozen_string_literal: true

require "rspec_helper"
require_relative "../../../../tasks/connectors/veracode_asset_vulns/lib/veracode_av_client"

RSpec.describe Kenna::Toolkit::VeracodeAV::Client do
  subject(:client) do
    described_class.new(
      "test_id",
      "test_key",
      "/tmp",
      "test_file.json",
      "https://api.kennasecurity.com",
      "12345",
      "api_key",
      "1-10,2-20,3-30,4-40,5-50"
    )
  end

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

  let(:static_findings_response) do
    {
      "_embedded" => {
        "findings" => [
          {
            "scan_type" => "STATIC",
            "issue_id" => "issue-static-1",
            "description" => "Static finding",
            "violates_policy" => true,
            "finding_details" => {
              "file_name" => "app/models/user.rb",
              "severity" => 5,
              "finding_category" => { "id" => "CAT-1", "name" => "Category 1", "href" => "/categories/CAT-1" },
              "cwe" => { "id" => "CWE-79", "name" => "XSS", "href" => "/cwes/CWE-79" }
            },
            "finding_status" => {
              "status" => "OPEN",
              "first_found_date" => "2024-01-01T00:00:00Z",
              "last_seen_date" => "2024-01-02T00:00:00Z"
            }
          }
        ]
      },
      "_links" => {}
    }.to_json
  end

  let(:sca_findings_response) do
    {
      "_embedded" => {
        "findings" => [
          {
            "scan_type" => "SCA",
            "description" => "SCA finding",
            "violates_policy" => false,
            "finding_details" => {
              "component_filename" => "rack-2.2.8.gem",
              "severity" => 4,
              "cve" => { "name" => "CVE-2024-0001", "href" => "/cves/CVE-2024-0001" },
              "cwe" => { "id" => "CWE-89", "name" => "SQL Injection", "href" => "/cwes/CWE-89" }
            },
            "finding_status" => {
              "status" => "CLOSED",
              "first_found_date" => "2024-02-01T00:00:00Z",
              "last_seen_date" => "2024-02-02T00:00:00Z"
            }
          }
        ]
      },
      "_links" => {}
    }.to_json
  end

  describe "#initialize" do
    it "initializes with required parameters" do
      expect(client.instance_variable_get(:@id)).to eq("test_id")
      expect(client.instance_variable_get(:@key)).to eq("test_key")
      expect(client.instance_variable_get(:@output_dir)).to eq("/tmp")
      expect(client.instance_variable_get(:@filename)).to eq("test_file.json")
      expect(client.instance_variable_get(:@score_map)).to eq({ "1" => "10", "2" => "20", "3" => "30", "4" => "40", "5" => "50" })
    end
  end

  describe "#build_score_map" do
    it "builds a score map from comma-separated values" do
      score_map = client.build_score_map("1-10,2-20,3-30")
      expect(score_map).to eq({ "1" => "10", "2" => "20", "3" => "30" })
    end

    it "raises error for invalid score mapping with non-numeric score" do
      expect do
        client.build_score_map("1-abc,2-20")
      end.to raise_error(SystemExit)
    end

    it "raises error for score outside 0-100 range" do
      expect do
        client.build_score_map("1-101,2-20")
      end.to raise_error(SystemExit)
    end
  end

  describe "#applications" do
    context "successful response" do
      before do
        stub_request(:get, %r{https://api\.veracode\.com/appsec/v1/applications})
          .to_return(body: applications_response, status: 200)
      end

      it "fetches applications from API" do
        apps = client.applications(100)
        expect(apps).to be_an(Array)
        expect(apps.first["guid"]).to eq("test-guid")
      end

      it "includes tags and owner information" do
        apps = client.applications(100)
        expect(apps.first["tags"]).to be_an(Array)
        expect(apps.first["owner"]).to eq("Test Owner")
      end
    end

    context "when http_get returns nil" do
      before do
        allow(client).to receive(:http_get).and_return(nil)
      end

      it "returns nil when response is nil" do
        apps = client.applications(100)
        expect(apps).to be_nil
      end
    end

    context "with custom field filters" do
      before do
        stub_request(:get, %r{https://api\.veracode\.com/appsec/v1/applications})
          .to_return(body: applications_response, status: 200)
      end

      it "applies custom field filter" do
        apps = client.applications(100, "custom_field", "filter_value")
        expect(apps).to be_an(Array)
      end
    end
  end

  describe "#cwe_recommendations" do
    context "successful response" do
      before do
        stub_request(:get, %r{https://api\.veracode\.com/appsec/v1/cwes})
          .to_return(body: cwe_response, status: 200)
      end

      it "fetches CWE recommendations from API" do
        client.cwe_recommendations(100)
        cwe_recs = client.instance_variable_get(:@cwe_recommendations)
        expect(cwe_recs).to be_an(Array)
        expect(cwe_recs.first["id"]).to eq("CWE-79")
      end
    end

    context "when http_get returns nil" do
      before do
        allow(client).to receive(:http_get).and_return(nil)
      end

      it "returns nil when response is nil" do
        result = client.cwe_recommendations(100)
        expect(result).to be_nil
      end
    end
  end

  describe "#category_recommendations" do
    context "successful response" do
      before do
        stub_request(:get, %r{https://api\.veracode\.com/appsec/v1/categories})
          .to_return(body: category_response, status: 200)
      end

      it "fetches category recommendations from API" do
        client.category_recommendations(100)
        cat_recs = client.instance_variable_get(:@category_recommendations)
        expect(cat_recs).to be_an(Array)
        expect(cat_recs.first["id"]).to eq("CAT-1")
      end
    end

    context "when http_get returns nil" do
      before do
        allow(client).to receive(:http_get).and_return(nil)
      end

      it "returns nil when response is nil" do
        result = client.category_recommendations(100)
        expect(result).to be_nil
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

  describe "pagination handling" do
    context "with multiple pages of applications" do
      let(:first_page) do
        {
          "_embedded" => {
            "applications" => [{ "guid" => "app1", "profile" => { "name" => "App 1", "tags" => nil, "business_unit" => { "name" => "BU1" }, "business_criticality" => nil, "business_owners" => [], "custom_fields" => [] } }]
          },
          "_links" => { "next" => { "href" => "https://api.veracode.com/page2" } }
        }.to_json
      end

      let(:second_page) do
        {
          "_embedded" => {
            "applications" => [{ "guid" => "app2", "profile" => { "name" => "App 2", "tags" => nil, "business_unit" => { "name" => "BU2" }, "business_criticality" => nil, "business_owners" => [], "custom_fields" => [] } }]
          },
          "_links" => {}
        }.to_json
      end

      before do
        stub_request(:get, "https://api.veracode.com/appsec/v1/applications?size=100")
          .to_return(body: first_page, status: 200)
        stub_request(:get, "https://api.veracode.com/page2")
          .to_return(body: second_page, status: 200)
      end

      it "handles paginated application results" do
        apps = client.applications(100)
        expect(apps.length).to eq(2)
        expect(apps.map { |a| a["guid"] }).to contain_exactly("app1", "app2")
      end
    end
  end

  describe "retry options" do
    it "uses retry options for HTTP requests" do
      allow(client).to receive(:http_get).and_call_original
      stub_request(:get, %r{https://api\.veracode\.com/appsec/v1/cwes})
        .to_return(body: cwe_response, status: 200)

      client.cwe_recommendations(100)
      expect(client).to have_received(:http_get)
    end
  end

  describe "#get_findings" do
    it "uses the retry-enabled http_get call for static findings" do
      client.instance_variable_set(:@category_recommendations, [{ "id" => "CAT-1", "recommendation" => "Fix this" }])
      client.instance_variable_set(:@cwe_recommendations, [{ "id" => "CWE-79", "recommendation" => "Sanitize input" }])

      allow(client).to receive(:http_get).and_return(instance_double("Response", body: static_findings_response))
      allow(client).to receive(:create_kdi_asset_vuln)
      allow(client).to receive(:create_kdi_vuln_def)

      client.get_findings("app-guid", "Test App", [], "Test Owner", 100, "STATIC")

      expect(client).to have_received(:http_get).with(
        "https://api.veracode.com/appsec/v2/applications/app-guid/findings?size=100&scan_type=STATIC",
        {},
        5,
        true,
        hmac_client: client,
        retry_options: described_class::RETRY_OPTIONS_504_ONLY
      )
    end
  end

  describe "#get_findings_sca" do
    it "uses the retry-enabled http_get call for SCA findings" do
      allow(client).to receive(:http_get).and_return(instance_double("Response", body: sca_findings_response))
      allow(client).to receive(:create_kdi_asset_vuln)
      allow(client).to receive(:create_kdi_vuln_def)

      client.get_findings_sca("app-guid", "Test App", [], "Test Owner", 100)

      expect(client).to have_received(:http_get).with(
        "https://api.veracode.com/appsec/v2/applications/app-guid/findings?size=100&scan_type=SCA",
        {},
        5,
        true,
        hmac_client: client,
        retry_options: described_class::RETRY_OPTIONS_504_ONLY
      )
    end
  end
end
