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

  describe "#initialize" do
    it "initializes with required parameters" do
      expect(client.instance_variable_get(:@id)).to eq("test_id")
      expect(client.instance_variable_get(:@key)).to eq("test_key")
      expect(client.instance_variable_get(:@output_dir)).to eq("/tmp")
      expect(client.instance_variable_get(:@filename)).to eq("test_file.json")
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
      end.to raise_error(RuntimeError)
    end

    it "raises error for score outside 0-100 range" do
      expect do
        client.build_score_map("1-101,2-20")
      end.to raise_error(RuntimeError)
    end
  end

  describe "#applications" do
    context "successful response" do
      before do
        allow(client).to receive(:http_get).and_return(
          double(body: File.read("#{$basedir}/spec/tasks/connectors/veracode_findings/fixtures/applications.json"))
        )
      end

      it "fetches applications from API" do
        apps = client.applications(100)
        expect(apps).to be_an(Array)
        expect(client).to have_received(:http_get)
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
  end

  describe "#cwe_recommendations" do
    context "successful response" do
      before do
        allow(client).to receive(:http_get).and_return(
          double(body: File.read("#{$basedir}/spec/tasks/connectors/veracode_findings/fixtures/cwe_recommendations.json"))
        )
      end

      it "fetches CWE recommendations from API" do
        client.cwe_recommendations(100)
        expect(client.instance_variable_get(:@cwe_recommendations)).to be_an(Array)
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
        allow(client).to receive(:http_get).and_return(
          double(body: File.read("#{$basedir}/spec/tasks/connectors/veracode_findings/fixtures/category_recommendations.json"))
        )
      end

      it "fetches category recommendations from API" do
        client.category_recommendations(100)
        expect(client.instance_variable_get(:@category_recommendations)).to be_an(Array)
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
end
