# frozen_string_literal: true

require 'rspec_helper'

RSpec.describe Kenna::Toolkit::SecurityScorecard do
  let(:security_scorecard) { described_class.new }

  describe "#ip?" do
    context "when given a valid ip input" do
      it "returns truthy for valid ipv4" do
        expect(security_scorecard.ip?('192.168.1.1')).to be_truthy
      end

      it "returns truthy for valid ipv6" do
        expect(security_scorecard.ip?('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).to be_truthy
      end
    end

    context "when given invalid ip input" do
      it "return false for incomplete ipv4" do
        expect(security_scorecard.ip?('00.32.123')).to be false
      end

      it "return false for string ips" do
        expect(security_scorecard.ip?('1234')).to be false
      end

      it "return false for nil input" do
        expect(security_scorecard.ip?(nil)).to be false
      end

      it "return false for empty input" do
        expect(security_scorecard.ip?('')).to be false
      end
    end
  end

  describe "#url" do
    context "when given valid url" do
      it "return true for valid url" do
        expect(security_scorecard.url?('https://example.com')).to be_truthy
      end
    end

    context "when given invalid url" do
      it "retrun false for empty string" do
        expect(security_scorecard.url?('')).to be false
      end

      it "return false when http or https is missing" do
        expect(security_scorecard.url?('example.com')).to be false
      end
    end
  end

  describe "#scc_issue_to_kdi_asset_hash" do
    let(:issue) do
      {
        "connection_attributes" => {
          "dst_ip" => "192.168.1.1",
          "dst_host" => "example.com",
          "dst_port" => 80
        },
        "hostname" => "example.com",
        "subdomain" => "sub.example.com",
        "common_name" => "example.com",
        "target" => "example.com",
        "ip_address" => "192.168.1.1",
        "src_ip" => "200.205.32.55",
        "initial_url" => "https://example.com",
        "url" => "https://example.com"
      }
    end

    context "when issue has valid attributes" do
      it "returns asset attributes hash" do
        result = security_scorecard.ssc_issue_to_kdi_asset_hash(issue)

        expect(result).to be_a(Hash)
        expect(result["tags"]).to include("SecurityScorecard")
        expect(result["hostname"]).to eq("example.com")
        expect(result["ip_address"]).to eq("192.168.1.1")
      end
    end

    context "when issue has missing attributes" do
      it "still returns asset hash when other attributes are present" do
        issue_with_missing_attributes = issue.dup
        issue_with_missing_attributes.delete("connection_attributes")
        result = security_scorecard.ssc_issue_to_kdi_asset_hash(issue_with_missing_attributes)

        expect(result).to be_a(Hash)
        expect(result["tags"]).to include("SecurityScorecard")
        expect(result["hostname"]).to eq("example.com") # from issue["hostname"]
        expect(result["ip_address"]).to eq("192.168.1.1") # from issue["ip_address"]
      end

      it "returns nil when no valid identifiers are found" do
        empty_issue = {}
        result = security_scorecard.ssc_issue_to_kdi_asset_hash(empty_issue)

        expect(result).to be_nil
      end

      it "returns nil when connection_attributes is not a hash" do
        invalid_issue = { "connection_attributes" => "not a hash" }
        result = security_scorecard.ssc_issue_to_kdi_asset_hash(invalid_issue)

        expect(result).to be_nil
      end
    end
  end

  describe "#ssc_issue_to_kdi_vuln_hash" do
    let(:issue) do
      {
        "connection_attributes" => {
          "dst_ip" => "127.0.0.1",
          "dst_port" => 8080
        },
        "vulnerability_id" => "12345",
        "cve" => "CVE-2023-12345",
        "port" => 80,
        "type" => "patching_cadence_high",
        "created_at" => "2023-10-01T12:00:00Z",
        "last_seen_at" => "2023-10-02T12:00:00Z",
        "issue_type_severity" => "High",
        "severity" => "High",
        "first_seen_time" => "2023-10-01T12:00:00Z",
        "last_seen_time" => "2023-10-02T12:00Z"
      }
    end

    context "test different issue type logic - patching_cadence and service_vuln" do
      context "when issue type includes patching_cadence or service_vuln" do
        let(:patching_cadence_issue) do
          {
            "connection_attributes" => {
              "dst_port" => 443
            },
            "vulnerability_id" => "VULN-12345",
            "cve" => "CVE-2023-12345",
            "type" => "patching_cadence_critical",
            "first_seen_time" => "2023-10-01T12:00:00Z",
            "last_seen_time" => "2023-10-02T12:00:00Z"
          }
        end

        let(:service_vuln_issue) do
          {
            "connection_attributes" => {
              "dst_port" => 22
            },
            "vulnerability_id" => "SSH-VULN-001",
            "type" => "service_vuln_ssh",
            "first_seen_time" => "2023-10-01T12:00:00Z",
            "last_seen_time" => "2023-10-02T12:00:00Z"
          }
        end

        it "returns correct vuln_attributes for patching_cadence issue" do
          vuln_attributes, _vuln_def_attributes = security_scorecard.ssc_issue_to_kdi_vuln_hash(patching_cadence_issue)

          expect(vuln_attributes["scanner_identifier"]).to eq("VULN-12345")
          expect(vuln_attributes["vuln_def_name"]).to eq("VULN-12345")
          expect(vuln_attributes["scanner_type"]).to eq("SecurityScorecard")
          expect(vuln_attributes["status"]).to eq("open")
          expect(vuln_attributes["port"]).to eq(443)
          expect(vuln_attributes["created_at"]).to eq("2023-10-01T12:00:00Z")
          expect(vuln_attributes["last_seen_at"]).to eq("2023-10-02T12:00:00Z")
        end

        it "returns correct vuln_def_attributes for patching_cadence issue" do
          _vuln_attributes, vuln_def_attributes = security_scorecard.ssc_issue_to_kdi_vuln_hash(patching_cadence_issue)

          expect(vuln_def_attributes["name"]).to eq("VULN-12345")
          expect(vuln_def_attributes["cve_identifiers"]).to eq("VULN-12345")
          expect(vuln_def_attributes["scanner_type"]).to eq("SecurityScorecard")
          expect(vuln_def_attributes["description"]).to eq("patching_cadence_critical")
        end

        it "returns correct attributes for service_vuln issue" do
          vuln_attributes, vuln_def_attributes = security_scorecard.ssc_issue_to_kdi_vuln_hash(service_vuln_issue)

          expect(vuln_attributes["scanner_identifier"]).to eq("SSH-VULN-001")
          expect(vuln_attributes["vuln_def_name"]).to eq("SSH-VULN-001")
          expect(vuln_attributes["port"]).to eq(22)
          expect(vuln_def_attributes["description"]).to eq("service_vuln_ssh")
        end

        it "falls back to cve when vulnerability_id is not present" do
          issue_with_cve = patching_cadence_issue.dup
          issue_with_cve.delete("vulnerability_id")
          issue_with_cve["cve"] = "CVE-2023-99999"

          vuln_attributes, _vuln_def_attributes = security_scorecard.ssc_issue_to_kdi_vuln_hash(issue_with_cve)

          expect(vuln_attributes["scanner_identifier"]).to eq("CVE-2023-99999")
          expect(vuln_attributes["vuln_def_name"]).to eq("CVE-2023-99999")
        end
      end

      context "when issue type does not include patching_cadence or service_vuln" do
        let(:other_issue) do
          {
            "type" => "ssl_certificate_issue",
            "issue_type_severity" => "medium",
            "severity" => "medium",
            "first_seen_time" => "2023-10-01T12:00:00Z",
            "last_seen_time" => "2023-10-02T12:00:00Z"
          }
        end

        before do
          # Mock the extract_vuln_def method since @fm is not present
          allow(security_scorecard).to receive(:extract_vuln_def).and_return(
            {
              "name" => "SSL Certificate Issue",
              "scanner_score" => 6,
              "description" => "SSL certificate vulnerability"
            }
          )
        end

        it "goes through the mapper logic for other issue types" do
          vuln_attributes, vuln_def_attributes = security_scorecard.ssc_issue_to_kdi_vuln_hash(other_issue)

          expect(vuln_attributes["scanner_identifier"]).to eq("ssl_certificate_issue")
          expect(vuln_attributes["scanner_type"]).to eq("SecurityScorecard")
          expect(vuln_attributes["scanner_score"]).to eq(6)
          expect(vuln_attributes["vuln_def_name"]).to eq("SSL Certificate Issue")
          expect(vuln_def_attributes["name"]).to eq("SSL Certificate Issue")
        end

        it "does not include port when port is not positive" do
          issue_with_zero_port = other_issue.dup
          issue_with_zero_port["port"] = 0

          vuln_attributes, _vuln_def_attributes = security_scorecard.ssc_issue_to_kdi_vuln_hash(issue_with_zero_port)

          expect(vuln_attributes).not_to have_key("port")
        end
      end
    end
  end

  describe "#extract_vuln_def" do
    let(:issue) do
      {
        "type" => "ssl_certificate_issue",
        "issue_type_severity" => "High"
      }
    end

    before do
      allow(security_scorecard).to receive(:map_ssc_to_kdi_severity).and_return(7)
    end

    it "returns vulnerability definition hash with correct attributes" do
      result = security_scorecard.extract_vuln_def(issue)

      expect(result["name"]).to eq("ssl_certificate_issue")
      expect(result["scanner_score"]).to eq(7)
      expect(result["override_score"]).to eq(70)
      expect(result["description"]).to eq("Ssl certificate issue")
      expect(result["scanner_type"]).to eq("SecurityScorecard")
    end

    it "falls back to severity when issue_type_severity is missing" do
      issue_without_type_severity = { "type" => "test", "severity" => "Medium" }

      expect(security_scorecard).to receive(:map_ssc_to_kdi_severity).with("Medium")
      security_scorecard.extract_vuln_def(issue_without_type_severity)
    end
  end

  describe "#map_ssc_to_kdi_severity" do
    it "returns 3 for low severity" do
      expect(security_scorecard.map_ssc_to_kdi_severity("low")).to eq(3)
    end

    it "returns 6 for medium severity" do
      expect(security_scorecard.map_ssc_to_kdi_severity("medium")).to eq(6)
    end

    it "returns 10 for high severity" do
      expect(security_scorecard.map_ssc_to_kdi_severity("high")).to eq(10)
    end

    it "returns 0 for unknown severity" do
      expect(security_scorecard.map_ssc_to_kdi_severity("critical")).to eq(0)
      expect(security_scorecard.map_ssc_to_kdi_severity("unknown")).to eq(0)
      expect(security_scorecard.map_ssc_to_kdi_severity(nil)).to eq(0)
    end
  end

  describe "#run" do
    let(:client) { instance_double(Kenna::Toolkit::Ssc::Client) }
    let(:options) do
      {
        ssc_api_key: "test_api_key",
        ssc_domain: "example.com",
        ssc_exclude_severity: "info,low",
        output_directory: "output/security_scorecard"
      }
    end

    before do
      allow(Kenna::Toolkit::Ssc::Client).to receive(:new).and_return(client)
      allow(client).to receive(:successfully_authenticated?).and_return(true)
      allow(client).to receive(:portfolios).and_return({ "entries" => [] })
      allow(security_scorecard).to receive(:print_good)
      allow(security_scorecard).to receive(:print_debug)
      allow(security_scorecard).to receive(:create_kdi_asset_vuln)
      allow(security_scorecard).to receive(:create_kdi_vuln_def)
      allow(security_scorecard).to receive(:kdi_upload)
    end

    context "when authentication fails" do
      before do
        allow(client).to receive(:successfully_authenticated?).and_return(false)
        allow(client).to receive(:types_by_factors).and_return([])
      end

      it "fails the task" do
        expect(security_scorecard).to receive(:fail_task).with("Unable to proceed, invalid key for Security Scorecard?")
        security_scorecard.run(options)
      end
    end

    context "when using ssc_domain" do
      let(:issue_types) { [{ "type" => "ssl_issue", "severity" => "medium", "detail_url" => "test_url" }] }
      let(:issues) { [{ "id" => 1, "hostname" => "example.com" }] }

      before do
        allow(client).to receive(:types_by_factors).and_return(issue_types)
        allow(client).to receive(:issues_by_factors).and_return({ "entries" => issues })
        allow(security_scorecard).to receive(:ssc_issue_to_kdi_asset_hash).and_return({ "hostname" => "example.com" })
        allow(security_scorecard).to receive(:ssc_issue_to_kdi_vuln_hash).and_return([{}, {}])
      end

      it "processes issues for the domain" do
        expect(client).to receive(:types_by_factors).with("example.com")
        expect(client).to receive(:issues_by_factors).with("test_url")
        security_scorecard.run(options)
      end
    end

    context "when using portfolio_ids" do
      let(:portfolio_options) do
        options.merge(ssc_domain: nil, ssc_portfolio_ids: "123")
      end
      let(:companies) { { "entries" => [{ "domain" => "example.com" }] } }

      before do
        allow(client).to receive(:companies_by_portfolio).and_return(companies)
        allow(client).to receive(:types_by_factors).and_return([])
      end

      it "processes companies in the portfolio" do
        expect(client).to receive(:companies_by_portfolio).with("123")
        security_scorecard.run(portfolio_options)
      end
    end
  end
end