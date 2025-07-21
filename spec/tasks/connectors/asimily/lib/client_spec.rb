# frozen_string_literal: true

require 'rspec_helper'

RSpec.describe Kenna::Toolkit::Asimily::Client do
    let(:base_url) { 'example.com' }
    let(:username) { 'user' }
    let(:password) { 'pass' }
    let(:page_size) { 10 }

    subject(:client) { described_class.new(base_url, username, password, page_size) }

    describe "#fetch_devices" do
        let(:filters) { { filter: 'test' } }
        let(:current_page) { 0 }

        before do
            allow(client).to receive(:http_get).and_return(double(body: '{"content": [], "totalElements": 0, "last": true}'))
        end

        it "fetches devices with the correct parameters" do
            devices, has_more_pages = client.fetch_devices(page_size, current_page, filters)
            expect(devices).to eq([])
            expect(has_more_pages).to be false
        end
    end

    describe "#fetch_vulnerabilities" do
        let(:device_id) { 123 }

        before do
            mock_response_body = [
            {
                "cves" => [
                    {
                        "cve_id" => "CVE-2021-1234",
                        "severity" => "HIGH",
                        "score" => 8.5,
                        "description" => "Test vulnerability"
                    },
                    {
                        "cve_id" => "CVE-2021-5678",
                        "severity" => "MEDIUM",
                        "score" => 6.2,
                        "description" => "Another test vulnerability"
                    }
                ]
            }
        ]
            mock_response = double(body: mock_response_body.to_json)
            allow(client).to receive(:http_get).and_return(mock_response)
        end

        it "fetches vulnerabilities for a device" do
            vulnerabilities = client.fetch_vulnerabilities(device_id)
            expect(vulnerabilities).to be_an(Array)
        end
    end

    describe "#transform_vulnerabilities" do
        let(:device_id) { 123 }
        let(:vul) do
        [
            {
                "cveName" => "CVE-2021-1234",
                "cveTitle" => "Test Vulnerability Title",
                "desciption" => "This is a test vulnerability description",
                "score" => 8.5,
                "openDate" => "2021-01-15T10:30:00Z",
                "fixedDate" => "2021-02-20T14:45:00Z"
            },
            {
                "cveName" => "CVE-2021-5678",
                "cveTitle" => "Another Test Vulnerability",
                "desciption" => "Another test vulnerability description",
                "score" => 6.2,
                "openDate" => "2021-03-10T09:15:00Z",
                "fixedDate" => nil
            }
        ]
        end

        it "map the vuln accordingly" do
            result = client.transform_vulnurebilities(vul, device_id)

            expect(result).to be_an(Array)

            first_vuln = result.first
            expect(first_vuln["scanner_identifier"]).to eq("CVE-2021-1234|123")
            expect(first_vuln["cve_identifiers"]).to eq("CVE-2021-1234")
            expect(first_vuln["name"]).to eq("Test Vulnerability Title")
            expect(first_vuln["scanner_score"]).to eq(9) # 8.5 ceiling
        end
    end

    describe "#cve_solution" do
    let(:cve) do
        {
            "ruleTextTypeMap" => {
                "MITIGATION_STEPS" => [
                    "Update firmware to latest version",
                    "Apply security patches immediately"
                ],
                "REMEDIATION_ADVICE" => [
                    "Contact vendor for specific guidance",
                    "Implement network segmentation"
                ],
                "TRIGGER_TEXT" => [
                    "This should be ignored"
                ],
                "TRIGGER_CONDITION" => [
                    "This should also be ignored"
                ],
                "SECURITY_RECOMMENDATIONS" => [
                    "Enable two-factor authentication",
                    "Monitor system logs regularly"
                ]
            }
        }
    end

        it "returns formatted solution text" do
            result = client.cve_solution(cve)

            expect(result).to be_a(String)
            expect(result.length).to be > 0
            expect(result).to include("Mitigation_steps")
            expect(result).to include("Update firmware to latest version")
            expect(result).to include("Remediation_advice")
            expect(result).to include("Security_recommendations")
            expect(result).not_to include("TRIGGER_TEXT")
            expect(result).not_to include("TRIGGER_CONDITION")
        end

        it "returns empty string when ruleTextTypeMap is empty" do
            cve_with_empty_rules = { "ruleTextTypeMap" => {} }

            result = client.cve_solution(cve_with_empty_rules)
            expect(result).to eq("")
        end
    end

    describe "#cve_details" do
    let(:cve) do
        {
            "ruleTextTypeMap" => {
                "MITIGATION_STEPS" => [
                    "Update firmware to latest version",
                    "Apply security patches immediately"
                ],
                "REMEDIATION_ADVICE" => [
                    "Contact vendor for specific guidance",
                    "Implement network segmentation"
                ],
                "TRIGGER_TEXT" => [
                    "This should also be included",
                    "Another trigger text messages"
                ],
                "TRIGGER_CONDITION" => [
                    "This should be ignored",
                ],
                "SECURITY_RECOMMENDATIONS" => [
                    "Enable two-factor authentication",
                    "Monitor system logs regularly"
                ]
            }
        }
        end

        it "return formatted cve details" do
            result = client.cve_details(cve)

            expect(result).to be_a(String)
            expect(result).to include(" - This should also be included")
            expect(result).to include(" - Another trigger text messages")
        end
    end

    describe "#check_cve_status" do
        let(:cve_open) do
            {
                "status" => "open",
                "cve_id" => "CVE-2021-1234"
            }
        end

        let(:cve_fixed) do
            {
                "status" => "fixed",
                "cve_id" => "CVE-2021-5678"
            }
        end

        let(:cve_nil_status) do
            {
                "status" => nil,
                "cve_id" => "CVE-2021-9999"
            }
        end

        let(:cve_no_status) do
            {
                "cve_id" => "CVE-2021-0000"
            }
        end

        it "return open status" do
            result = client.check_cve_status(cve_open)
            expect(result).to eq("open")
        end

        it "return close status when fixed" do
            result = client.check_cve_status(cve_fixed)
            expect(result).to eq("closed")
        end

        it "return open status if cve status is nil" do
            result = client.check_cve_status(cve_nil_status)
            expect(result).to eq("open")
        end

        it "return open status if cve status is nil" do
            result = client.check_cve_status(cve_nil_status)
            expect(result).to eq("open")
        end

        it "return open status if cve doesn't have status" do
            result = client.check_cve_status(cve_nil_status)
            expect(result).to eq("open")
        end
    end

    describe "#transform_vulnerability" do
        let(:cve) do
            {
                "scanner_identifier" => "CVE-2021-1234|123",
                "scanner_type" => "Asimily",
                "scanner_score" => 85,
                "last_seen_at" => "2021-01-15T10:30:00Z",
                "created_at" => "2021-01-10T08:00:00Z",
                "status" => "open",
                "last_fixed_on" => "2021-02-20T14:45:00Z",
                "vuln_def_name" => "Test Vulnerability Title"
            }
        end

        it "transforms vulnerability correctly" do
            result = client.transform_vulnerability(cve)

            expect(result).to be_a(Hash)
            expect(result["scanner_identifier"]).to eq("CVE-2021-1234|123")
            expect(result["scanner_type"]).to eq("Asimily")
            expect(result["scanner_score"]).to eq(85)
            expect(result["last_seen_at"]).to eq("2021-01-15T10:30:00Z")
            expect(result["created_at"]).to eq("2021-01-10T08:00:00Z")
            expect(result["status"]).to eq("open")
            expect(result["last_fixed_on"]).to eq("2021-02-20T14:45:00Z")
            expect(result["vuln_def_name"]).to eq("Test Vulnerability Title")
        end

        it "compacts nil values" do
            cve_with_nils = {
                "scanner_identifier" => "CVE-2021-5678|456",
                "scanner_type" => "Asimily",
                "scanner_score" => nil,
                "last_seen_at" => "2021-03-01T12:00:00Z",
                "created_at" => nil,
                "status" => "closed",
                "last_fixed_on" => nil,
                "vuln_def_name" => nil
            }

            result = client.transform_vulnerability(cve_with_nils)

            expect(result).not_to have_key("scanner_score")
            expect(result).not_to have_key("created_at")
            expect(result).not_to have_key("last_fixed_on")
            expect(result).not_to have_key("vuln_def_name")
            expect(result["status"]).to eq("closed")
            expect(result["last_seen_at"]).to eq("2021-03-01T12:00:00Z")
        end
    end

    describe "#transform_vulnerability_def" do
        let(:cve) do
            {
                "scanner_identifier" => "CVE-2021-1234|123",
                "scanner_type" => "Asimily",
                "cve_identifiers" => "CVE-2021-1234",
                "vuln_def_name" => "Test Vulnerability Title",
                "desciption" => "This is a test vulnerability description",
                "solution" => "Update firmware to latest version",
                "details" => "Additional vulnerability details"
            }
        end

        it "transforms vulnerability definition correctly" do
            result = client.transform_vulnerability_def(cve)

            expect(result).to be_a(Hash)
            expect(result["scanner_identifier"]).to eq("CVE-2021-1234|123")
            expect(result["scanner_type"]).to eq("Asimily")
            expect(result["cve_identifiers"]).to eq("CVE-2021-1234")
            expect(result["name"]).to eq("Test Vulnerability Title")
            expect(result["desciption"]).to eq("This is a test vulnerability description")
            expect(result["solution"]).to eq("Update firmware to latest version")
            expect(result["details"]).to eq("Additional vulnerability details")
        end

        it "compacts nil values" do
            cve_with_nils = {
                "scanner_identifier" => "CVE-2021-5678|456",
                "scanner_type" => "Asimily",
                "cve_identifiers" => "CVE-2021-5678",
                "vuln_def_name" => nil,
                "desciption" => "Description only",
                "solution" => nil,
                "details" => nil
            }

            result = client.transform_vulnerability_def(cve_with_nils)

            expect(result).not_to have_key("name")
            expect(result).not_to have_key("solution")
            expect(result).not_to have_key("details")
            expect(result["desciption"]).to eq("Description only")
        end
    end

    describe "#extract_tags" do
        let(:device) do
            {
                "deviceTag" => ["tag1", "tag2", "custom_tag"],
                "facility" => "Building A - Floor 2",
                "deviceModel" => "OptiPlex 7090",
                "deviceType" => "Desktop",
                "manufacturer" => "Dell",
                "deviceMasterFamily" => "OptiPlex Series"
            }
        end

        let(:device_with_nil_tags) do
            {
                "deviceTag" => nil,
                "facility" => "Main Office",
                "deviceModel" => nil,
                "deviceType" => "Laptop",
                "manufacturer" => "",
                "deviceMasterFamily" => "ThinkPad Series"
            }
        end

        it "extracts tags from device with full data" do
            result = client.extract_tags(device)

            expect(result).to be_an(Array)
            expect(result).to include("tag1", "tag2", "custom_tag")
            expect(result).to include("Facility: Building A - Floor 2")
            expect(result).to include("DeviceModel: OptiPlex 7090")
            expect(result).to include("DeviceType: Desktop")
            expect(result).to include("Manufacturer: Dell")
            expect(result).to include("DeviceMasterFamily: OptiPlex Series")
        end

        it "handles device with nil deviceTag array" do
            result = client.extract_tags(device_with_nil_tags)

            expect(result).to be_an(Array)
            expect(result).to include("Facility: Main Office")
            expect(result).to include("DeviceType: Laptop")
            expect(result).to include("DeviceMasterFamily: ThinkPad Series")
            expect(result).not_to include("DeviceModel:")
            expect(result).not_to include("Manufacturer:")
        end
    end

    describe "#transform_device" do
        let(:device) do
            {
                "v4IpAddrs" => ["192.168.1.100", "10.0.0.50"],
                "deviceID" => 12345,
                "macAddr" => "AA:BB:CC:DD:EE:FF",
                "hostName" => "test-device-01",
                "os" => "Linux Ubuntu 20.04",
                "lastDiscoveredAt" => "2021-07-15T14:30:00Z",
                "deviceTag" => ["tag1", "tag2"]
            }
        end

        let(:device_with_minimal_data) do
            {
                "v4IpAddrs" => [],
                "deviceID" => 67890,
                "macAddr" => "",
                "hostName" => "",
                "os" => "unknown",
                "lastDiscoveredAt" => nil
            }
        end

        it "transforms device with full data" do
            allow(client).to receive(:extract_tags).and_return(["tag1", "tag2"])
            allow(client).to receive(:date_to_iso8601).and_return("2021-07-15T14:30:00Z")

            result = client.transform_device(device)

            expect(result).to be_a(Hash)
            expect(result["ip_address"]).to eq("192.168.1.100")
            expect(result["external_id"]).to eq("12345")
            expect(result["mac_address"]).to eq("AA:BB:CC:DD:EE:FF")
            expect(result["hostname"]).to eq("test-device-01")
            expect(result["os"]).to eq("Linux Ubuntu 20.04")
            expect(result["tags"]).to eq(["tag1", "tag2"])
        end

         it "handles device with minimal data" do
            allow(client).to receive(:extract_tags).and_return([])
            allow(client).to receive(:date_to_iso8601).and_return("2021-08-01T09:00:00Z")

            result = client.transform_device(device_with_minimal_data)

            expect(result["ip_address"]).to be_nil
            expect(result["external_id"]).to eq("67890")
            expect(result).not_to have_key("mac_address")
            expect(result).not_to have_key("hostname")
            expect(result).not_to have_key("os")
        end
    end

    describe "#date_to_iso8601" do
        let(:string_date) { "2021-07-15 14:30:00" }
        let(:iso_date) { "2021-07-15T10:30:00Z" }
        let(:invalid_date) { "not-a-date" }
        let(:nil_date) { nil }

        it "converts valid string date to ISO8601 format" do
            result = client.date_to_iso8601(string_date)
            expect(result).to be_a(String)
            expect(result).to match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\+00:00|Z)/)
        end

        it "converts ISO date string to ISO8601 format" do
            result = client.date_to_iso8601(iso_date)
            expect(result).to be_a(String)
            expect(result).to match(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\+00:00|Z)/)
        end

        it "returns nil for invalid date string" do
            result = client.date_to_iso8601(invalid_date)
            expect(result).to be_nil
        end

        it "returns nil for nil input" do
            result = client.date_to_iso8601(nil_date)
            expect(result).to be_nil
        end
    end
end