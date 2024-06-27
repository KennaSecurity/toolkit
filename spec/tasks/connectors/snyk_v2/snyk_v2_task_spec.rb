# frozen_string_literal: true

require "rspec_helper"
require_relative "snyk_v2_stubs"
require "json"

RSpec.describe Kenna::Toolkit::SnykV2Task do
  include SnykV2Stubs
  subject(:task) { described_class.new }

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { "data_file" => 12 }, run_files_on_connector: { "success" => connector_run_success }) }
    let(:options) do
      {
        snyk_api_token: '0xdeadbeef',
        from_date: "2024-05-06T00:00:00Z",
        to_date: "2024-06-05T00:00:00Z",
        include_license: false,
        page_size: 100,
        batch_size: 500,
        page_num: 5000,
        kenna_connector_id: nil,
        kenna_api_key: nil,
        kenna_api_host: "api.kennasecurity.com",
        output_directory: "output/snyk",
        snyk_api_base: "api.snyk.io"
      }
    end

    let(:org_id) { JSON.parse(read_fixture_file("orgs.json"))["data"].first["id"] }

    before do
      stub_orgs_request
      stub_projects_request(org_id)
      stub_issues_request(org_id, options[:from_date], options[:to_date])
      allow(Kenna::Api::Client).to receive(:new) { kenna_client }
      spy_on_accumulators
    end

    context "vulnerability" do
      let(:import_type) { "vulns" }

      it "creates normalized (non-duplicative) vuln_defs" do
        task.run(options)
        expect(task.vuln_defs).to include(
          {
            "cve_identifiers" => "CVE-2015-7501,CVE-2015-4852",
            "description" => "Deserialization of Untrusted Data",
            "name" => "CVE-2015-7501",
            "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078",
            "scanner_type" => "Snyk"
          }
        )
      end

      it "creates normalized (non-duplicative) vulns on assets" do
        task.run(options)
        expect(task.assets).to include(
          {
            "file" => "pom.xml",
            "application" => "JoyChou93/java-sec-code:pom.xml",
            "tags" => ["github", "maven", "Org:Kenna Security NFR - Shared"],
            "vulns" => [
              {
                "created_at" => "2023-04-26",
                "details" => be_kind_of(String),
                "last_seen_at" => be_kind_of(String),
                "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078",
                "scanner_score" => 9,
                "scanner_type" => "Snyk",
                "status" => "open",
                "vuln_def_name" => "CVE-2015-7501"
              }
            ]
          }
        )
      end
    end

    context "finding that has multiple CVEs" do
      let(:import_type) { "findings" }

      it "creates duplicate vuln_defs" do
        task.run(options)
        expect(task.vuln_defs).to include(
          {
            "cve_identifiers" => "CVE-2015-7501",
            "description" => "Deserialization of Untrusted Data",
            "name" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078-CVE-2015-7501",
            "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078-CVE-2015-7501",
            "scanner_type" => "Snyk"
          },
          {
            "cve_identifiers" => "CVE-2015-4852",
            "description" => "Deserialization of Untrusted Data",
            "name" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078-CVE-2015-4852",
            "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078-CVE-2015-4852",
            "scanner_type" => "Snyk"
          }
        )
      end

      it "creates assets with duplicate findings" do
        task.run(options)
        expect(task.assets).to include(
          hash_including("file" => "pom.xml",
                         "application" => "JoyChou93/java-sec-code:pom.xml",
                         "tags" => ["github", "maven", "Org:Kenna Security NFR - Shared"],
                         "findings" => [
                           asset_finding_for_cve("CVE-2015-7501"), asset_finding_for_cve("CVE-2015-4852")
                         ])
        )
      end

      def asset_finding_for_cve(cve)
        {
          "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078-#{cve}",
          "scanner_type" => "Snyk",
          "vuln_def_name" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078-#{cve}",
          "severity" => 9,
          "last_seen_at" => "2023-04-26",
          "additional_fields" => {
            "url" => "http://security.snyk.io/vuln/SNYK-JAVA-COMMONSCOLLECTIONS-30078",
            "id" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078",
            "title" => "Deserialization of Untrusted Data",
            "file" => "pom.xml",
            "application" => "JoyChou93/java-sec-code:pom.xml",
            "introducedDate" => "2023-04-26",
            "isPatchable" => "false",
            "isUpgradable" => "false",
            "language" => "java",
            "semver" => "{\n  \"vulnerable\": [\n    \"[3.0,3.2.2)\"\n  ]\n}",
            "cvssScore" => "9.8",
            "severity" => "critical",
            "package" => "commons-collections:commons-collections",
            "version" => "3.1",
            "identifiers" => { "CVE" => ["CVE-2015-7501", "CVE-2015-4852"], "CWE" => ["CWE-502"] },
            "publicationTime" => "2015-11-06T16:51:56.000Z"
          },
          "triage_state" => "new"
        }
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end
end
