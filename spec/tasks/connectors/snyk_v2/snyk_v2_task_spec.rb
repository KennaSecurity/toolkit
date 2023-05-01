# frozen_string_literal: true

require "rspec_helper"
require_relative "snyk_v2_stubs"

RSpec.describe Kenna::Toolkit::SnykV2Task do
  subject(:task) { described_class.new }

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { "data_file" => 12 }, run_files_on_connector: { "success" => connector_run_success }) }
    let(:options) { { snyk_api_token: '0xdeadbeef', import_type: } }
    let(:import_type) { "findings" }

    before do
      stub_orgs_request
      stub_projects_request
      stub_issues_request
      allow(Kenna::Api::Client).to receive(:new) { kenna_client }
    end

    describe "accumulator properties" do
      before do
        spy_on_accumulators
        task.run(options)
      end

      context "finding that has multiple CVEs" do
        it "creates duplicate vuln_defs" do
          expect(task.vuln_defs).to include(
            {
              "cve_identifiers" => "CVE-2015-7501",
              "description" => "Deserialization of Untrusted Data",
              "name" => "CVE-2015-7501",
              "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078-CVE-2015-7501",
              "scanner_type" => "Snyk"
            },
            {
              "cve_identifiers" => "CVE-2015-4852",
              "description" => "Deserialization of Untrusted Data",
              "name" => "CVE-2015-4852",
              "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078-CVE-2015-4852",
              "scanner_type" => "Snyk"
            }
          )
        end

        it "creates assets with duplicate findings" do
          expect(task.assets).to include(
            hash_including("file" => "pom.xml",
                           "application" => "JoyChou93/java-sec-code:pom.xml",
                           "tags" => ["github", "maven", "Org:Kenna Security NFR - Shared"],
                           "priority" => 10,
                           "findings" => [
                             asset_finding_for_cve("CVE-2015-7501"), asset_finding_for_cve("CVE-2015-4852")
                           ])
          )
        end

        def asset_finding_for_cve(cve)
          { "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078-#{cve}",
            "scanner_type" => "Snyk",
            "vuln_def_name" => cve,
            "severity" => 9,
            "last_seen_at" => "2023-04-26",
            "additional_fields" =>
                           { "url" => "http://security.snyk.io/vuln/SNYK-JAVA-COMMONSCOLLECTIONS-30078",
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
                             "publicationTime" => "2015-11-06T16:51:56.000Z" },
            "triage_state" => "new" }
        end
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end
end
