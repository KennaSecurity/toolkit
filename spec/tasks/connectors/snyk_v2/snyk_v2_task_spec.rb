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

      it "creates vuln_defs" do
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

      it "creates assets with vulns" do
        expect(task.assets).to include(
          {
            "file" => "pom.xml",
            "application" => "JoyChou93/java-sec-code:pom.xml",
            "priority" => 10,
            "tags" => ["github", "maven", "Org:Kenna Security NFR - Shared"],
            "vulns" =>
          [{ "created_at" => "2023-04-26",
             "details" => be_kind_of(String),
             "last_seen_at" => "2023-04-26",
             "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078",
             "scanner_score" => 9,
             "scanner_type" => "Snyk",
             "status" => "open",
             "vuln_def_name" => "CVE-2015-7501" },
           { "created_at" => "2023-04-26",
             "details" => be_kind_of(String),
             "last_seen_at" => "2023-04-26",
             "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078",
             "scanner_score" => 9,
             "scanner_type" => "Snyk",
             "status" => "open",
             "vuln_def_name" => "CVE-2015-4852" }]
          }
        )
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end
end
