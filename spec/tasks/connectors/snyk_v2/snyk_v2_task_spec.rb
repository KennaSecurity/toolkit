# frozen_string_literal: true

require "rspec_helper"
require_relative "snyk_v2_stubs"

RSpec.describe Kenna::Toolkit::SnykV2Task do
  include SnykV2Stubs
  subject(:task) { described_class.new }

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { "data_file" => 12 }, run_files_on_connector: { "success" => connector_run_success }) }
    let(:options) { { snyk_api_token: '0xdeadbeef', import_type: } }

    before do
      stub_orgs_request
      stub_projects_request
      stub_issues_request
      allow(Kenna::Api::Client).to receive(:new) { kenna_client }
      spy_on_accumulators
      task.run(options)
    end

    context "vulnerability" do
      let(:import_type) { "vulns" }

      it "creates normalized (non-duplicative) vuln_defs" do
        VCR.use_cassette('snyk_v2_task_run', record: :new_episodes) do
          task.run(options)
        end

        expect(task.vuln_defs).to include(
          {
            "name" => "SNYK-RHEL9-GLIB2-6820066",
            "scanner_type" => "Snyk",
            "cve_identifiers" => "CVE-2024-34397",
            "cwe_identifiers" => "CWE-940",
            "description" => "Improper Verification of Source of a Communication Channel",
            "solution" => "For more information, go to this link: https://nvd.nist.gov/vuln/detail/CVE-2024-34397"
          }
        )
      end

      it "creates normalized (non-duplicative) vulns on assets" do
        expect(task.assets).to include(
          {
            "file" => "Snyk_RHEL9_GLIB2_6820066_f5798261-5db0-442a-9eb8-10bf21d50888",
            "tags" => ["Org:e0319d01-7a3f-442a-8e94-3613b81c705a"],
            "os" => "RHEL9",
            "priority" => 10,
            "vulns" => [
              { "scanner_identifier" => "f5798261-5db0-442a-9eb8-10bf21d50888",
                "vuln_def_name" => "SNYK-RHEL9-GLIB2-6820066",
                "scanner_type" => "Snyk",
                "created_at" => "2024-05-11T01:12:50.945Z",
                "last_seen_at" => "2024-05-11T01:12:51.532107Z",
                "status" => "open",
                "details" => "CVE-2024-34397 : Improper Verification of Source of a Communication Channel",
                "scanner_score" => 4 }
            ]
          }
        )
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end
end
