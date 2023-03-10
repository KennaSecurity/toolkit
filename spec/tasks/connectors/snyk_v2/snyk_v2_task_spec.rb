# frozen_string_literal: true

require "rspec_helper"
require_relative "snyk_v2_stubs"

RSpec.describe Kenna::Toolkit::SnykV2Task do
  subject(:task) { described_class.new }

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: {"data_file" => 12}, run_files_on_connector: {"success" => connector_run_success}) }
    let(:options) { { "snyk_api_token" => '0xdeadbeef', "import_type" => import_type } }
    let(:import_type) { nil }

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
        expect(task.vuln_defs).to include({
          "cve_identifiers" => "CVE-2015-7501,CVE-2015-4852",
          "description" => "Deserialization of Untrusted Data",
          "name" => "CVE-2015-7501",
          "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078",
          "scanner_type" => "Snyk",
          "solution" => '{"id"=>"", "urls"=>[], "version"=>"", "comments"=>[], "modificationTime"=>""}'
        })
      end

      xit "creates assets with vulns" do
        expect(task.assets).to include({})
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end
end
