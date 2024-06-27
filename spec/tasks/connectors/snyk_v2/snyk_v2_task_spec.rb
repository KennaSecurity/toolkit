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

    context "fetches data from Snyk API" do
      it "fetches organizations" do
        expect_any_instance_of(Kenna::Toolkit::SnykV2::SnykV2Client).to receive(:snyk_get_orgs).and_call_original
        task.run(options)
      end

      it "fetches projects" do
        expect_any_instance_of(Kenna::Toolkit::SnykV2::SnykV2Client).to receive(:snyk_get_projects).with(org_id).and_call_original
        task.run(options)
      end

      it "fetches issues" do
        expect_any_instance_of(Kenna::Toolkit::SnykV2::SnykV2Client).to receive(:snyk_get_issues).with(100, 5000, options[:from_date], options[:to_date], org_id).and_call_original
        task.run(options)
      end
    end

    context "vulnerability" do
      it "creates normalized (non-duplicative) vuln_defs" do
        task.run(options)
        expect(task.vuln_defs).to include(
          hash_including(
            "name" => "Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-125)",
            "scanner_identifier" => "pcre2-3355351",
            "scanner_type" => "Snyk"
          )
        )
      end

      it "creates normalized (non-duplicative) vulns on assets" do
        task.run(options)
        expect(task.assets).to include(
          hash_including(
            "file" => "pcre2",
            "application" => "034629b9-c709-4af7-b31f-433f9f2f7027",
            "tags" => ["Org:e0319d01-7a3f-442a-8e94-3613b81c705a"],
            "vulns" => array_including(
              hash_including(
                "scanner_identifier" => "pcre2-3355351",
                "scanner_type" => "Snyk",
                "vuln_def_name" => "Improper Restriction of Operations within the Bounds of a Memory Buffer (CWE-125)",
                "severity" => 7.5
              )
            )
          )
        )
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end
end
