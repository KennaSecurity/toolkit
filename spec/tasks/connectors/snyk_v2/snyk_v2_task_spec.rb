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
      VCR.use_cassette("snyk_v2_task_run") do
        stub_orgs_request
        stub_projects_request(org_id)
        stub_issues_request(org_id, options[:from_date], options[:to_date])
        allow(Kenna::Api::Client).to receive(:new).and_return(kenna_client)
        spy_on_accumulators
      end
    end

    it "runs the task and includes the expected vulnerability definition" do
      VCR.use_cassette("snyk_v2_task_run") do
        task.run(options)
        expect(task.vuln_defs).to include(
          {
            "description" => "Deserialization of Untrusted Data",
            "name" => "CVE-2015-7501",
            "scanner_identifier" => "SNYK-JAVA-COMMONSCOLLECTIONS-30078",
            "scanner_type" => "Snyk"
          }
        )
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end
end
