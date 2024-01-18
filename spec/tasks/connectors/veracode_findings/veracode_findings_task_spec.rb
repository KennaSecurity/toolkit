# frozen_string_literal: true

require "rspec_helper"
require "json"
require_relative "veracode_findings_stubs"

RSpec.describe Kenna::Toolkit::VeracodeFindings do
  include VeracodeFindingsStubs
  subject(:task) { described_class.new }

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { "data_file" => 12 }, run_files_on_connector: { "success" => connector_run_success }) }
    let(:options) { { veracode_id: 'abc', veracode_key: '123' } }

    before do
      stub_findings_request
      stub_sca_findings_request
      stub_applications_request
      stub_categories_request
      allow(Kenna::Api::Client).to receive(:new) { kenna_client }
      spy_on_accumulators
      task.run(options)
    end

    context "veracode findings" do
      it "should map available vulnerability definitions " do
        output = JSON.parse(File.read("#{$basedir}/output/veracode/veracode_app1.json"))
        expect(output['vuln_defs']).to include(
          {
            "cwe_identifiers" => "CWE-TEST",
            "name" => "TEST NAME",
            "scanner_type" => "veracode",
            "solution" => "123",
            "scanner_identifier" => "app1:123"
          }
        )
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end
end
