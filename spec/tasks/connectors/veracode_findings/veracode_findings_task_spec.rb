# frozen_string_literal: true

require "rspec_helper"
require_relative "veracode_findings_stubs"

RSpec.describe Kenna::Toolkit::VeracodeFindings do
  include VeracodeFindingsStubs
  subject(:task) { described_class.new }

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { "data_file" => 12 }, run_files_on_connector: { "success" => connector_run_success }) }
    let(:options) { { veracode_id: '', veracode_key: '' } }

    before do
      skip "FIXME CON-4429: This spec was copied from Snyk and never set up properly."
      stub_findings_request
      stub_sca_findings_request
      stub_applications_request
      allow(Kenna::Api::Client).to receive(:new) { kenna_client }
      spy_on_accumulators
      task.run(options)
    end

    context "veracode findings" do
      it "should map the scanner_identifier to include the application name and the issue id" do
        expect(task.vuln_defs).to include(
          an_object_having_attributes({
                                        "scanner_identifier": "app1:123"
                                      })
        )
        expect(task.assets.first.findings).to include(
          an_object_having_attributes({
                                        "scanner_identifier": "app1:123",
                                        "cwe_identifiers": "CWE-TEST"
                                      })
        )
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end
end
