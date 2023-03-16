# frozen_string_literal: true

require "rspec_helper"
# require_relative "aws_inspector2_stubs"

RSpec.describe Kenna::Toolkit::AwsInspector2 do
  subject(:task) { described_class.new }

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { "data_file" => 12 }, run_files_on_connector: { "success" => connector_run_success }) }
    let(:options) do
      {
        aws_access_key: ENV["AWS_ACCESS_KEY"],
        aws_secret_key: ENV["AWS_SECRET_KEY"]
      }
    end

    before do
      allow(Kenna::Api::Client).to receive(:new) { kenna_client }
    end

    describe "accumulator properties" do
      before do
        spy_on_accumulators
        VCR.use_cassette("aws_inspector_v2_findings") do
          task.run(options)
        end
      end

      it "creates vuln_defs" do
        expect(task.vuln_defs)
          .to include({
                        cve_identifiers: "CVE-2022-21426",
                        name: "CVE-2022-21426",
                        scanner_identifier: "CVE-2022-21426",
                        scanner_type: "AWS Inspector V2"
                      })
      end

      it "creates assets" do
        expect(task.assets)
          .to include({ ec2: "i-09fd5b46b5457d22c",
                        fqdn: "Sonarcube",
                        ip_address: "172.31.10.90",
                        os: "AMAZON_LINUX_2",
                        priority: 10,
                        tags: be_an(Array),
                        vulns: be_an(Array) })
      end

      it "creates vulns on the assets" do
        expect(asset_with_ip("172.31.10.90")[:vulns])
          .to include({ created_at: be_a(DateTime),
                        last_seen_at: be_a(DateTime),
                        scanner_identifier: "CVE-2022-36123",
                        scanner_type: "AWS Inspector V2",
                        status: "open",
                        scanner_score: 7,
                        vuln_def_name: "CVE-2022-36123" })
      end

      it "creates tags on the assets" do
        expect(asset_with_ip("172.31.10.90")[:tags])
          .to include("AWS", "Tribe:Sports", "Environment:", "OS:AMAZON_LINUX_2", "AWS Account ID:612899039241",
                      "Squad:", "External:", "Technical Service:")
      end
    end

    describe "writing out the KDI file" do
      it "writes one file per batch" do
        expect(task).to receive(:kdi_upload).at_least(2).times
        VCR.use_cassette("aws_inspector_v2_findings") do
          task.run(options)
        end
      end
    end

    describe "multiple regions"
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end

  def asset_with_ip(ip_address)
    task.assets.find { |asset| asset[:ip_address] == ip_address }
  end
end
