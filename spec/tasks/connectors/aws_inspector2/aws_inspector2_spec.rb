# frozen_string_literal: true

require "rspec_helper"
# require_relative "aws_inspector2_stubs"

RSpec.describe Kenna::Toolkit::AwsInspector2 do
  subject(:task) { described_class.new }

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { "data_file" => 12 }, run_files_on_connector: { "success" => connector_run_success }) }
    let(:aws_regions) { nil } # rely on option default
    let(:options) do
      {
        aws_access_key: ENV["AWS_ACCESS_KEY"] || "AWS_ACCESS_KEY",
        aws_secret_key: ENV["AWS_SECRET_KEY"] || "AWS_SECRET_KEY",
        aws_regions:
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
                        name: "CVE-2022-21426 - java-1.7.0-openjdk",
                        scanner_identifier: "arn:aws:inspector2:us-east-1:612899039241:finding/f7108e88a43e52e5f5168861180f1efd",
                        scanner_type: "AWS Inspector V2",
                        description: start_with("Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product"),
                        solution: "None Provided"
                      })
      end

      it "creates ec2 assets" do
        expect(task.assets)
          .to include({ ec2: "i-0c0fe138a5367ef34",
                        fqdn: "nessus.connectorlab.org",
                        hostname: "",
                        ip_address: "34.235.255.215",
                        os: "AMAZON_LINUX",
                        priority: 10,
                        tags: be_an(Array),
                        vulns: be_an(Array) })
        expect(task.assets)
          .to include({ ec2: "i-09fd5b46b5457d22c",
                        fqdn: "",
                        hostname: "Sonarcube",
                        ip_address: "54.242.136.219",
                        os: "AMAZON_LINUX_2",
                        priority: 10,
                        tags: be_an(Array),
                        vulns: be_an(Array) })
      end

      it "creates ecr image assets" do
        expect(task.assets)
          .to include({ asset_type: "image",
                        image_id: start_with("sha256:34ca666355"),
                        priority: 10,
                        tags: be_an(Array),
                        vulns: be_an(Array) })
      end

      it "creates vulns on the assets" do
        expect(select_asset("i-09fd5b46b5457d22c")[:vulns])
          .to include({ created_at: be_a(Time),
                        last_seen_at: be_a(Time),
                        scanner_identifier: "arn:aws:inspector2:us-east-1:612899039241:finding/32750bb2f6cae06b828c652864bc1060",
                        scanner_type: "AWS Inspector V2",
                        status: "open",
                        scanner_score: 7,
                        vuln_def_name: "CVE-2022-36123 - kernel" })
        expect(select_asset("sha256:34ca666355")[:vulns])
          .to include({ created_at: be_a(Time),
                        last_seen_at: be_a(Time),
                        scanner_identifier: "arn:aws:inspector2:us-east-1:612899039241:finding/01078690981ce6c19ba17107030248d6",
                        scanner_type: "AWS Inspector V2",
                        status: "open",
                        scanner_score: 8,
                        vuln_def_name: "IN1-JS-TOUGHCOOKIE-10119 - tough-cookie" })
      end

      it "creates tags on the assets" do
        expect(select_asset("i-0c0fe138a5367ef34")[:tags])
          .to include("Schedule:nightnight", "state:started")
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

    context "multiple regions" do
      let(:aws_regions) { %w[us-east-1 us-east-2] }
      let(:empty_response) { instance_double("Aws::Inspector2::Client", list_findings: double(findings: [], next_token: nil)) }

      it "queries Inspector in each region" do
        aws_regions.each do |region|
          expect(Aws::Inspector2::Client).to receive(:new).with(
            { region:,
              credentials: be_an(Aws::Credentials) }
          ).and_return(empty_response)
        end
        task.run(options)
      end
    end
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end

  def select_asset(id)
    task.assets.find { |asset| asset[:ec2] == id || asset[:image_id]&.start_with?(id) }
  end
end
