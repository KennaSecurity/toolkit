# frozen_string_literal: true

require "rspec_helper"

RSpec.describe Kenna::Toolkit::AwsInspector2 do
  subject(:task) { described_class.new }

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { "data_file" => 12 }, run_files_on_connector: { "success" => connector_run_success }) }
    let(:aws_regions) { ENV["AWS_REGION"] || "us-east-1" }
    let(:options) do
      {
        aws_access_key_id: ENV["AWS_ACCESS_KEY_ID"] || "AWS_ACCESS_KEY_ID",
        aws_secret_access_key: ENV["AWS_SECRET_ACCESS_KEY"] || "AWS_SECRET_ACCESS_KEY",
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
                        cve_identifiers: "CVE-2024-26598",
                        description: start_with(" In the Linux kernel, the following vulnerability has been resolved: KVM: arm64:"),
                        name: "CVE-2024-26598 - linux-image-aws",
                        scanner_identifier: "arn:aws:inspector2:us-east-1:612899039241:finding/002dafdaaad8d66b7829d617031415c9",
                        scanner_type: "AWS Inspector V2",
                        solution: "None Provided"
                      })
      end

      it "creates ec2 assets" do
        expect(task.assets)
          .to include({ ec2: "i-0325ce909a8eac7d1",
                        fqdn: "",
                        hostname: "VM for Scanners",
                        ip_address: "52.203.164.153",
                        os: "UBUNTU_20_04",
                        tags: be_an(Array),
                        vulns: be_an(Array) })
        expect(task.assets)
          .to include({ ec2: "i-054fe8def0d3d3306",
                        fqdn: "",
                        hostname: "splunk",
                        ip_address: "3.218.161.161",
                        os: "AMAZON_LINUX_2",
                        tags: be_an(Array),
                        vulns: be_an(Array) })
      end

      it "creates ecr image assets" do
        expect(task.assets)
          .to include({ asset_type: "image",
                        image_id: start_with("sha256:01d39a8f0b"),
                        tags: be_an(Array),
                        vulns: be_an(Array) })
      end

      it "creates vulns on the assets" do
        expect(select_asset("i-054fe8def0d3d3306")[:vulns])
          .to include({ scanner_identifier: "arn:aws:inspector2:us-east-1:612899039241:finding/011a86590a40dd0f548ce7ba4f2fdb63",
                        scanner_type: "AWS Inspector V2",
                        created_at: be_a(Time),
                        last_seen_at: be_a(Time),
                        status: "open",
                        vuln_def_name: "CVE-2023-50387 - bind-utils, bind-libs-lite and 3 more",
                        scanner_score: 8 })
        expect(select_asset("sha256:01d39a8f0b")[:vulns])
          .to include({ scanner_identifier: "arn:aws:inspector2:us-east-1:612899039241:finding/004b20187b011e240f1ec712682eb112",
                        scanner_type: "AWS Inspector V2",
                        created_at: be_a(Time),
                        last_seen_at: be_a(Time),
                        status: "open",
                        vuln_def_name: "CVE-2019-7149 - elfutils, libelf1",
                        scanner_score: 7 })
      end

      it "creates tags on the assets" do
        expect(select_asset("i-0f4c0b7681d50408f")[:tags])
          .to include("Schedule:nightnight", "status:started")
        expect(select_asset("sha256:01d39a8f0b")[:tags])
          .to include("registry-612899039241", "repository-inspector2_ecr_scanning")
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
      let(:aws_regions) { "us-east-1,us-east-2" }
      let(:empty_findings) { double(findings: [], next_token: nil) }

      it "queries Inspector in each region" do
        aws_regions.split(",").each do |region|
          aws_client = double("Aws::Inspector2::Client", list_findings: empty_findings)
          allow(aws_client).to receive(:config).and_return(double(region:))
          expect(Aws::Inspector2::Client).to receive(:new).with(
            hash_including(region:)
          ).and_return(aws_client)
        end

        task.run(options)
      end
    end
  end

  describe "#new_aws_client" do
    let(:region) { 'asgard-1' }

    describe "region configuration" do
      it "errors helpfully when region not provided" do
        expect { task.new_aws_client }.to raise_error(Aws::Errors::MissingRegionError, /AWS_REGION/)
      end

      it "collects region from $AWS_REGION" do
        stub_env('AWS_REGION' => region)
        expect(task.new_aws_client.config.region).to eq(region)
      end

      it "collects region from $AWS_DEFAULT_REGION" do
        stub_env('AWS_DEFAULT_REGION' => region)
        expect(task.new_aws_client.config.region).to eq(region)
      end

      it "can be explicitly given a region" do
        expect(task.new_aws_client(region).config.region).to eq(region)
      end
    end

    describe "credential configuration" do
      subject { task.new_aws_client(region) }

      it "collects credentials from $AWS_ACCESS_KEY_ID and $AWS_SECRET_ACCESS_KEY in ENV" do
        stub_env('AWS_ACCESS_KEY_ID' => 'foo', 'AWS_SECRET_ACCESS_KEY' => 'bar')
        expect(subject.config.credentials).to be_present
        expect(subject.config.credentials.session_token).to be_nil
      end

      it "collects credentials from $AWS_SESSION_TOKEN in ENV" do
        stub_env('AWS_ACCESS_KEY_ID' => 'foo', 'AWS_SECRET_ACCESS_KEY' => 'bar', 'AWS_SESSION_TOKEN' => 'baz')
        expect(subject.config.credentials).to be_present
        expect(subject.config.credentials.session_token).to be_present
      end

      it "can be explicitly given a key and secret" do
        credentials = Aws::Credentials.new('foo', 'bar')
        client = task.new_aws_client(region, credentials)
        expect(client.config.credentials).to_not be_nil
        expect(client.config.credentials.session_token).to be_nil
      end

      it "can be explicitly given a session token" do
        credentials = Aws::Credentials.new('foo', 'bar', 'baz')
        client = task.new_aws_client(region, credentials)
        expect(client.config.credentials).to_not be_nil
        expect(client.config.credentials.session_token).to be_present
      end
    end

    describe "#aws_credentials" do
      subject do
        VCR.use_cassette("aws_sts") do
          described_class.new(options).aws_credentials
        end
      end

      let(:options) do
        {
          aws_access_key_id: ENV["AWS_ACCESS_KEY_ID"] || "AWS_ACCESS_KEY_ID",
          aws_secret_access_key: ENV["AWS_SECRET_ACCESS_KEY"] || "AWS_SECRET_ACCESS_KEY",
          aws_regions: 'us-east-1'
        }
      end

      context "access key and secret key provided" do
        it "returns a simple credentials object" do
          expect(subject).to be_kind_of(Aws::Credentials)
        end
      end

      context "role arn is provided" do
        it "returns assumed role credentials" do
          options.merge!(aws_role_arn: "arn:aws:iam::612899039241:role/Inspectorv2ReadOnly")
          expect(subject).to be_kind_of(Aws::AssumeRoleCredentials)
        end
      end
    end
  end

  def stub_env(hash)
    stub_const('ENV', ENV.to_hash.merge(hash))
  end

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end

  def select_asset(id)
    task.assets.find { |asset| asset[:ec2] == id || asset[:image_id]&.start_with?(id) }
  end
end
