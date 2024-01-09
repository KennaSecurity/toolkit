# frozen_string_literal: true

require "rspec_helper"
require 'time'

RSpec.describe Kenna::Toolkit::GithubDependabot do
  subject(:task) { described_class.new }

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { "data_file" => 12 }, run_files_on_connector: { "success" => connector_run_success }) }
    let(:options) do
      {
        github_organization_name: "shotop",
        github_token: ENV["GITHUB_TOKEN"] || "GITHUB_TOKEN_ID"
      }
    end

    before do
      allow(Kenna::Api::Client).to receive(:new) { kenna_client }
    end

    it 'succeeds' do
      VCR.use_cassette('github_dependabot') do
        expect { task.run(options) }.to_not raise_error
      end
    end

    context "with all required params" do
      before do
        spy_on_accumulators

        @now = Time.new(2021, 10, 30, 8, 9, 10)

        Timecop.freeze(@now) do
          VCR.use_cassette('github_dependabot') do
            task.run(options)
          end
        end
      end

      it 'creates application assets' do
        expect(task.assets.map { |a| a["application"] })
          .to include("advent_of_code_2020")
      end

      it 'creates application assets with vulnerabilities' do
        expect(task.assets.first["vulns"].first)
          .to include({ "scanner_identifier" => "CVE-2009-4492",
                        "created_at" => "2017-11-16T05:26:48Z",
                        "scanner_type" => "GitHubDependabot",
                        "scanner_score" => 0,
                        :last_seen_at => @now,
                        :status => "open",
                        "vuln_def_name" => "CVE-2009-4492",
                        "details" =>
                    "{\n  \"packageName\": \"webrick\",\n  \"firstPatchedVersion\": \"1.4.0\",\n  \"vulnerableVersionRange\": \"<= 1.3.1\",\n  \"dependabot_url\": \"https://github.com/shotop/sjh/security/dependabot/1\"\n}",
                        "status" => "open",
                        "last_seen_at" => "2021-10-30" })
      end
    end

    context 'when required options are missing' do
      let(:options) { {} }

      it 'exits the task' do
        expect { task.run(options) }.to raise_error(SystemExit) { |e| expect(e.status).to_not be_zero }
      end
    end
  end
end
