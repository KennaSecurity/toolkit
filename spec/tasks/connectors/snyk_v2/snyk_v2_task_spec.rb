# frozen_string_literal: true

require "rspec_helper"
require_relative "snyk_v2_stubs"

RSpec.describe Kenna::Toolkit::SnykV2Task do
  include SnykV2Stubs
  subject(:task) { described_class.new }

  describe "#run" do
    let(:connector_run_success) { true }
    let(:kenna_client) { instance_double(Kenna::Api::Client, upload_to_connector: { "data_file" => 12 }, run_files_on_connector: { "success" => connector_run_success }) }
    let(:options) { { snyk_api_token: '2dfbc991-a5e2-487b-a19c-eeb213bd0c7c', import_type: } }

    before do
      # Eliminé los stubs porque VCR manejará las solicitudes HTTP automáticamente.
      stub_orgs_request
      stub_projects_request
      stub_issues_request

      allow(Kenna::Api::Client).to receive(:new) { kenna_client }
      spy_on_accumulators
      # Moví la ejecución de task.run(options) dentro del bloque VCR.use_cassette
      # para asegurar que las solicitudes HTTP sean capturadas o reproducidas correctamente.
    end

    context "vulnerability" do
      let(:import_type) { "vulns" }

      it "creates normalized (non-duplicative) vuln_defs" do
        VCR.use_cassette('snyk_v2_task_run') do
          task.run(options) # Ejecución de la tarea dentro del bloque VCR
        end

        expect(task.vuln_defs).to include(
          {
            "name" => "SNYK-JAVA-DUMMYORGAPACHETOMCATEMBEDXX-7430175",
            "scanner_type" => "Snyk",
            "cve_identifiers" => "CVE-2024-34750",
            "cwe_identifiers" => "CWE-613",
            "description" => "CVE-2024-34750: Insufficient Session Expiration_package_vulnerability",
            "solution" => "For more information, go to this link: https://nvd.nist.gov/vuln/detail/CVE-2024-34750"
          }
        )
      end

      it "creates normalized (non-duplicative) vulns on assets" do
        VCR.use_cassette('snyk_v2_task_run') do
          task.run(options) # Ejecución de la tarea dentro del bloque VCR
        end

        expect(task.assets).to include(
        {
          "file" => "Snyk_DUMMYORGAPACHETOMCATEMBEDXX_d62c5f6a-ABCD-41b3-EFGH-487c83881841",
          "tags" => ["Org:abcd1234-5678-90ef-ghij-klmnopqrstuv"],
          "os" => "JAVA",
          "priority" => 10,
          "findings" => [
            {
              "additional_fields" => {
                "dependency" => {
                  "package_name" => "org.apache.tomcat.embed:tomcat-embed-core",
                  "package_version" => "9.0.12"
                },
                "is_fixable_manually" => false,
                "is_fixable_snyk" => true,
                "is_fixable_upstream" => false,
                "is_patchable" => false,
                "is_upgradeable" => true,
                "reachability" => "no-info"
              },
              "created_at" => "2024-07-08T10:13:37.548Z",
              "last_seen_at" => "2024-07-08T10:13:37.548Z",
              "scanner_identifier" => "d62c5f6a-ABCD-41b3-EFGH-487c83881841",
              "scanner_type" => "Snyk",
              "severity" => 6,
              "triage_state" => "new",
              "vuln_def_name" => "SNYK-JAVA-DUMMYORGAPACHETOMCATEMBEDXX-7430175"
            }
          ],
          "vulns" => [
            {
              "created_at" => "2024-07-08T10:13:37.548Z",
              "details" => "CVE-2024-34750 : Insufficient Session Expiration_package_vulnerability",
              "last_seen_at" => "2024-07-08T10:13:37.548Z",
              "scanner_identifier" => "d62c5f6a-ABCD-41b3-EFGH-487c83881841",
              "scanner_score" => 6,
              "scanner_type" => "Snyk",
              "status" => "open",
              "vuln_def_name" => "SNYK-JAVA-DUMMYORGAPACHETOMCATEMBEDXX-7430175"
            }
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
