# frozen_string_literal: true

require_relative "lib/qualys_was_helper"
require "json"
require "pry"

module Kenna
  module Toolkit
    class QualysWas < Kenna::Toolkit::BaseTask
      include Kenna::Toolkit::QualysWasHelper

      def self.metadata
        {
          id: "qualys_was",
          name: "qualys_was Vulnerabilities",
          description: "Pulls assets and vulnerabilitiies from qualys_was",
          options: [
            { name: "qualys_was_console",
              type: "hostname",
              required: true,
              default: nil,
              description: "Your qualys_was Console hostname (without protocol and port), e.g. app.qualys_wassecurity.com" },
            { name: "qualys_was_console_port",
              type: "integer",
              required: false,
              default: nil,
              description: "Your qualys_was Console port, e.g. 8080" },
            { name: "qualys_was_user",
              type: "user",
              required: true,
              default: nil,
              description: "qualys_was Username" },
            { name: "qualys_was_password",
              type: "password",
              required: true,
              default: nil,
              description: "qualys_was Password" },
            { name: "container_data",
              type: "boolean",
              required: false,
              default: "false",
              description: "Optional filter to limit vulnerabilities using a comma separated list of severities (e.g. CRITICAL,HIGH)" },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.kennasecurity.com",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/qualys_was",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        username = @options[:qualys_was_user]
        password = @options[:qualys_was_password]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]

        token = qualys_was_get_token(username, password)
        web_apps = qualys_was_get_webapp(token)
        vuln_hsh = {}
        web_apps["ServiceResponse"]["data"].each do |web_app|
          web_app_id = web_app["WebApp"]["id"]
          findings = qualys_was_get_webapp_findings(web_app_id, token)
          next unless findings.present?

          findings.map do |_, finding|
            qids = findings["ServiceResponse"]["data"].map { |x| x["Finding"]["qid"] }.uniq
            vulns = qualys_was_get_vuln(qids, token)
            vulns = JSON.parse(vulns)["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"].group_by do |vuln|
              vuln["QID"]
            end

            vuln_hsh.merge!(vulns)

            finding["data"].each do |data|
              find_from = data["Finding"]

              asset = {
                "url" => "",
                "application_identifier" => find_from["webApp"]["name"]
              }
              asset.compact!

              details = {
                "potential" => find_from["potential"],
                "result_list" => find_from["resultList"]["list"]
              }

              details.tap do |t|
                t.merge!(find_from["owasp"]) if find_from["owasp"].present?
                t.merge!(find_from["wasc"]) if find_from["wasc"].present?
              end

              details.compact!

              # start finding section
              finding = {
                "scanner_identifier" => find_from["id"],
                "scanner_type" => "QualysWas",
                "severity" => find_from["severity"] * 2,
                "created_at" => find_from["firstDetectedDate"],
                "last_seen_at" => find_from["lastTestedDatee"],
                "additional_fields" => details,
                "triage_state" => find_from["status"],
                "vuln_def_name" => find_from["name"]
              }
              # in case any values are null, it"s good to remove them
              finding.compact!

              vuln_def = {
                "name" => find_from["name"],
                "scanner_type" => "QualysWas"
              }

              vuln_def.tap do |t|
                if vuln_hsh[find_from["qid"].to_s].present?
                  diagnosis = vuln_hsh[find_from["qid"].to_s].last["DIAGNOSIS"]
                  solution = vuln_hsh[find_from["qid"].to_s].last["solution"]
                  t["description"] = diagnosis
                  t["solution"] = solution
                end
                t["cwe_id"] = find_from["cwe"]["list"].first if find_from["cwe"].present?
              end

              vuln_def.compact!

              # Create the KDI entries
              create_kdi_asset_finding(asset, finding)
              create_kdi_vuln_def(vuln_def)
            end
          end

          ### Write KDI format
          output_dir = "#{$basedir}/#{@options[:output_directory]}"
          filename = "qualys_was_#{web_app_id}.json"
          print_good "Output is available at: #{output_dir}/#{filename}"
          print_good "Attempting to upload to Kenna API"
          kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
        end
      end
    end
  end
end
