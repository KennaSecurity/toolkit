# frozen_string_literal: true

require_relative "lib/qualys_was_helper"
require "json"
require "pry"
require "uri"

module Kenna
  module Toolkit
    class QualysWas < Kenna::Toolkit::BaseTask
      include Kenna::Toolkit::QualysWasHelper

      STATUS = {
        "new" => "new",
        "active" => "new",
        "reopened" => "new",
        "fixed" => "resolved",
        "retesting" => "in process",
        "protected" => "remediated"
      }.freeze

      IGNORE_STATUS = {
        "false_positive" => "false positive",
        "risk_accepted" => "risk accepted",
        "not_applicable" => "not_a_security_issue"
      }.freeze

      def self.metadata
        {
          id: "qualys_was",
          name: "qualys_was Vulnerabilities",
          description: "Pulls assets and vulnerabilitiies from qualys_was",
          options: [
            { name: "qualys_was_domain",
              type: "hostname",
              required: true,
              default: nil,
              description: "Your qualys_was api base url (with protocol and port), e.g. qualysapi.qg3.apps.qualys.com" },
            { name: "qualys_was_api_version_url",
              type: "integer",
              required: false,
              default: nil,
              description: "Your qualys_was_api_version_url, e.g. /qps/rest/3.0/" },
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

        initialize_options

        token = qualys_was_get_token(@username, @password)
        web_apps = qualys_was_get_webapp(token)
        fail_task "Unable to retrieve webapps, please check credentials" unless web_apps

        vuln_hsh = {}
        total_count = 0

        web_apps.each do |individual_web_app|
          next unless individual_web_app.present?

          individual_web_app["ServiceResponse"]["data"].each do |web_app|
            web_app_id = web_app["WebApp"]["id"]
            findings = qualys_was_get_webapp_findings(web_app_id, token)
            next unless findings.present?

            findings.each do |findg|
              findg.map do |_, finding|
                qids = findg["ServiceResponse"]["data"].map { |x| x["Finding"]["qid"] }.uniq
                vulns = qualys_was_get_vuln(qids, token)
                vulns = JSON.parse(vulns)["KNOWLEDGE_BASE_VULN_LIST_OUTPUT"]["RESPONSE"]["VULN_LIST"]["VULN"].group_by do |vuln|
                  vuln["QID"]
                end

                vuln_hsh.merge!(vulns)
                web_app_finding_count = finding["data"].try(:count).to_i
                print_debug "Total Finding for #{web_app_id} is #{web_app_finding_count}"
                total_count += web_app_finding_count

                finding["data"].each do |data|
                  find_from = data["Finding"]

                  asset = {
                    "url" => find_from["webApp"]["url"],
                    "application" => find_from["webApp"]["name"].presence || domain_detail(find_from)
                  }
                  asset.compact!

                  details = {
                    "potential" => find_from["potential"]
                  }.tap do |d|
                    d["result_list"] = find_from["resultList"]["list"].to_json if find_from["resultList"]["list"].present?
                  end

                  details.tap do |t|
                    t.merge!(find_from["owasp"]) if find_from["owasp"].present?
                    t.merge!(find_from["wasc"]) if find_from["wasc"].present?
                  end
                  details.compact!

                  # start finding section
                  finding_data = {
                    "scanner_identifier" => find_from["id"],
                    "scanner_type" => "QualysWas",
                    "severity" => find_from["severity"].to_i * 2,
                    "created_at" => find_from["firstDetectedDate"],
                    "last_seen_at" => find_from["lastTestedDatee"],
                    "additional_fields" => details,
                    "vuln_def_name" => name(find_from)
                  }.tap do |f|
                    f["triage_state"] = status(find_from) if find_from["status"].present?
                  end
                  # in case any values are null, it's good to remove them
                  finding_data.compact!

                  vuln_def = {
                    "name" => name(find_from),
                    "scanner_type" => "QualysWas"
                  }

                  vuln_def.tap do |t|
                    if vuln_hsh[find_from["qid"].to_s].present?
                      diagnosis = vuln_hsh[find_from["qid"].to_s].last["DIAGNOSIS"]
                      solution = vuln_hsh[find_from["qid"].to_s].last["solution"]
                      t["description"] = remove_html_tags(diagnosis) if diagnosis.present?
                      t["solution"] = remove_html_tags(solution) if solution.present?
                    end
                    t["cwe_identifiers"] = "CWE-#{find_from['cwe']['list'].first}" if find_from["cwe"].present?
                  end

                  vuln_def.compact!

                  # Create the KDI entries
                  create_kdi_asset_finding(asset, finding_data)
                  create_kdi_vuln_def(vuln_def)
                end
              end
            end

            ### Write KDI format
            output_dir = "#{$basedir}/#{@options[:output_directory]}"
            filename = "qualys_was_#{web_app_id}.json"
            print_good "Output is available at: #{output_dir}/#{filename}"
            print_good "Attempting to upload to Kenna API"
            kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, @retries, @kdi_version
          end
        end
        print_debug "Total Finding of qualys was is #{total_count}"
        # Total count of findings
        # this method will automatically use the stored array of uploaded files when calling the connector
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end

      private

      def initialize_options
        @username = @options[:qualys_was_user]
        @password = @options[:qualys_was_password]
        @qualys_was_domain = @options[:qualys_was_domain]
        @qualys_was_api_version_url = @options[:qualys_was_api_version_url] || "/qps/rest/3.0/"
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @base_url = @qualys_was_domain + @qualys_was_api_version_url
        @retries = 3
        @kdi_version = 2
      end

      def domain_detail(find_from)
        uri = URI.parse(find_from["webApp"]["url"])
        uri.host
      end

      def name(find_from)
        "#{find_from['qid']}-#{find_from['name']}"
      end

      def status(find_from)
        if find_from["isIgnored"] == "true"
          IGNORE_STATUS[find_from["ignoredReason"].downcase]
        else
          STATUS[find_from["status"].downcase]
        end
      end
    end
  end
end
