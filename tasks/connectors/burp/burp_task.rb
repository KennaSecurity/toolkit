# frozen_string_literal: true

require_relative "lib/burp_client"
module Kenna
  module Toolkit
    #noinspection DuplicatedCode
    class BurpTask < Kenna::Toolkit::BaseTask
      def self.metadata
        {
          id: "burp",
          name: "Burp",
          description: "Pulls assets and vulnerabilitiies from Burp",
          options: [
            { name: "burp_api_host",
              type: "hostname",
              required: true,
              default: nil,
              description: "Burp instance hostname, e.g. http://burp.example.com:8080" },
            { name: "burp_site_id",
              type: "string",
              required: true,
              default: nil,
              description: "Burp Site ID" },
            { name: "burp_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Burp User API token" },
            { name: "vulnerabilities_since",
              type: "integer",
              required: false,
              default: nil,
              description: "integer days number to get the vulnerabilities detected SINCE x days" },
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
              default: "output/burp",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        @host = @options[:burp_api_host]
        @site_id = @options[:burp_site_id]
        @api_token = @options[:burp_api_token]
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        skip_autoclose = false
        retries = 3
        kdi_version = 2

        client = Kenna::Toolkit::Burp::BurpClient.new(@host, @api_token)

        last_scan = client.get_last_site_scan(@site_id)
        return unless last_scan

        issues = client.get_scan(last_scan["id"])["issues"]
        issues.each do |issue|
          asset = extract_asset(issue)
          finding = extract_finding(issue)
          definition = extract_definition(issue)

          create_kdi_asset_finding(asset, finding)
          create_kdi_vuln_def(definition)
        end

        kdi_upload(@output_directory, "burp_scan_report.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, skip_autoclose, retries, kdi_version)
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end

      private

      SEVERITY_VALUE = {
        "info" => 0,
        "low" => 3,
        "medium" => 6,
        "high" => 10
      }.freeze

      def extract_asset(issue)
        {
          "url" => "#{issue['origin']}#{issue['path']}",
          "application" => issue["origin"]
        }.compact
      end

      def extract_finding(issue)
        {
          "scanner_identifier" => issue["serial_number"],
          "scanner_type" => "BurpSuite",
          "vuln_def_name" => issue["issue_type"]["name"],
          "severity" => SEVERITY_VALUE[issue["severity"]],
          "triage_state" => triage_value(issue["confidence"]),
          "additional_fields" => [{ "novelty" => issue["novelty"] }]
        }.compact
      end

      def extract_definition(issue)
        {
          "name" => issue["issue_type"]["name"],
          "description" => issue["issue_type"]["description_html"],
          "solution" => issue["issue_type"]["remediation_html"],
          "scanner_type" => "BurpSuite"
        }.compact
      end

      def triage_value(triage)
        triage == "false_positive" ? "false_positive" : "new"
      end

    end
  end
end
