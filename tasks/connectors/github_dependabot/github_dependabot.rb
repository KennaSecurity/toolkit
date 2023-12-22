# frozen_string_literal: true

require_relative "lib/github_dependabot_client"
module Kenna
  module Toolkit
    class GithubDependabot < Kenna::Toolkit::BaseTask
      SCANNER_TYPE = "GitHubDependabot"

      def self.metadata
        {
          id: "github_dependabot",
          name: "github_dependabot Vulnerabilities",
          description: "Pulls assets and vulnerabilitiies from github_dependabot",
          options: [
            { name: "github_organization_name",
              type: "string",
              required: true,
              default: nil,
              description: "github organization name" },
            { name: "github_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Github Access Token" },
            { name: "github_page_size",
              type: "integer",
              required: false,
              default: 100,
              description: "Number of records to bring back with each page request from GitHub. Maximum is 100." },
            { name: "kenna_batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Maximum number of vulnerabilities to upload to Kenna in each batch." },
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
              default: "output/github_dependabot",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options
        initialize_options

        client = Kenna::Toolkit::GithubDependabotModule::GithubDependabotClient.new(@github_organization_name, @github_access_token, @page_size)

        kdi_batch_upload(@batch_size, @output_directory, "github_dependabot_kdi.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version) do |batch|
          client.repositories.each do |repo_name|
            print_good "Processing repository #{@github_organization_name}/#{repo_name}."
            vulns = client.vulnerabilities(repo_name).reject { |ad| ad["identifiers"].last.value?("GHSA") }
            batch.append do
              process_repo(repo_name, vulns)
            end
          end
        end

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end

      private

      def initialize_options
        @github_organization_name = @options[:github_organization_name]
        @github_access_token = @options[:github_token]
        @page_size = @options[:github_page_size].to_i
        @batch_size = @options[:kenna_batch_size].to_i
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @max_issues = @options[:batch_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def process_repo(repo_name, vulns)
        asset_hash = { "application" => repo_name, "tags" => [SCANNER_TYPE] }

        create_kdi_asset(asset_hash)

        vulns.each do |vuln|
          cve_identifier = vuln["identifiers"].detect { |identifier| identifier["type"] == "CVE" }
          vuln_name = cve_identifier&.fetch("value") || vuln["identifiers"].last["value"]
          number = vuln["number"]
          details = {
            "packageName" => vuln.dig("securityVulnerability", "package", "name"),
            "firstPatchedVersion" => vuln.dig("securityVulnerability", "firstPatchedVersion", "identifier"),
            "vulnerableVersionRange" => vuln.dig("securityVulnerability", "vulnerableVersionRange"),
            "dependabot_url" => "https://github.com/#{@github_organization_name}/#{repo_name}/security/dependabot/#{number}"
          }.compact
          vuln_hash = {
            "scanner_identifier" => vuln_name,
            "created_at" => vuln["createdAt"],
            "scanner_type" => SCANNER_TYPE,
            "scanner_score" => vuln["cvss"]["score"].to_i,
            "last_seen_at": Time.now.utc,
            "status": "open",
            "vuln_def_name" => vuln_name,
            "details" => JSON.pretty_generate(details)
          }.compact
          vuln_def_hash = {
            "scanner_type" => SCANNER_TYPE,
            "name" => vuln_name,
            "cve_identifiers" => (cve_identifier["value"] if cve_identifier),
            "description" => vuln["description"]
          }.compact

          create_kdi_asset_vuln(asset_hash, vuln_hash)
          create_kdi_vuln_def(vuln_def_hash)
        end
      end
    end
  end
end
