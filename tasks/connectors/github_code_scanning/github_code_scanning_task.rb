# frozen_string_literal: true

require_relative "lib/github_code_scanning_client"
module Kenna
  module Toolkit
    module GithubCodeScanning
      class Task < Kenna::Toolkit::BaseTask
        SCANNER_TYPE = "GitHubCodeScanning"

        def self.metadata
          {
            id: "github_code_scanning",
            name: "GitHub Code Scanning",
            description: "Pulls Code Scanning alerts from GitHub.",
            options: [
              { name: "github_username",
                type: "api_key",
                required: true,
                default: nil,
                description: "GitHub username" },
              { name: "github_token",
                type: "api_key",
                required: true,
                default: nil,
                description: "GitHub token" },
              { name: "github_repositories",
                type: "string",
                required: true,
                default: nil,
                description: "A list of GitHub repository names (comma-separated). This is required if no organizations are specified. Use owner/repo name format, e.g. KennaSecurityOwner/toolkit" },
              { name: "github_tool_name",
                type: "string",
                required: false,
                default: nil,
                description: "The name of a code scanning tool. Only results by this tool will be imported. If not present, ALL will be imported" },
              { name: "github_state",
                type: "string",
                required: false,
                default: nil,
                description: "Set to open, fixed, or dismissed to import code scanning alerts in a specific state. If not present, ALL will be imported." },
              { name: "github_severity",
                type: "string",
                required: false,
                default: nil,
                description: "A list of [error, warning, note] (comma separated). Only code scanning alerts with one of these severities are imported. If not present, ALL will be imported." },
              { name: "github_security_severity",
                type: "string",
                required: false,
                default: nil,
                description: "A list of [critical, high, medium, or low] (comma separated). Only code scanning alerts with one of these severities are imported. If not present, ALL will be imported." },
              { name: "github_page_size",
                type: "integer",
                required: false,
                default: 100,
                description: "Maximum number of alerts to retrieve in each page. Maximum is 100." },
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
                default: "output/github_code_scanning",
                description: "If set, will write a file upon completion. Path is relative to #{$basedir}" },
              # 1. add organization option here
              { name: "github_organizations",
                type: "string",
                required: true, 
                default: nil, 
                description: "Input your Organizations name here (comma-separated). This is required if no repositories are specified. Use organization name format, e.g. KennaSecurityOrg" }
            ]
          }
        end

        def run(opts)
          super
          initialize_options
          initialize_client

          # 3. conditionally set up the endpoint based on input
          if !@repositories.empty? && @organizations.empty?
            @repositories.each do |repo|
              endpoint = "/repos/#{repo}/code-scanning/alerts"
              import_alerts(repo, endpoint)
            end
          elsif @repositories.empty? && !organizations.empty?
            @organizations.each do |org|
              endpoint = "/orgs/#{org}/code-scanning/alerts"
              import_alerts(org, endpoint)
            end
          else   
            puts "You can only input Organizations or Repositories. You cannot specify both"
            break
          end

          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        rescue Kenna::Toolkit::Sample::Client::ApiError => e
          fail_task e.message
        end

        private

        def initialize_options
          @username = @options[:github_username]
          @token = @options[:github_token]
          @repositories = extract_list(:github_repositories, [])
          # 2. extract organizations from the list
          @organizations = extract_list(:github_organizations, [])
          @tool_name = @options[:github_tool_name]
          @state = @options[:github_state]
          @severity = extract_list(:github_severity)
          @security_severity = extract_list(:github_security_severity)
          @page_size = @options[:github_page_size].to_i
          @output_directory = @options[:output_directory]
          @kenna_api_host = @options[:kenna_api_host]
          @kenna_api_key = @options[:kenna_api_key]
          @kenna_connector_id = @options[:kenna_connector_id]
          @skip_autoclose = false
          @retries = 3
          @kdi_version = 2
          validate_options
        end

        # Map needed when the source data value isn't in the range 0 - 10
        SEVERITY_VALUE = {
          "low" => 3,
          "medium" => 6,
          "high" => 8,
          "critical" => 10
        }.freeze

        def initialize_client
          @client = Kenna::Toolkit::GithubCodeScanning::Client.new(@username, @token)
        end

        def extract_list(key, default = nil)
          list = (@options[key] || "").split(",").map(&:strip)
          list.empty? ? default : list
        end

        def validate_options
          fail_task("Invalid task parameters. Maximum page size is 100.") if @page_size > 100
          fail_task("Invalid task parameters. state must be one of [open, fixed, dismissed] if present.") unless [nil, "open", "fixed", "dismissed"].include?(@state)
        end

        def import_alerts(orgORrepo, endpoint)
          # 4. rename the variables to orgOrrepo
          page = 1
          while (alerts = @client.code_scanning_alerts(endpoint, page, @page_size, @state, @tool_name)).present?
            alerts.each do |alert|
              next unless import?(alert)

              asset = extract_asset(alert, orgORrepo)
              finding = extract_finding(alert, orgORrepo)
              definition = extract_definition(alert)

              create_kdi_asset_finding(asset, finding)
              create_kdi_vuln_def(definition)
            end

            print_good("Processed #{alerts.count} alerts for #{orgORrepo}.")
            kdi_upload(@output_directory, "github_code_scanning_#{orgORrepo.tr('/', '_')}_report_#{page}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
            puts kdi_upload(@output_directory, "github_code_scanning_#{orgORrepo.tr('/', '_')}_report_#{page}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
            page += 1
          end
        end

        # This works like a filter because it's useful and GitHub API doesn't provide the functionality in the API
        def import?(alert)
          (@severity.blank? || @severity.include?(alert.dig("rule", "severity"))) && (@security_severity.blank? || @security_severity.include?(alert.dig("rule", "security_severity_level")))
        end

        def extract_asset(alert, orgORrepo)
          # 5. refactor the variable name to orgOrrepo
          asset = {
            "url" => alert.fetch("html_url"),
            "file" => alert.fetch("most_recent_instance").fetch("location").fetch("path"),
            "application" => orgORrepo
          }
          asset.compact
        end

        def extract_finding(alert, orgORrepo)
          severity = alert.dig("rule", "security_severity_level")
          # 6. conditionally construct the additional field
          additional_fields = if !@repositories.empty?
                                { "Repository": orgORrepo }.merge(extract_additional_fields(alert))  
                              else 
                                { "Organization": orgORrepo }.merge(extract_additional_fields(alert))
                              end

          {
            "url" => alert.fetch("url"),
            "scanner_identifier" => alert.fetch("number"),
            "created_at" => alert.fetch("created_at"),
            "last_seen_at" => alert.fetch("updated_at"),
            "scanner_type" => SCANNER_TYPE,
            "vuln_def_name" => vuln_def_name(alert),
            "severity" => (SEVERITY_VALUE[severity] if severity),
            "triage_state" => triage_value(alert.fetch("state")),
            "additional_fields" => additional_fields
          }.compact
        end

        def extract_definition(alert)
          definition = {
            "name" => vuln_def_name(alert),
            "scanner_type" => SCANNER_TYPE
          }
          definition["description"] = alert.dig("rule", "description") unless alert.dig("rule", "description").empty?
          definition.compact
        end

        def extract_additional_fields(alert)
          fields = {
            "Url" => alert["html_url"],
            "State" => alert["state"],
            "Fixed at" => alert["fixed_at"],
            "Dismissed at" => alert["dismissed_at"],
            "Dismissed by" => alert.dig("dismissed_by", "login"),
            "Dismissed reason" => alert["dismissed_reason"],
            "Rule" => shallow_hash(alert["rule"]).compact,
            "Tool" => shallow_hash(alert["tool"]).compact,
            "Most recent instance" => shallow_hash(alert.fetch("most_recent_instance")).compact
          }
          fields.compact
        end

        def vuln_def_name(alert)
          alert.fetch("rule").fetch("name")
        end

        def triage_value(triage)
          case triage
          when "open"
            "new"
          when "fixed"
            "resolved"
          else
            "not_a_security_issue"
          end
        end

        # Return a hash for the first level of the argument hash.
        # More depth hashes are passed as JSON
        # THis is needed for a bug present in AppSec UI
        def shallow_hash(hash)
          hash.transform_values { |v| v.is_a?(Enumerable) ? JSON.pretty_generate(v) : v }
        end
      end
    end
  end
end
