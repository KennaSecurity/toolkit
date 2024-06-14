# frozen_string_literal: true

require_relative "lib/snyk_v2_client"

module Kenna
  module Toolkit
    class SnykV2Task < Kenna::Toolkit::BaseTask
      SCANNER_TYPE = "Snyk"
      ISSUE_SEVERITY_MAPPING = { "critical" => 10, "high" => 6, "medium" => 4, "low" => 1, "info" => 0 }.freeze

      attr_reader :vuln_defs, :assets

      def self.metadata
        {
          id: "snyk_v2",
          name: "Snyk V2",
          description: "Pulls assets and vulnerabilities or findings from Snyk",
          options: [
            { name: "snyk_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Snyk API Token" },
            { name: "retrieve_from",
              type: "date",
              required: false,
              default: 30,
              description: "default will be 30 days before today format: YYYY-MM-DD" },
            { name: "include_license",
              type: "boolean",
              required: false,
              default: false,
              description: "retrieve license issues." },
            { name: "page_size",
              type: "integer",
              required: false,
              default: 100,
              description: "The number of objects per page (Min 10 |Max 100| multiple of 10)." },
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "The maximum number of issues to submit to Kenna in each batch." },
            { name: "page_num",
              type: "integer",
              required: false,
              default: 5000,
              description: "Max pagination number" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
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
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/snyk",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" },
            { name: "snyk_api_base",
              type: "string",
              required: false,
              default: "api.snyk.io",
              description: "Snyk environment API base URL without prefix e.g. api.eu.snyk.io, api.snyk.io or api.au.snyk.io" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        initialize_options
        initialize_client

        @vuln_defs = []
        @assets = []

        suffix = "findings_vulns"

        kdi_batch_upload(@batch_size, "#{$basedir}/#{@options[:output_directory]}", "snyk_kdi_#{suffix}.json",
                         @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries,
                         @kdi_version) do |batch|
          org_json = client.snyk_get_orgs
          org_ids = fetch_orgs_ids(org_json)
          projects = fetch_projects(org_json)

          types = ["vuln"]
          types << "license" if @include_license

          issue_json = []
          projects.keys.each_slice(500) do
            org_ids.each do |org_id|
              issues_page_data = client.snyk_get_issues(@page_size, @page_num, @from_date, @to_date, org_id)
              issue_json.concat(issues_page_data) unless issues_page_data.empty?
            end

            print_debug "issue json = #{issue_json}"
          end

          issue_json.each do |issue_arr|
            issue_arr.each do |issue_obj|
              issue = issue_obj["attributes"]
              project = issue_obj["relationships"]["scan_item"]["data"]
              org_id = issue_obj["relationships"]["organization"]["data"]["id"]

              application = project.fetch("id")
              package_name = issue["coordinates"][0]["representations"][0]["dependency"]["package_name"]
              tags = ["Org:#{org_id}"]

              asset = {
                "file" => package_name,
                "application" => application,
                "tags" => tags
              }

              issue_identifier = issue["key"]
              issue_severity = issue["effective_severity_level"]
              scanner_score = ISSUE_SEVERITY_MAPPING[issue_severity]

              issue["problems"].each do |problem|
                next unless problem["source"] == "NVD"

                scanner_identifier = "#{issue_identifier}-#{problem['id']}"
                scanner_type = "Snyk"
                vuln_def_name = problem["id"]
                created_at = format_date(issue["created_at"])

                additional_fields = {
                  "is_fixable_manually" => issue["coordinates"][0]["is_fixable_manually"],
                  "is_fixable_snyk" => issue["coordinates"][0]["is_fixable_snyk"],
                  "is_fixable_upstream" => issue["coordinates"][0]["is_fixable_upstream"],
                  "is_patchable" => issue["coordinates"][0]["is_patchable"],
                  "is_upgradeable" => issue["coordinates"][0]["is_upgradeable"],
                  "reachability" => issue["coordinates"][0]["reachability"],
                  "dependency" => issue["coordinates"][0]["representations"][0]["dependency"]
                }.compact

                finding = {
                  "scanner_identifier" => scanner_identifier,
                  "vuln_def_name" => vuln_def_name,
                  "scanner_type" => scanner_type,
                  "created_at" => created_at,
                  "last_seen_at" => format_date(issue["updated_at"]),
                  "severity" => scanner_score,
                  "additional_fields" => additional_fields
                }

                kdi_issue = {
                  "scanner_identifier" => scanner_identifier,
                  "scanner_type" => scanner_type,
                  "vuln_def_name" => vuln_def_name,
                  "last_seen_at" => format_date(issue["updated_at"]),
                  "scanner_score" => scanner_score,
                  "created_at" => created_at
                }

                vuln_def = {
                  "name" => vuln_def_name,
                  "scanner_type" => scanner_type,
                  "scanner_identifier" => issue_identifier,
                  "description" => issue["title"],
                  "solution" => issue["resolution"] ? issue["resolution"]["details"] : nil
                }.compact

                batch.append do
                  create_kdi_asset_finding(asset, finding)
                  create_kdi_asset_vuln(asset, kdi_issue)
                  create_kdi_vuln_def(vuln_def)
                end

                @vuln_defs << vuln_def
                @assets << asset
              end
            end
          end
        end
        kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key if @kenna_connector_id && @kenna_api_host && @kenna_api_key
      end

      private

      attr_reader :client

      def initialize_client
        @client = Kenna::Toolkit::SnykV2::SnykV2Client.new(@snyk_api_token, @snyk_api_base)
      end

      def initialize_options
        @snyk_api_token = @options[:snyk_api_token]
        @snyk_api_base = @options[:snyk_api_base]
        @output_directory = @options[:output_directory]
        @include_license = @options[:include_license]

        @retrieve_from = @options[:retrieve_from]
        @from_date = "#{(Date.today - @retrieve_from.to_i).strftime('%Y-%m-%d')}T00:00:00Z"
        @to_date = "#{Date.today.strftime('%Y-%m-%d')}T00:00:00Z"

        @page_size = @options[:page_size].to_i
        @batch_size = @options[:batch_size].to_i
        @page_num = @options[:page_num].to_i

        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]

        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def fetch_projects(org_json)
        {}.tap do |projects|
          org_json.each do |org|
            client.snyk_get_projects(org.fetch("id")).each do |project|
              projects[project.fetch("id")] = project.merge("org" => org)
            end
          end
        end
      end

      def fetch_orgs_ids(org_json)
        org_ids = Array.wrap(org_json).map { |org| org.fetch("id") }

        print_debug org_json
        print_debug "orgs = #{org_ids}"

        org_ids
      end

      def format_date(date_string)
        date_string.include?('T') ? date_string : "#{date_string}T00:00:00Z"
      end
    end
  end
end
