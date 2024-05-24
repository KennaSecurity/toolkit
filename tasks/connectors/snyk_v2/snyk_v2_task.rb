# frozen_string_literal: true

require_relative "lib/snyk_v2_client"

module Kenna
  module Toolkit
    class SnykV2Task < Kenna::Toolkit::BaseTask
      SCANNER_TYPE = "Snyk"
      ISSUE_SEVERITY_MAPPING = { "critical" => 10, "high" => 6, "medium" => 4, "low" => 1, "info" => 0 }.freeze

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
            { name: "import_type",
              type: "string",
              required: false,
              default: "vulns",
              description: "what to import \"vulns\" or \"findings\". By default \"vulns\"" },
            { name: "retrieve_from",
              type: "date",
              required: false,
              default: 90,
              description: "default will be 90 days before today" },
            { name: "include_license",
              type: "boolean",
              required: false,
              default: false,
              description: "retrieve license issues." },
            { name: "projectName_strip_colon",
              type: "boolean",
              required: false,
              default: false,
              description: "strip colon and following data from Project Name - used as application identifier" },
            { name: "packageManager_strip_colon",
              type: "boolean",
              required: false,
              default: false,
              description: "strip colon and following data from packageManager - used in asset file locator" },
            { name: "package_strip_colon",
              type: "boolean",
              required: false,
              default: false,
              description: "strip colon and following data from package - used in asset file locator" },
            { name: "application_locator_mapping",
              type: "string",
              required: false,
              default: "application",
              description: "indicates which field should be used in application locator. Valid options are application and organization. Default is application." },
            { name: "page_size",
              type: "integer",
              required: false,
              default: 1000,
              description: "The number of objects per page (currently limited from 1 to 1000)." },
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "The maximum number of issues to submit to Kenna in each batch." },
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
              required: true,
              default: nil,
              description: "Snyk environment API base URL without prefix e.g. api.eu.snyk.io or api.snyk.io or api.au.snyk.io" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        initialize_options
        initialize_client

        cves = nil
        cwes = nil
        page_num = 0
        more_pages = true
        suffix = @import_findings ? "findings" : "vulns"

        kdi_batch_upload(@batch_size, "#{$basedir}/#{@options[:output_directory]}", "snyk_kdi_#{suffix}.json",
                         @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries,
                         @kdi_version) do |batch|
          org_json = client.snyk_get_orgs
          org_ids = fetch_orgs_ids(org_json)
          projects = fetch_projects(org_json)

          types = ["vuln"]
          types << "license" if @include_license

          while more_pages
            issue_json = []

            projects.keys.each_slice(500) do |sliced_ids|
              issue_filter_json = {
                "filters": {
                  "orgs": org_ids,
                  "projects": sliced_ids,
                  "isFixed": false,
                  "types": types
                }
              }
              print_debug "issue filter json = #{issue_filter_json}"

              page_num += 1
              org_ids.each do |org_id|
                issues_page_data = client.snyk_get_issues(@page_size, issue_filter_json.to_json, page_num, @from_date, @to_date, org_id)
                issue_json.concat(issues_page_data) unless issues_page_data.empty?
              end

              print_debug "issue json = #{issue_json}"
              issue_json.flatten!
            end

            if issue_json.nil? || issue_json.empty? || issue_json.length.zero?
              more_pages = false
              break
            end

            issue_json.each do |issue_obj|
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
                created_at = issue["created_at"]

                details = {
                  "url" => problem["url"],
                  "id" => issue_obj["id"],
                  "title" => issue["title"],
                  "file" => package_name,
                  "application" => application,
                  "introducedDate" => issue["created_at"],
                  "source" => problem["source"],
                  "isPatchable" => issue["coordinates"][0]["is_patchable"].to_s,
                  "isUpgradable" => issue["coordinates"][0]["is_upgradeable"].to_s,
                  "language" => nil,
                  "references" => issue["problems"].map { |p| p["url"] },
                  "cvssScore" => scanner_score,
                  "severity" => issue_severity,
                  "package" => package_name,
                  "version" => issue["coordinates"][0]["representations"][0]["dependency"]["package_version"],
                  "identifiers" => { "CVE" => [problem["id"]], "CWE" => issue["classes"].map { |c| c["id"] } },
                  "publicationTime" => issue["updated_at"]
                }.compact

                kdi_issue = {
                  "scanner_identifier" => scanner_identifier,
                  "scanner_type" => scanner_type,
                  "vuln_def_name" => vuln_def_name,
                  "scanner_score" => scanner_score,
                  "created_at" => created_at,
                  "details" => details
                }

                vuln_def = {
                  "name" => vuln_def_name,
                  "scanner_type" => scanner_type,
                  "scanner_identifier" => issue_identifier,
                  "description" => issue["title"],
                  "solution" => issue["resolution"] ? issue["resolution"]["details"] : nil
                }.compact

                batch.append do
                  create_kdi_asset_vuln(asset, kdi_issue)
                  create_kdi_vuln_def(vuln_def)
                end
              end
            end
          end
        end
        kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key if @kenna_connector_id && @kenna_api_host && @kenna_api_key
      end

      private

      attr_reader :client

      def initialize_client
        @client = Kenna::Toolkit::SnykV2::SnykV2Client.new(@snyk_api_token, @api_base_url)
      end

      def initialize_options
        @snyk_api_token = @options[:snyk_api_token]
        @api_base_url = @options[:snyk_api_base]
        @import_findings = @options[:import_type] == "findings"
        @output_directory = @options[:output_directory]
        @include_license = @options[:include_license]

        @project_name_strip_colon = @options[:projectName_strip_colon]
        @package_manager_strip_colon = @options[:packageManager_strip_colon]
        @package_strip_colon = @options[:package_strip_colon]

        @retrieve_from = @options[:retrieve_from]
        @from_date = (Date.today - @retrieve_from.to_i).strftime("%Y-%m-%d")
        @to_date = Date.today.strftime("%Y-%m-%d")

        @page_size = @options[:page_size].to_i
        @batch_size = @options[:batch_size].to_i

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
        org_ids = org_json.map { |org| org.fetch("id") }

        print_debug org_json
        print_debug "orgs = #{org_ids}"

        org_ids
      end
    end
  end
end
