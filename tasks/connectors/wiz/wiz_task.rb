# frozen_string_literal: true

require_relative "lib/wiz_client"
require_relative "lib/issues_mapper"
require_relative "lib/vulns_mapper"
module Kenna
  module Toolkit
    class WizTask < Kenna::Toolkit::BaseTask
      def self.metadata
        {
          id: "wiz",
          name: "WIZ",
          description: "Pulls assets, vulnerabilities and issues from WIZ",
          options: [
            { name: "wiz_client_id",
              type: "string",
              required: true,
              default: nil,
              description: "WIZ client id" },
            { name: "wiz_client_secret",
              type: "api_key",
              required: true,
              default: nil,
              description: "WIZ client secret" },
            { name: "wiz_auth_endpoint",
              type: "hostname",
              required: false,
              default: "auth.app.wiz.io",
              description: "WIZ auth endpoint hostname used to get the authorization token." },
            { name: "wiz_api_host",
              type: "hostname",
              required: true,
              default: nil,
              description: "WIZ API Endpoint URL. If schema is included, it should be between double quotes escaped." },
            { name: "vuln_page_size",
              type: "integer",
              required: false,
              default: 5000,
              description: "Maximum number of vulnerabilities to retrieve in each page." },
            { name: "issue_page_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Maximum number of issues to retrieve in each page." },
            { name: "days_back",
              type: "integer",
              required: false,
              default: nil,
              description: "Integer days number to get the vulnerabilities/issues detected x days back TODAY." },
            { name: "vuln_object_types",
              type: "string",
              required: false,
              default: nil,
              description: "Array of object types for VULNS import. Allowed values: VIRTUAL_MACHINE,CONTAINER_IMAGE,SERVERLESS. Import all if not present." },
            { name: "severity",
              type: "string",
              required: false,
              default: nil,
              description: "Array of severity types for VULNS and ISSUES (ALL) import. Allowed values: CRITICAL,HIGH,MEDIUM,LOW,INFO. Import all if not present." },
            { name: "issue_status",
              type: "string",
              required: false,
              default: nil,
              description: "Array of issue status for ISSUES import. Allowed values: OPEN,IN_PROGRESS,RESOLVED,REJECTED. Import all if not present." },
            { name: "import_type",
              type: "string",
              required: false,
              default: "ISSUES",
              description: "What to import, ISSUES, VULNS or ALL" },
            { name: "issues_external_id_attr",
              type: "string",
              required: false,
              default: nil,
              description: "For ISSUES, the entitySnapshot attribute used to map Kenna asset's external_id, for instance, `providerId` or `resourceGroupExternalId`. If not present or the value for the passed attribute is not present the provideId attribute value is used." },
            { name: "vulns_external_id_attr",
              type: "string",
              required: false,
              default: nil,
              description: "For VULNS, the `vulnerableEntity` attribute used to map Kenna asset's external_id, for instance, `id`, `providerUniqueId` or `name`. If not present or the value for the passed attribute is not present the `id` attribute value is used." },
            { name: "issues_hostname_attr",
              type: "string",
              required: false,
              default: nil,
              description: "For ISSUES, the entitySnapshot attribute used to map Kenna asset's hostname, for instance, `name`, `subscriptionId`, `subscriptionExternalId`, `subscriptionName`, `resourceGroupId`, `resourceGroupExternalId`, `providerId`. If not present or the value for the passed attribute is not present the `name` attribute value is used." },
            { name: "vulns_hostname_attr",
              type: "string",
              required: false,
              default: nil,
              description: "For VULNS, the `vulnerableEntity` attribute used to map Kenna asset's hostname, for instance, `name`, `providerUniqueId` or `subscriptionExternalId` . If not present or the value for the passed attribute is not present the `name` attribute value is used." },
            { name: "kenna_batch_size",
              type: "integer",
              required: false,
              default: 1000,
              description: "Maximum number of vulnerabilities to upload to Kenna in each batch. Increasing this value could improve performance." },
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
              default: "output/wiz",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super
        initialize_options
        initialize_client

        import_issues if import?("issues")
        import_vulns if import?("vulns")

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::Toolkit::Sample::Client::ApiError => e
        fail_task e.message
      end

      private

      attr_reader :client

      def initialize_client
        @client = Wiz::Client.new(@client_id, @client_secret, @auth_endpoint, @api_host, @page_size_vulns, @page_size_issues, @days_back, @vuln_object_types, @severity, @issue_status)
      end

      def initialize_options
        validate_options
        @client_id = @options[:wiz_client_id]
        @client_secret = @options[:wiz_client_secret]
        @auth_endpoint = @options[:wiz_auth_endpoint].start_with?("http") ? "#{@options[:wiz_auth_endpoint]}/oauth/token" : "https://#{@options[:wiz_auth_endpoint]}/oauth/token"
        @api_host = @options[:wiz_api_host].start_with?("http") ? "#{@options[:wiz_api_host]}/graphql" : "https://#{@options[:wiz_api_host]}/graphql"
        @vuln_object_types = extract_list(:vuln_object_types)
        @severity = extract_list(:severity)
        @issue_status = extract_list(:issue_status)
        @days_back = @options[:days_back].to_i if @options[:days_back].present?
        @page_size_vulns = @options[:vuln_page_size].to_i if @options[:vuln_page_size].present?
        @page_size_issues = @options[:issue_page_size].to_i if @options[:issue_page_size].present?
        @import_type = @options[:import_type].downcase
        @issues_external_id_attr = @options[:issues_external_id_attr]
        @vulns_external_id_attr = @options[:vulns_external_id_attr]
        @issues_hostname_attr = @options[:issues_hostname_attr]
        @vulns_hostname_attr = @options[:vulns_hostname_attr]
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @kenna_batch_size = @options[:kenna_batch_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def validate_options
        fail_task("`external_id_attr` option was renamed to `issues_external_id_attr`. Please update your task parameters.") if @options[:external_id_attr].present?
      end

      def extract_list(key, default = nil)
        list = (@options[key] || "").split(",").map(&:strip)
        list.empty? ? default : list
      end

      def import?(type)
        @import_type == type || @import_type == "all"
      end

      def import_issues
        print_good "Issues import started."
        import(client.paged_issues, @page_size_issues, Wiz::IssuesMapper.new(@issues_external_id_attr, @issues_hostname_attr))
      end

      def import_vulns
        print_good "Vulns import started."
        import(client.paged_vulns, @page_size_vulns, Wiz::VulnsMapper.new(@vulns_external_id_attr, @vulns_hostname_attr))
      end

      def import(pages, page_size, mapper)
        pos = 0
        total_count = nil
        kdi_batch_upload(@kenna_batch_size, @output_directory, "wiz_#{mapper.plural_name.downcase}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version) do |batch|
          pages.each do |page|
            total_count ||= page["totalCount"]
            nodes = page["nodes"]
            nodes.each do |node|
              asset = mapper.extract_asset(node)
              vuln = mapper.extract_vuln(node)
              definition = mapper.extract_definition(node)
              batch.append do
                create_kdi_asset_vuln(asset, vuln)
                create_kdi_vuln_def(definition)
              end
            end
            print_good("Processed #{[pos + page_size, total_count].min} of #{total_count} #{mapper.plural_name.downcase}.")
            pos += page_size
          end
        end
      end
    end
  end
end
