# frozen_string_literal: true

require "aws-sdk-inspector2"

module Kenna
  module Toolkit
    class AwsInspector2 < Kenna::Toolkit::BaseTask
      SCANNER_TYPE = "AWS Inspector V2"
      PRIVATE_IP_PATTERN = /^(10|127|169\.254|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\./
      def self.metadata
        {
          id: "aws_inspector2",
          name: "AWS Inspector 2",
          description: "Pulls findings from the AWS Inspector V2 API",
          options: [
            {
              name: "aws_access_key",
              type: "string",
              required: false,
              default: "",
              description: "AWS access key"
            }, {
              name: "aws_secret_key",
              type: "string",
              required: false,
              default: "",
              description: "AWS secret key"
            }, {
              name: "aws_regions",
              type: "array",
              required: false,
              default: ['us-east-1'],
              description: "AWS regions to include when collecting findings"
            }, {
              name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API key"
            }, {
              name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.kennasecurity.com",
              description: "Kenna API hostname"
            }, {
              name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector"
            }, {
              name: "output_directory",
              type: "filename",
              required: false,
              default: "output/inspector",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}"
            }, {
              name: "aws_security_token",
              type: "string",
              required: false,
              default: "",
              description: "AWS security token"
            }, {
              name: "role_arn",
              type: "string",
              required: false,
              default: "",
              description: "AWS security role used to assume access to the Audit account"
            }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        initialize_options
        kdi_initialize

        @aws_regions.each do |region|
          print_debug "Querying #{region} for findings"
          loop do
            response = get_inspector_findings(region, @aws_access_key, @aws_secret_key)
            response.findings.each do |finding|
              # We only handle package vulns for now.
              next unless finding.type == "PACKAGE_VULNERABILITY"

              # #Skip Finding if it is not an EC2 object, Kenna backend likes no ECR findings
              next unless finding.resources.first.details.aws_ec2_instance

              asset = extract_asset(finding)
              vuln = extract_asset_vuln(finding)
              definition = extract_definition(finding)

              create_kdi_asset(asset)
              create_kdi_asset_vuln(asset, vuln)
              create_kdi_vuln_def(definition)
            end

            @batch_num ||= 0
            @batch_num += 1
            kdi_upload(@output_directory, "aws_inspector2_batch_#{@batch_num}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
            @next_token = response.next_token or break
          end
        end

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end

      private

      def initialize_options
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @aws_regions = @options[:aws_regions].uniq
        @aws_access_key = @options[:aws_access_key]
        @aws_secret_key = @options[:aws_secret_key]
        @output_directory = @options[:output_directory]
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2

        # FIXME: Add support for role/token
        @aws_security_token = @options[:aws_security_token]
        @role_arn = @options[:role_arn]
      end

      def extract_asset(finding)
        resource = finding.resources.first
        name = resource.tags.delete("Name")
        hostname, fqdn = name.partition(/^*(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.){2,}[a-zA-Z]{2,63}\.?$/)
        {
          ec2: resource.id,
          fqdn:,
          hostname:,
          ip_address: resource.details.aws_ec2_instance.ip_v4_addresses.sort_by {|ip| ip[PRIVATE_IP_PATTERN].to_s }.first,
          os: resource.details.aws_ec2_instance.platform,
          tags: resource.tags.map { |tag| tag.join(':') },
          vulns: []
        }.with_indifferent_access
      end

      def extract_asset_vuln(finding)
        raise "Unhandled finding type #{finding.type}" unless finding.type == "PACKAGE_VULNERABILITY"

        cve = finding.package_vulnerability_details
        raise "Not a CVE" unless cve.vulnerability_id.include?("CVE")

        # Sometimes inspector_score is nil, in which case we set it to 1 because the Kenna Data
        # Importer requires a score. However, it's not that important because it doesn't factor into
        # the Kenna score, which is derived from proprietary data sources and models.
        numeric_severity = finding.inspector_score || 1

        {
          scanner_identifier: finding.finding_arn,
          scanner_type: SCANNER_TYPE,
          created_at: DateTime.now,
          last_seen_at: DateTime.now,
          status: finding.status == "ACTIVE" ? "open" : "closed",
          vuln_def_name: finding.title,
          scanner_score: numeric_severity.round
        }.with_indifferent_access
      end

      def extract_definition(finding)
        cve_id = finding.package_vulnerability_details.vulnerability_id
        {
          scanner_identifier: finding.finding_arn,
          scanner_type: SCANNER_TYPE,
          cve_identifiers: cve_id,
          name: finding.title,
          description: finding.description
        }.with_indifferent_access
      end

      def get_inspector_findings(region, access_key, secret_key)
        Aws::Inspector2::Client.new(
          { region:,
            credentials: Aws::Credentials.new(access_key, secret_key) }
        ).list_findings(next_token: @next_token)
      end
    end
  end
end
