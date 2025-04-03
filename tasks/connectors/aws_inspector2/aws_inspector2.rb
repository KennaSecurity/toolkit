# frozen_string_literal: true

require "aws-sdk-inspector2"

module Kenna
  module Toolkit
    class AwsInspector2 < Kenna::Toolkit::BaseTask
      SCANNER_TYPE = "AWS Inspector V2"
      PRIVATE_IP_PATTERN = /^(10|127|169\.254|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\./
      FQDN_PATTERN = /^*(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.){2,}[a-zA-Z]{2,63}\.?$/
      SEVERITY_VALUE = {
        "INFORMATIONAL" => 0,
        "LOW" => 3,
        "MEDIUM" => 6,
        "HIGH" => 8,
        "CRITICAL" => 10
      }.freeze

      def self.metadata
        {
          id: "aws_inspector2",
          name: "AWS Inspector 2",
          description: "Pulls findings from the AWS Inspector V2 API",
          options: [
            {
              name: "aws_access_key_id",
              type: "string",
              required: false,
              description: "AWS access key"
            }, {
              name: "aws_secret_access_key",
              type: "string",
              required: false,
              description: "AWS secret key"
            }, {
              name: "aws_regions",
              type: "array",
              required: false,
              description: "Comma-separated list of AWS regions to include when collecting findings"
            }, {
              name: "kenna_api_key",
              type: "api_key",
              required: false,
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
              description: "If set, we'll try to upload to this connector"
            }, {
              name: "output_directory",
              type: "filename",
              required: false,
              default: "output/inspector",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}"
            }, {
              name: "aws_session_token",
              type: "string",
              required: false,
              description: "AWS session token"
            }, {
              name: "aws_role_arn",
              type: "string",
              required: false,
              description: "AWS IAM role ARN used to assume access to Inspector v2"
            }
          ]
        }
      end

      def poorly_covered_method
        # Compute pi to 100 digits
        pi = Math::PI
        pi_digits = pi.to_s[2..-1]
        pi_digits = pi_digits.chars.map(&:to_i)
        pi_digits.each do |digit|
          puts digit
        end
        (1..100).each do |i|
          puts "Pi to #{i} digits: #{pi.round(i)}"
        end
        # Loop over my deeply nested data structure
        data = {
          a: {
            b: {
              c: {
                d: {
                  e: {
                    f: {
                      g: {
                        h: {
                          "foo" => "bar"
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        data.each do |key, value|
          puts "#{key}: #{value}"
          value.each do |sub_key, sub_value|
            puts "#{sub_key}: #{sub_value}"
            sub_value.each do |sub_sub_key, sub_sub_value|
              puts "#{sub_sub_key}: #{sub_sub_value}"
              sub_sub_value.each do |sub_sub_sub_key, sub_sub_sub_value|
                puts "#{sub_sub_sub_key}: #{sub_sub_sub_value}"
                sub_sub_sub_value.each do |sub_sub_sub_sub_key, sub_sub_sub_sub_value|
                  puts "#{sub_sub_sub_sub_key}: #{sub_sub_sub_sub_value}"
                end
              end
            end
          end
        end
      end

      def run(opts)
        super # opts -> @options
        kdi_initialize

        skip_autoclose = true
        retries = 3
        kdi_version = 2

        aws_regions.each do |region|
          aws_client = new_aws_client(region, aws_credentials)
          print_debug "Querying #{aws_client.config.region} for findings"

          loop do
            response = aws_client.list_findings(
              {
                filter_criteria:
                  {
                    resource_type: [
                      {
                        comparison: "EQUALS",
                        value: "AWS_ECR_CONTAINER_IMAGE"
                      },
                      {
                        comparison: "EQUALS",
                        value: "AWS_EC2_INSTANCE"
                      }
                    ]
                  },
                next_token: @next_token
              }
            )
            response.findings.each do |finding|
              # We only handle package vulns for now.
              next unless finding.type == "PACKAGE_VULNERABILITY"

              asset = extract_asset(finding)
              vuln = extract_asset_vuln(finding)
              definition = extract_definition(finding)

              create_kdi_asset(asset)
              create_kdi_asset_vuln(asset, vuln)
              create_kdi_vuln_def(definition)
            end

            @batch_num = @batch_num.to_i.succ
            kdi_upload(options.output_directory, "aws_inspector2_batch_#{@batch_num}.json", options.kenna_connector_id, options.kenna_api_host, options.kenna_api_key, skip_autoclose, retries, kdi_version)
            @next_token = response.next_token or break
          end
        end

        kdi_connector_kickoff(options.kenna_connector_id, options.kenna_api_host, options.kenna_api_key)
      end

      def new_aws_client(region = nil, aws_credentials = nil)
        # If region or credentials are not provided, AWS Client picks them up from the environment
        # but setting them to nil short circuits that ability.
        Aws::Inspector2::Client.new({}.tap do |client_opts|
          client_opts[:credentials] = aws_credentials if aws_credentials
          client_opts[:region] = region if region
        end)
      rescue Aws::Errors::MissingRegionError => e
        raise e, "No AWS region was provided. Populate ~/.aws/config, $AWS_REGION, or the aws_regions task option."
      end

      def aws_credentials
        credentials = Aws::Credentials.new(options.aws_access_key_id, options.aws_secret_access_key, options.aws_session_token) if options.aws_access_key_id && options.aws_secret_access_key
        if options.aws_role_arn
          params = {
            role_arn: options.aws_role_arn,
            role_session_name: 'kenna_toolkit_aws_inspector2'
          }
          params[:region] = aws_regions.first if aws_regions.any?
          params[:credentials] = credentials if credentials
          Aws::AssumeRoleCredentials.new(params)
        else
          credentials
        end
      end

      private

      def aws_regions
        @options[:aws_regions]&.uniq || [nil]
      end

      def extract_asset(finding)
        resource = finding.resources.first
        name = resource.tags.delete("Name")
        hostname, fqdn = name&.partition(FQDN_PATTERN)
        if resource.type == "AWS_ECR_CONTAINER_IMAGE"
          {
            asset_type: "image",
            image_id: resource.dig(:details, :aws_ecr_container_image, :image_hash)
          }
        else
          {
            ec2: resource.id,
            fqdn:,
            hostname:,
            ip_address: resource.details.aws_ec2_instance.ip_v4_addresses.min_by { |ip| ip[PRIVATE_IP_PATTERN].to_s },
            os: resource.details.aws_ec2_instance.platform
          }
        end.merge({
                    tags: build_tags(resource),
                    vulns: []
                  }).compact.with_indifferent_access
      end

      def extract_asset_vuln(finding)
        raise "Unhandled finding type #{finding.type}" unless finding.type == "PACKAGE_VULNERABILITY"

        # Sometimes inspector_score is nil, in which case we try to map the severity value to a
        # numeric value. If that fails, we set it to 1 because the Kenna Data Importer requires
        # a score. However, it's not that important because it doesn't factor into
        # the Kenna score, which is derived from proprietary data sources and models.
        severity_value = SEVERITY_VALUE[finding.severity]
        numeric_severity = finding.inspector_score || severity_value || 1

        {
          scanner_identifier: finding.finding_arn,
          scanner_type: SCANNER_TYPE,
          created_at: finding.first_observed_at,
          last_seen_at: finding.last_observed_at,
          status: finding.status == "CLOSED" ? "closed" : "open",
          vuln_def_name: finding.title,
          scanner_score: numeric_severity.round
        }.compact.with_indifferent_access
      end

      def extract_definition(finding)
        vuln_id = finding.package_vulnerability_details.vulnerability_id
        {
          scanner_identifier: finding.finding_arn,
          scanner_type: SCANNER_TYPE,
          cve_identifiers: vuln_id.include?("CVE") ? vuln_id : nil,
          cwe_identifiers: vuln_id.include?("CWE") ? vuln_id : nil,
          wasc_identifiers: vuln_id.include?("WASC") ? vuln_id : nil,
          name: finding.title,
          description: finding.description,
          solution: finding.remediation.recommendation.text
        }.compact.with_indifferent_access
      end

      def build_tags(resource)
        regular_tags = resource.tags.map { |tag| tag.join(':') }
        registry_tags = resource.dig(:details, :aws_ecr_container_image, :registry).try { |r| "registry-#{r}" }
        repository_tags = resource.dig(:details, :aws_ecr_container_image, :repository_name).try { |r| "repository-#{r}" }
        [regular_tags, registry_tags, repository_tags].flatten.compact
      end
    end
  end
end
