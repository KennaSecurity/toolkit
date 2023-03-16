# frozen_string_literal: true

require "aws-sdk-inspector2"
require "json"
require "strscan"

module Kenna
  module Toolkit
    class AwsInspector2 < Kenna::Toolkit::BaseTask
      SCANNER_TYPE = "AWS Inspector V2"
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

        # Loop over all regions from options
        @aws_regions.each do |region|
          print_debug "Querying #{region} for findings"
          loop do
            findings = get_inspector_findings(region, @aws_access_key, @aws_secret_key)
            findings[:findings].each do |finding|
              # #Skips if the Finding does not have a Vulnerability
              next unless finding.package_vulnerability_details

              # #Skip Finding if it is not an EC2 object, Kenna backend likes no ECR findings
              next unless finding.resources.first.details.aws_ec2_instance

              asset = extract_asset(finding)
              vuln = extract_asset_vuln(finding) # vulnerability_id, numeric_severity, title
              definition = extract_definition(finding)

              create_kdi_asset(asset)
              create_kdi_asset_vuln(asset, vuln)
              create_kdi_vuln_def(definition)
            end

            @batch_num ||= 0
            @batch_num += 1
            kdi_upload(@output_directory, "aws_inspector2_batch_#{@batch_num}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
            @next_token = findings.next_token or break
          end

          ####
          ### Finish by uploading if we're all configured
          ####
          return unless kenna_connector_id && kenna_api_host && kenna_api_key

          print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
          upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
        end
      end
      
      private

      def initialize_options
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @aws_regions = @options[:aws_regions].uniq
        @aws_access_key = @options[:aws_access_key]
        @aws_secret_key = @options[:aws_secret_key]
        # FIXME: Add support for role/token
        aws_security_token = @options[:aws_security_token]
        role_arn = @options[:role_arn]
        @output_directory = @options[:output_directory]
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def extract_asset(finding)
        fqdn = finding[:resources].first[:tags]["Name"] # FIXME: this isn't always a valid fqdn
        # fqdn = "" if fqdn.class.to_s == 'NilClass' #FIXME do this better
        fqdn = if !fqdn.empty?
                 finding[:resources][0][:tags]["Name"]
               else
                 # #Have to put an asset name or Kenna backend cries like an ugly baby
                 "NoName"
               end
        instance_id = finding[:resources][0][:id]
        tribe = "Sports"
        # tribe = finding[:resources][0][:tags]["Tribe"]
        environment = finding[:resources][0][:tags]["Environment"]
        platform = finding[:resources][0][:details][:aws_ec2_instance][:platform]
        awsaccount = finding[:aws_account_id]
        squad = finding[:resources][0][:tags]["Squad"]
        external = finding[:resources][0][:tags]["TLA-Name"]
        service = finding[:resources][0][:tags]["service"]
        ipaddress = finding[:resources][0][:details][:aws_ec2_instance][:ip_v4_addresses][0]
        {
          fqdn: fqdn.to_s,
          ec2: instance_id.to_s,
          os: platform.to_s,
          tags: ["AWS", "Tribe:#{tribe}", "Environment:#{environment}", "OS:#{platform}", "AWS Account ID:#{awsaccount}", "Squad:#{squad}", "External:#{external}", "Technical Service:#{service}"],
          priority: 10,
          ip_address: ipaddress.to_s,
          vulns: []
        }.with_indifferent_access
      end

      def extract_asset_vuln(finding)
        raise "Unhandled finding type #{finding.type}" unless finding.type == "PACKAGE_VULNERABILITY"

        cve = finding.package_vulnerability_details
        raise "Not a CVE" unless cve.vulnerability_id.include?("CVE")

        vulnerability_id = cve[:vulnerability_id]

        # if cve.key?(:relatedVulnerabilities) # jagarber: I don't understand this block
        #   vulnerability_id = cve.relatedVulnerabilities
        #   puts "GOOD?#{vulnerability_id}"
        # end
        # #Checks if CVE score is present
        if finding.inspector_score
          numeric_severity = finding.inspector_score
        else
          # #Sets manual CVE Score of 1 or Kenna backend goes ugly baby mode again
          puts "Untriaged CVE #{vulnerability_id} - Open a case to AWS support and ask them to triage the CVE and provide a score in the API response"
          numeric_severity = 1
        end

        {
          scanner_identifier: vulnerability_id.to_s,
          scanner_type: SCANNER_TYPE,
          created_at: DateTime.now,
          last_seen_at: DateTime.now,
          status: "open",
          vuln_def_name: vulnerability_id.to_s, # FIXME: Should be finding.title?
          scanner_score: numeric_severity.round
        }.with_indifferent_access
      end

      def extract_definition(finding)
        cve_id = finding.package_vulnerability_details.vulnerability_id
        {
          scanner_identifier: cve_id.to_s,
          scanner_type: SCANNER_TYPE,
          cve_identifiers: cve_id.to_s,
          name: cve_id.to_s # FIXME: Should be finding.title?
        }.with_indifferent_access
      end

      def get_inspector_findings(region, access_key, secret_key)
        begin
          # Open a socket to AWS API using only access and secret keys - Static API keys used.
          inspector = Aws::Inspector2::Client.new({
                                                    region:,
                                                    credentials: Aws::Credentials.new(access_key, secret_key)
                                                  })

          # Get findings one page at a time.
          findings = if @next_token.nil?
                       inspector.list_findings
                     else
                       inspector.list_findings(next_token: @next_token)
                     end
          findings.map(&:to_hash)
        end
        findings
      end
    end
  end
end
