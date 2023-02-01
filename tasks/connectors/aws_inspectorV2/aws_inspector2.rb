require "aws-sdk-inspector2"
require "json"
require "strscan"

module Kenna
  module Toolkit
    class AwsInspectorToKdi < Kenna::Toolkit::BaseTask
      ###
      ### TODO ... needs to be converted to KDI helpers
      ###

      def self.metadata
        {
          id: "aws_inspector2",
          name: "AWS Inspector 2",
          description: "This task pulls results from AWS inspector API and translates them into KDI",
          options: [
            {
              name: "aws_region",
              type: "string",
              required: false,
              default: "eu-west-1",
              description: "This is the AWS region."
            }, {
              name: "aws_access_key",
              type: "string",
              required: false,
              default: "",
              description: "This is the AWS access key used to query the API."
            }, {
              name: "aws_secret_key",
              type: "string",
              required: false,
              default: "",
              description: "This is the AWS secret key used to query the API."
            }, {
              name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key"
            }, {
              name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.kennasecurity.com",
              description: "Kenna API Hostname"
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
              description: "This is the AWS security token used to query the API."
            }, {
              name: "role_arn",
              type: "string",
              required: false,
              default: "",
              description: "This is the AWS security token used to query the API."
            }, {
              name: "aws_regions_to_collect",
              type: "list",
              required: false,
              default: ["ca-central-1", "eu-central-1", "eu-west-2", "eu-west-1", "us-east-1", "us-east-2", "us-west-2"],
              description: "AWS Regions to loop over to collect findings"
            }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        # Get options
        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]
        aws_region = @options[:aws_region]
        aws_access_key = @options[:aws_access_key]
        aws_secret_key = @options[:aws_secret_key]
        aws_security_token = @options[:aws_security_token]
        regions = @options[:aws_regions_to_collect]
        role_arn = @options[:role_arn]

        # iterate through the findings, looking for CVEs
        @assets = []
        @vuln_defs = []


        regions.each do |i|
              puts i
              @next_token = nil
          loop do
            v = get_inspector_findings(i, aws_access_key, aws_secret_key, role_arn)
            v[:findings].each do |f|
            fqdn = f[:resources][0][:tags]["Name"]
            if fqdn.class.to_s == 'NilClass'
              fqdn = ""
            end
            if fqdn.length() != 0
                fqdn = f[:resources][0][:tags]["Name"]
            else
              puts "Asset with no name"
              fqdn = "NoName"

            end

              awsaccount = f[:aws_account_id]
              tribe = f[:resources][0][:tags]["tribe"]
             if f[:resources][0][:tags]["environment"].class.to_s.empty?
                environment = f[:resources][0][:tags]["Environment"]
              else
                environment = f[:resources][0][:tags]["environment"]
              end
              squad = f[:resources][0][:tags]["squad"]
              if f[:resources][0][:tags]["external"].class.to_s.empty?
                external = f[:resources][0][:tags]["TLA-Name"]
              else
                external = f[:resources][0][:tags]["external"]
              end
              service = f[:resources][0][:tags]["service"]
              instance_id = f[:resources][0][:id]
              ##Skips if the Finding does not have a Vulnerability
              next if f.key?(:package_vulnerability_details) != true
              if f[:package_vulnerability_details].class.to_s != 'NilClass'

                cve = f[:package_vulnerability_details].to_hash
                if cve.key?(:vulnerability_id) == true
                  vulnerability_id = cve[:vulnerability_id]
                  next if vulnerability_id.include?("CVE") != true
                end

                ##Checks if CVE score is present
                if cve.key?(:cvss) == true
                  if cve[:cvss].length() != 0
                    numeric_severity = cve[:cvss][0][:base_score]
                  else
                    ##Sets manual CVE Score of 1
                    puts "Untriaged CVE " + vulnerability_id
                    numeric_severity = 1

                  end
                end
                title = vulnerability_id
              end
              ##Skip Finding if it is not an EC2 object
            next if f[:resources][0][:details].key?(:aws_ec2_instance) != true

                platform = f[:resources][0][:details][:aws_ec2_instance][:platform]
                ipaddress = f[:resources][0][:details][:aws_ec2_instance][:ip_v4_addresses][0]
                puts ipaddress

            ##  else
              ##  platform = f[:resources][0][:details][:aws_ec2_instance][:platform]



              create_asset fqdn, instance_id, tribe, environment, platform, awsaccount, squad, external, service, ipaddress
              create_asset_vuln fqdn, vulnerability_id, numeric_severity, title
              create_vuln_def vulnerability_id, title
            end

            break if v[:next_token].nil?
            @next_token = v[:next_token]
          end
         ####
         # Write KDI format
         ####
         kdi_output = { skip_autoclose: false, version: 2, assets: @assets, vuln_defs: @vuln_defs }
         output_dir = "#{$basedir}/#{@options[:output_directory]}"
         filename = "inspector.kdi.json"
         # actually write it
         write_file output_dir, filename, JSON.pretty_generate(kdi_output)
         print_good "Output is available at: #{output_dir}/#{filename}"

         ####
         ### Finish by uploading if we're all configured
         ####
         return unless kenna_connector_id && kenna_api_host && kenna_api_key

         print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
         upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
        end
      end
        def create_asset(fqdn, instance_id, tribe, environment, platform, awsaccount, squad, external, service, ipaddress)
         # if we already have it, skip
         return unless @assets.select { |a| a[:fqdn] == fqdn }.empty?

         @assets << {
           fqdn: fqdn.to_s,
           ec2: instance_id.to_s,
           os: platform.to_s,
           tags: ["AWS", "Tribe:"+tribe.to_s, "Environment:"+environment.to_s, "OS:"+platform.to_s, "AWS Account ID:"+awsaccount.to_s, "Squad:"+squad.to_s, "External:"+external.to_s, "Technical Service:"+service.to_s],
           priority: 10,
           ip_address: ipaddress.to_s,
           vulns: []
         }
        end

        def create_asset_vuln(fqdn, cve_id, numeric_severity, title)
         # check to make sure it doesnt exist
         asset = @assets.find { |a| a[:fqdn] == fqdn }
         return unless asset[:vulns].select { |v| v[:scanner_identifier] == cve_id }.empty?

         vuln = {
           scanner_identifier: cve_id.to_s,
           scanner_type: "AWS Inspector",
           created_at: DateTime.now,
           last_seen_at: DateTime.now,
           status: "open",
           vuln_def_name: title
         }
         vuln.merge(scanner_score: numeric_severity.round.to_i) if numeric_severity

         asset[:vulns] << vuln
        end

        def create_vuln_def(cve_id, title)
         return unless @vuln_defs.select { |a| a[:cve_identifiers] == cve_id }.empty?

         @vuln_defs << {
           scanner_identifier: cve_id.to_s,
           scanner_type: "AWS Inspector",
           cve_identifiers: cve_id.to_s,
           name: title
         }
        end

        def get_inspector_findings(region, access_key, secret_key, role_arn)
          begin
            #          inspector = Aws::Inspector2::Client.new(region: region)
            # do stuff
            if access_key != nil && secret_key != nil
              inspector = Aws::Inspector2::Client.new({
                region: region,
                credentials: Aws::Credentials.new(access_key, secret_key)
              })
              if role_arn != nil
                Aws.config.update({
                  credentials: Aws::Credentials.new(access_key, secret_key)
                })
                role_credentials = aws::assumerolecredentials.new(
                  client: Aws::STS::Client.new,
                  role_arn: role_arn,
                  role_session_name: "kenna-session"
                )
                inspector = Aws::Inspector2::Client.new(credentials: role_credentials)

              end
            end
            if role_arn != nil
              puts "Using role: " + role_arn
              role_credentials = Aws::AssumeRoleCredentials.new(
                client: Aws::STS::Client.new(region: region),
                role_arn: role_arn,
                role_session_name: "kenna-session"
              )
              puts region
              inspector = Aws::Inspector2::Client.new(region: region, credentials: role_credentials)
            else
              inspector = Aws::Inspector2::Client.new(region: region)
            end

            # go get the inspector findings
            if @next_token == nil
              findings = inspector.list_findings
            else
              findings = inspector.list_findings(next_token:@next_token)
            end
            findings.map(&:to_hash)
          end
          findings
        end
        end
        end
        end
