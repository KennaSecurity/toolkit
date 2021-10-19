# frozen_string_literal: true

require_relative "lib/wiz_client"
module Kenna
  module Toolkit
    class WizTask < Kenna::Toolkit::BaseTask
      def self.metadata
        {
          id: "wiz",
          name: "Wiz",
          description: "Pulls assets and vulnerabilitiies from Wiz",
          options: [
            { name: "wiz_client_id",
              type: "string",
              required: true,
              default: nil,
              description: "Wiz client id" },
            { name: "wiz_client_secret",
              type: "api_key",
              required: true,
              default: nil,
              description: "Wiz client secret" },
            { name: "scanner_api_host",
              type: "hostname",
              required: false,
              default: "api.xxx.com",
              description: "url to retrieve hosts and vulns - if no variation this might not need to be a param" },
            { name: "vulnerabilities_since",
              type: "integer",
              required: false,
              default: 30,
              description: "integer days number to get the vulnerabilities detected SINCE x days" },
            { name: "report_object_types",
              type: "string",
              required: false,
              default: "VIRTUAL_MACHINE,CONTAINER_IMAGE,SERVERLESS",
              description: "array of object types to include in the report" },
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

      def delete_file(dir, fname)
        puts "#{dir}/#{fname}"
        File.delete("#{dir}/#{fname}")
      end

      def run(opts)
        super # opts -> @options
        # in this section get the options into variables if needed
        # if you will only reference the data from this method you can call @options in-line

        client_id = @options[:wiz_client_id]
        client_secret = @options[:wiz_client_secret]
        report_object_types = @options[:report_object_types].split(",")
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        skip_autoclose = false
        retries = 3
        kdi_version = 2

        days_used_regenerate_report = false
        # vulnerabilities_since = @options[:vulnerabilities_since]

        client = Kenna::Toolkit::Wiz::WizClient.new(client_id, client_secret, @output_directory)

        puts "report object types count #{report_object_types.size} and #{report_object_types}"

        puts "Generating Vulnerability Report for all types: Virtal Machines, Container Images and Serverless"
        puts "-- ** ** --"
        # report_types = ["a"]
        # @create_report_variables[:input][:params][:vulnerabilities_since] = vulnerabilities_since if vulnerabilities_since != ''

        # client.create_report(days_used_regenerate_report, report_object_types)

        Dir.entries(@output_directory.to_s).each do |abspath|
          # puts abspath
          fname = File.basename(abspath)
          # puts fname
          csv_file = CSV.parse(File.open("#{@output_directory}/#{fname}", "r:bom|utf-8", &:read), headers: true)
          unless csv_file.size.positive?
            delete_file(@output_directory, fname)
            next
          end
          csv_file.each do |row|
            vuln_url = row["WizURL"]
            cve = row["Name"]
            severity = row["VendorSeverity"]
            version = row["Version"]
            fixed_version = row["FixedVersion"]
            first_seen = row["FirstDetected"]
            last_seen = row["LastDetected"]
            solution = row["Remediation"]
            hostname = row["AssetName"]
            unique_id = row["ProviderUniqueId"]
            image_id = ""
            os = ""
            runtime = ""
            tags = []
            puts "before the parse"
            if JSON.parse(row["Tags"])
              puts "passed the if"
              tags_hash = JSON.parse(row["Tags"])
              puts "parsed the file"
              unless tags_hash.empty?
                tags_hash.each do |key, value|
                  tags << "#{key}:#{value}"
                  puts tags
                end
              end
            end
            tags << "Region:#{row['AssetRegion']}"
            tags << "CloudPlatform:#{row['CloudPlatform']}"
            vuln_severity = { "high" => 6, "medium" => 4, "low" => 1 }
            vuln_score = vuln_severity[severity].to_i
            if abspath.include? "VIRTUAL_MACHINE"
              runtime = row["Runtime"]
            elsif abspath.include? "CONTAINER_IMAGE"
              image_id = row["ImageId"]
            elsif abspath.include? "SERVERLESS"
              os = row["OperatingSystem"]
              external_id = unique_id
            end
            asset = {
              # used for VM assets primarily
              "image_id" => image_id,
              "hostname" => hostname,
              "tags" => tags,
              "os" => os,
              "external_id" => external_id
            }
            asset.compact!
            details_additional_fields = {
              "WizURL" => vuln_url,
              "Version" => version,
              "FixedVersion" => fixed_version,
              "Projects" => row["Projects"],
              "Runtime" => runtime,
              "ProviderUniqueId" => unique_id,
              "CloudProviderURL" => row["CloudProviderURL"]
            }
            # in case any values are null, it's good to remove them
            details_additional_fields.compact!

            vuln = {
              "scanner_type" => "Wiz",
              "scanner_identifier" => cve,
              # next is only needed for KDI V2 = vuln short name, text name, or cve or cwe name
              "vuln_def_name" => cve,
              "created_at" => first_seen,
              "scanner_score" => vuln_score,
              "last_seen_at" => last_seen,
              "details" => JSON.pretty_generate(details_additional_fields)
            }
            # in case any values are null, it's good to remove them
            vuln.compact!

            vuln_def = {
              # PICK (CVE OR CWE OR WASC) OR none but not all three
              "cve_id" => cve,
              "solution" => solution,
              "scanner_type" => "Wiz",
              "name" => cve
            }
            # in case any values are null, it's good to remove them
            vuln_def.compact!

            # Create the KDI entries for vulns or findings
            create_kdi_asset_vuln(asset, vuln)

            # create the KDI vuln def entry
            create_kdi_vuln_def(vuln_def)
          end
          filename = abspath.sub(/.csv/, ".json")
          kdi_upload @output_directory, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, skip_autoclose, retries, kdi_version
        end
        # this method will automatically use the stored array of uploaded files when calling the connector
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end
    end
  end
end
