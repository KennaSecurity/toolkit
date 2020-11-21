# rubocop:disable Style/SoleNestedConditional
require_relative "lib/snyk_helper"

module Kenna
  module Toolkit
    class Snyk < Kenna::Toolkit::BaseTask
      include Kenna::Toolkit::SnykHelper

      def self.metadata
        {
          id: "snyk",
          name: "Snyk",
          description: "Pulls assets and vulnerabilitiies from Snyk",
          options: [
            { name: "snyk_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Snyk API Token" },
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
            { name: "include_license",
              type: "boolean",
              required: false,
              default: false,
              description: "retrieve license issues." },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
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
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/snyk",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }

          ]
        }
      end

      def run(opts)
        super # opts -> @options

        snyk_api_token = @options[:snyk_api_token]

        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]

        output_directory = @options[:output_directory]
        include_license = @options[:include_license]

        projectName_strip_colon = @options[:projectName_strip_colon]
        packageManager_strip_colon = @options[:packageManager_strip_colon]
        package_strip_colon = @options[:package_strip_colon]

        org_json = snyk_get_orgs(snyk_api_token)
        projects = []
        project_ids = []
        org_ids = []
        pagenum = 0
        org_json.each do |org|
          org_ids << org.fetch("id")
        end
        print_debug org_json
        print_debug "orgs = #{org_ids}"

        org_ids.each do |org|
          project_json = snyk_get_projects(snyk_api_token, org)
          print_debug project_json
          project_json.each do |project|
            projects << [project.fetch("name"), project.fetch("id")]
            project_ids << project.fetch("id")
          end
        end

        print_debug "projects = #{project_ids}"

        types = ["vuln"]
        types << "license" if include_license

        issue_filter_json = "{
               \"filters\": {
                \"orgs\": #{org_ids},
                \"projects\": #{project_ids},
                \"isFixed\": false,
                \"types\": #{types}
              }
            }"

        print_debug "issue filter json = #{issue_filter_json}"

        morepages = true
        while morepages

          pagenum += 1

          vuln_json = snyk_get_issues(snyk_api_token, 500, issue_filter_json, pagenum)

          print_debug "issue json = #{vuln_json}"

          if vuln_json.nil? || vuln_json.empty? || vuln_json.length.zero?
            morepages = false
            break
          end

          vuln_severity = { "high" => 6, "medium" => 4, "low" => 1 } # converter
          vuln_json.each do |issue_obj|
            issue = issue_obj["issue"]
            project = issue_obj["project"]
            identifiers = issue["identifiers"]
            application = project.fetch("name")
            if projectName_strip_colon && !application.rindex(':').nil?
              application = application.slice(0..(application.rindex(':') - 1))
            end

            packageManager = issue.fetch("packageManager") if issue.key?("packageManager")
            package = issue.fetch("package")
            if project.key?("targetFile")
              targetFile = project.fetch("targetFile")
            else
              print_debug = "using strip colon params if set"
              if !packageManager.nil? && !packageManager.empty?
                if packageManager_strip_colon && !packageManager.rindex(':').nil?
                  packageManager = packageManager.slice(0..(packageManager.rindex(':') - 1))
                end
              end
              if !package.nil? && !package.empty?
                if package_strip_colon && !package.rindex(':').nil?
                  package = package.slice(0..(package.rindex(':') - 1))
                end
              end
              targetFile = packageManager.to_s unless packageManager.nil?
              targetFile = "#{targetFile}/" if !packageManager.nil? && !package.nil?
              targetFile = "#{targetFile}#{package}"
            end

            tags = []
            tags << project.fetch("source") if project.key?("source")
            tags << packageManager if !packageManager.nil? && !packageManager.empty?

            asset = {

              "file" => targetFile,
              "application" => application,
              "tags" => tags

            }

            scanner_score = ""
            scanner_score = if issue.key?("cvssScore")
                              issue.fetch("cvssScore").to_i
                            else
                              vuln_severity.fetch(issue.fetch("severity"))
                            end

            source = project.fetch("source") if issue.key?("source")
            fixedIn = issue.fetch("fixedIn") if issue.key?("fixedIn")
            from = issue.fetch("from") if issue.key?("from")
            functions = issue.fetch("functions") if issue.key?("functions")
            isPatchable = issue.fetch("isPatchable").to_s if issue.key?("isPatchable")
            isUpgradable = issue.fetch("isUpgradable").to_s if issue.key?("isUpgradable")
            if issue.key?("references")
              language = issue.fetch("language") if issue.key? "language",
                                                               references = issue.fetch("references")
            end
            semver = JSON.pretty_generate(issue.fetch("semver")) if issue.key?("semver")
            issue_severity = issue.fetch("severity") if issue.key?("severity")
            version =  issue.fetch("version") if issue.key?("version")
            description = issue.fetch("description") if issue.key?("description")

            additional_fields = {
              "source" => source,
              "fixedIn" => fixedIn,
              "from" => from,
              "functions" => functions,
              "isPatchable" => isPatchable,
              "isUpgradable" => isUpgradable,
              "language" => language,
              "references" => references,
              "semver" => semver,
              "severity" => issue_severity,
              "version" => version,
              "identifiers" => identifiers
            }

            additional_fields.compact!

            # craft the vuln hash
            vuln = {
              "scanner_identifier" => issue.fetch("id"),
              "scanner_type" => "Snyk",
              "scanner_score" => scanner_score,
              "created_at" => issue_obj.fetch("introducedDate"),
              "details" => JSON.pretty_generate(additional_fields)
            }

            vuln.compact!

            patches = issue["patches"].first.to_s unless issue["patches"].nil? || issue["patches"].empty?

            cves = nil
            cwes = nil
            unless identifiers.nil?
              cve_array = identifiers['CVE'] unless identifiers['CVE'].nil? || identifiers['CVE'].length.zero?
              cwe_array = identifiers['CWE'] unless identifiers['CWE'].nil? || identifiers['CVE'].length.zero?
              cve_array.delete_if { |x| x.start_with?('RHBA', 'RHSA') } unless cve_array.nil? || cve_array.length.zero?
              cves = cve_array.join(",") unless cve_array.nil? || cve_array.length.zero?
              cwes = cwe_array.join(",") unless cwe_array.nil? || cwe_array.length.zero?
            end

            vuln_name = nil
            vuln_name = issue.fetch("title") unless issue.fetch("title").nil?

            vuln_def = {
              "scanner_identifier" => issue.fetch("id"),
              "scanner_type" => "Snyk",
              "solution" => patches,
              "cve_identifiers" => cves,
              "cwe_identifiers" => cwes,
              "name" => vuln_name,
              "description" => description
            }

            vuln_def.compact!

            # Create the KDI entries
            create_kdi_asset_vuln(asset, vuln)
            create_kdi_vuln_def(vuln_def)
          end
        end

        ### Write KDI format
        kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "snyk_kdi.json"
        write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        print_good "Output is available at: #{output_dir}/#{filename}"

        ### Finish by uploading if we're all configured
        return unless kenna_connector_id && kenna_api_host && kenna_api_key

        print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
        upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
      end
    end
  end
end
# rubocop:enable Style/SoleNestedConditional
