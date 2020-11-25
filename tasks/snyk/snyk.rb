# frozen_string_literal: true

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
            { name: "ProjectName_Strip_Colon",
              type: "boolean",
              required: false,
              default: false,
              description: "strip colon and following data from Project Name - used as application identifier" },
            { name: "PackageManager_strip_colon",
              type: "boolean",
              required: false,
              default: false,
              description: "strip colon and following data from PackageManager - used in asset file locator" },
            { name: "Package_Strip_Colon",
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

        # output_directory = @options[:output_directory]
        # Not Used - Commented Out - 11/25/2020 - JG
        include_license = @options[:include_license]

        project_name_strip_colon = @options[:ProjectName_Strip_Colon]
        package_manager_strip_colon = @options[:PackageManager_strip_colon]
        package_strip_colon = @options[:Package_Strip_Colon]

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
            application = application.slice(0..(application.rindex(":") - 1)) if project_name_strip_colon && !application.rindex(":").nil?

            package_manager = issue.fetch("PackageManager") if issue.key?("PackageManager")
            package = issue.fetch("package")
            if project.key?("TargetFile")
              target_file = project.fetch("TargetFile")
            else
              # print_debug = "using strip colon params if set"
              # Not Used - Commented Out 11/25/2020 - JG
              if !package_manager.nil? && !package_manager.empty?
                package_manager = package_manager.slice(0..(package_manager.rindex(":") - 1)) if package_manager_strip_colon && !package_manager.rindex(":").nil?
              end
              if !package.nil? && !package.empty?
                package = package.slice(0..(package.rindex(":") - 1)) if package_strip_colon && !package.rindex(":").nil?
              end
              target_file = package_manager.to_s unless package_manager.nil?
              target_file = "#{target_file}/" if !package_manager.nil? && !package.nil?
              target_file = "#{target_file}#{package}"
            end

            tags = []
            tags << project.fetch("source") if project.key?("source")
            tags << package_manager if !package_manager.nil? && !package_manager.empty?

            asset = {

              "file" => target_file,
              "application" => application,
              "tags" => tags

            }

            scanner_score = if issue.key?("cvssScore")
                              issue.fetch("cvssScore").to_i
                            else
                              vuln_severity.fetch(issue.fetch("severity"))
                            end

            source = project.fetch("source") if issue.key?("source")
            fixed_in = issue.fetch("fixedIn") if issue.key?("fixedIn")
            from = issue.fetch("from") if issue.key?("from")
            functions = issue.fetch("functions") if issue.key?("functions")
            is_patchable = issue.fetch("isPatchable").to_s if issue.key?("isPatchable")
            is_upgradable = issue.fetch("isUpgradable").to_s if issue.key?("isUpgradable")
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
              "fixedIn" => fixed_in,
              "from" => from,
              "functions" => functions,
              "isPatchable" => is_patchable,
              "isUpgradable" => is_upgradable,
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
              cve_array = identifiers["CVE"] unless identifiers["CVE"].nil? || identifiers["CVE"].length.zero?
              cwe_array = identifiers["CWE"] unless identifiers["CWE"].nil? || identifiers["CVE"].length.zero?
              cve_array.delete_if { |x| x.start_with?("RHBA", "RHSA") } unless cve_array.nil? || cve_array.length.zero?
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
