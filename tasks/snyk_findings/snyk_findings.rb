require_relative "lib/snyk_helper"

module Kenna 
module Toolkit
class SnykFindings < Kenna::Toolkit::BaseTask

  include Kenna::Toolkit::SnykHelper

  def self.metadata 
    {
      id: "snyk_findings",
      name: "Snyk Findings",
      description: "Pulls assets and vulnerabilitiies from Snyk",
      options: [
        {:name => "snyk_api_token", 
          :type => "api_key", 
          :required => true, 
          :default => nil, 
          :description => "Snyk API Token" },
        {:name => "kenna_api_key", 
          :type => "api_key", 
          :required => false, 
          :default => nil, 
          :description => "Kenna API Key" },
        {:name => "kenna_api_host", 
          :type => "hostname", 
          :required => false  , 
          :default => "api.kennasecurity.com", 
          :description => "Kenna API Hostname" }, 
        {:name => "include_license", 
          :type => "boolean", 
          :required => false, 
          :default => false, 
          :description => "retrieve license issues." }, 
        { :name => "kenna_connector_id", 
          :type => "integer", 
          :required => false, 
          :default => nil, 
          :description => "If set, we'll try to upload to this connector" },    
        { :name => "output_directory", 
          :type => "filename", 
          :required => false, 
          :default => "output/snyk", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }

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
    
    org_json = snyk_get_orgs(snyk_api_token)
    projects = []
    project_ids = []
    org_ids = []
    pagenum = 0
    org_json.each do |org|
      org_ids << org.fetch("id")
    end
    print_debug "orgs = #{org_ids}"


    org_ids.each do |org|
      project_json = snyk_get_projects(snyk_api_token,org)
      project_json.each do |project|
        projects << [project.fetch("name"),project.fetch("id")]
        project_ids << project.fetch("id")
      end
    end

    print_debug "projects = #{project_ids}"

    types = ["vuln"]
    types << "license" if include_license

    issue_filter_json =  "{ 
               \"filters\": {
                \"orgs\": #{org_ids},
                \"projects\": #{project_ids},
                \"isFixed\": false,
                \"types\": #{types}
              }
            }"
    
    print_debug "issue filter json = #{issue_filter_json}"

    morepages = true
    while morepages do 

      pagenum = pagenum + 1

      finding_json = snyk_get_issues(snyk_api_token, 500, issue_filter_json, pagenum)

      print_debug "issue json = #{finding_json}"

      if finding_json.nil? || finding_json.empty? || finding_json.length == 0 then
        morepages = false
        break
      end

      
      finding_severity = { "high" => 6, "medium" => 4, "low" => 1} # converter
      finding_json.each do |issue_obj|
        issue = issue_obj["issue"]
        project = issue_obj["project"]
        identifiers = issue["identifiers"]

        targetFile = project.fetch("targetFile")if project.key? ("targetFile")
        package = project.fetch("package") if project.key? ("package")

        file = "#{targetFile}/" if !targetFile.nil?
        file = "#{file}#{package}"
        
        asset = {

          "file" => file,
          "application" => project.fetch("name"),
          "tags" => [project.fetch("source"),project.fetch("packageManager")]

        }

        scanner_score = ""
        if !issue.key?("cvssScore") then
          scanner_score = finding_severity.fetch(issue.fetch("severity")) 
        else
          scanner_score = issue.fetch("cvssScore").to_i
        end

        fixedIn = issue.fetch("fixedIn") if issue.key? ("fixedIn")
        from = issue.fetch("from") if issue.key? ("from")
        functions =  issue.fetch("functions") if issue.key? ("functions")
        isPatchable = issue.fetch("isPatchable").to_s if issue.key? ("isPatchable")
        isUpgradable = issue.fetch("isUpgradable").to_s if issue.key? ("isUpgradable")
        language = issue.fetch("language") if issue.key? ("language"),
        references = issue.fetch("references") if issue.key? ("references")
        semver = JSON.pretty_generate(issue.fetch("semver")) if issue.key? ("semver")
        issue_severity =  issue.fetch("severity") if issue.key? ("severity")
        version =  issue.fetch("version") if issue.key? ("version")
        description = issue.fetch("description") if issue.key? ("description")

        additional_fields= {
          "fixedIn" => fixedIn,
          "from" => from,
          "functions" => functions,
          "isPatchable" => isPatchable,
          "isUpgradable" => isUpgradable,
          "language" => language,
          "references" => references,
          "semver" => semver,
          "severity" => issue_severity,
          "version" => version
        }

        additional_fields = additional_fields.compact!


        # craft the vuln hash
        finding = {
          "scanner_identifier" => issue.fetch("id"),
          "scanner_type" => "Snyk",
          "severity" => scanner_score, 
          "created_at" => issue_obj.fetch("introducedDate"),
          "additional_fields" => additional_fields
        }

        patches = issue["patches"].first.to_s unless issue["patches"].nil? || issue["patches"].empty?

        cves = nil
        cwes = nil
        if !identifiers.nil? then
          cves = identifiers['CVE'].join(",") unless identifiers['CVE'].nil? || identifiers['CVE'].length == 0
          cwes = identifiers['CWE'].join(",") unless identifiers['CWE'].nil? || identifiers['CVE'].length == 0
        end 
        name = nil
        name = issue.fetch("title") unless issue.fetch("title").nil? 


        vuln_def= {
          "scanner_identifier" => issue.fetch("id"),
          "scanner_type" => "Snyk",
          "solution" => patches,
          "description" => description,
          "cve_identifiers" => cves,
          "cwe_identifiers" => cwes,
          "name" => issue.fetch("title")
        }

        vulndef = vuln_def.compact!

        # Create the KDI entries 
        create_kdi_asset_finding(asset, finding)
        create_kdi_vuln_def(vuln_def)
      end
    end

    ### Write KDI format
    kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
    output_dir = "#{$basedir}/#{@options[:output_directory]}"
    filename = "snyk_findings_kdi.json"
    write_file output_dir, filename, JSON.pretty_generate(kdi_output)
    print_good "Output is available at: #{output_dir}/#{filename}"

    ### Finish by uploading if we're all configured
    if kenna_connector_id && kenna_api_host && kenna_api_key
      print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
      upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
    end

  end
end
end
end
