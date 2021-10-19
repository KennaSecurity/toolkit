# frozen_string_literal: true

require_relative "lib/sample_helper"
module Kenna
  module Toolkit
    class ScannerToolkitName < Kenna::Toolkit::BaseTask
      include Kenna::Toolkit::ScannerToolkitNameHelper

      def self.metadata
        {
          id: "scanner",
          name: "My Scanner",
          description: "Pulls assets and vulnerabilitiies from Scanner",
          options: [
            { name: "scanner_login_id",
              type: "string",
              required: true,
              default: nil,
              description: "scanner id" },
            { name: "scanner_api_key",
              type: "api_key",
              required: true,
              default: nil,
              description: "scanner api key" },
            { name: "scanner_api_host",
              type: "hostname",
              required: false,
              default: "api.xxx.com",
              description: "url to retrieve hosts and vulns - if no variation this might not need to be a param" },
            { name: "scanner_page_size",
              type: "integer",
              required: false,
              default: 500,
              description: "give users the ability to change scanner page size if appropriate" },
            { name: "scanner_lookback",
              type: "integer",
              required: false,
              default: 30,
              description: "give users the ability to change scanner date range for scanner retrieval if appropriate" },
            { name: "vuln_risk_level",
              type: "string",
              required: false,
              default: "info,low OR critical,high",
              description: "give users the ability to include/disclude certain level risk items if appropriate" },
            { name: "batch_page_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Number of assets and their vulns to batch to the connector - you'll need to code for this" },
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
              default: "output/scanner",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options
        # in this section get the options into variables if needed
        # if you will only reference the data from this method you can call @options in-line

        scanner_user_id = @options[:scanner_user_id]
        scanner_api_key = @options[:scanner_api_id]
        scanner_api_host = @options[:scanner_api_host]
        batch_page_size = @options[:batch_page_size].to_i
        # these should exist in all toolkit tasks
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        skip_autoclose = false
        retries = 3
        kdi_version = 2

        # pass anything to the helper object that you will need later
        set_client_data(scanner_user_id, scanner_api_key, scanner_api_host, scanner_page_size)

        morevuln = true
        # this could be used it we were pulling a list of vulns so that we can increment
        # each time we start processing a new asset in order to batch to kenna
        asset_id = 0
        asset_count = 0
        submit_count = 0
        vuln_severity = { "Critical" => 10, "High" => 8, "Medium" => 6, "Low" => 3 } # converter if needed
        vuln_next_link = nil

        # now get the vulns
        while morevuln

          # call method in client that will pull vulns or assets
          # implement appropriate paging
          # this processing can reside in either the main task or can all be in the helper
          vuln_json_response = if vuln_next_link.nil?
                                 scanner_get_vulns
                               else
                                 scanner_get_vulns(vuln_next_link)
                               end

          vuln_json = vuln_json_response["value"]
          # loop through the vulns and do the appropriate mapping
          vuln_json.each do |vuln|
            vuln_cve = vuln.fetch("cveId")
            scanner_id = vuln_cve
            if vuln_cve.start_with?("CVE")
              vuln_cve = vuln_cve.strip
            else
              vuln_name = vuln_cve
              vuln_cve = nil
            end

            # if processing rows of vulns this keeps track of what asset we are working on
            machine_id = vuln.fetch("machineId")

            # if this isn't 0-10 value we'll need to convert
            # can be used as scanner_score(vuln) or severity(finding)
            vuln_score = (vuln["cvssV3"] || vuln_severity[vuln.fetch("severity")] || 0).to_i

            if asset_id.nil?
              print_debug "setting machine id for first asset"
              asset_id = machine_id
              asset_count += 1
              print_debug "asset count = #{asset_count}"
            end

            # if we are processing a new asset and have reached the batch page size,
            # send the KDI file to Kenna to free up container memoryd
            if asset_id.!= machine_id
              if asset_count == batch_page_size
                submit_count += 1
                print_debug "#{submit_count} about to upload file"
                # uniquely name the file
                filename = "scanner_kdi_#{submit_count}.json"
                # this method will efficiently write out the KDI file, upload to kenna if connector
                # information has been provided, and delete the file if debug = false and upload completes
                # it also saves the returned file id in an array for later
                kdi_upload @output_directory, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, skip_autoclose, retries, kdi_version
                asset_count = 0
              end
              asset_count += 1
              print_debug "asset count = #{asset_count}"
              # set this if we are processing all vulns sorted by asset id
              asset_id = machine_id
            end

            # craft the hash information to be built into the KDI file

            asset = {
              # used for VM assets primarily
              "fqdn" => vuln.fetch("fqdn_from_scanner"),
              "ip_address" => vuln.fetch("ip_address_from_scanner"),
              "mac_address" => vuln.fetch("mac_address_from_scanner"),
              "hostname" => vuln.fetch("hostname_from_scanner"),
              "netbios" => vuln.fetch("netbios_from_scanner"),
              # user for images & containers in VM
              "asset_type" => image_or_container,
              "image_id" => vuln.fetch("image_id_from_scanner"),
              "container_id" => vuln.fetch("container_id_from_scanner"),
              # asset meta data
              "owner" => vuln.fetch("owner_from_scanner"),
              "tags" => vuln.fetch("tags_from_scanner"),
              "os" => vuln.fetch("os_from_scanner"),
              "os_version" => vuln.fetch("os_version_from_scanner"),
              "priority" => vuln.fetch("priority_from_scanner"),
              # may be used for either VM or Findings model
              "external_id" => vuln.fetch("external_id_from_scanner"),
              # used for AppSec/finding assets
              "url" => vuln.fetch("url_from_scanner"),
              "file" => vuln.fetch("file_from_scanner"),
              "application" => vuln.fetch("application_from_scanner")
            }
            # in case any values are null, it's good to remove them
            asset.compact!

            # formatting data for either vuln or finding can be the same
            # and should include any data an engineer might need to
            # complete remediation
            details_additional_fields = {
              "introducedDate" => vuln.fetch("introducedDate"),
              "functions" => vuln.fetch("functions"),
              "isPatchable" => vuln.fetch("isPatchable"),
              "isUpgradable" => vuln.fetch("isUpgradable"),
              "module" => vuln.fetch("module"),
              "sourcefile" => vuln.fetch("sourcefile"),
              "line" => vuln.fetch("line")
            }
            # in case any values are null, it's good to remove them
            details_additional_fields.compact!

            vuln = {
              "scanner_type" => hardcodedscannervalue,
              "scanner_identifier" => vuln.fetch("scanner_id_from_scanner"),
              # next is only needed for KDI V2 = vuln short name, text name, or cve or cwe name
              "vuln_def_name" => vuln.fetch("some_vuln_name"),
              "created_at" => vuln.fetch("created_from_scanner"),
              "scanner_score" => vuln_score,
              "last_fixed_on" => vuln.fetch("last_fixed_from_scanner"),
              "last_seen_at" => vuln.fetch("last_seen_from_scanner"),
              "status" => vuln.fetch("status_from_scanner"),
              "closed" => vuln.fetch("closed_from_scanner"),
              "port" => vuln.fetch("port_from_scanner"),
              # JSON pretty used for details under vulns only to help with formatting
              "details" => JSON.pretty_generate(details_additional_fields)
            }
            # in case any values are null, it's good to remove them
            vuln.compact!

            # start finding section
            # finding = {
            #   "scanner_identifier" => scanner_id,
            #   "scanner_type" => hardcodedscannervalue,
            #   # next is only needed for KDI V2 = vuln short name, text name, or cve or cwe name
            #   "vuln_def_name" => vuln.fetch("some_vuln_name"),
            #   "severity" => vuln_score,
            #   "created_at" => vuln.fetch("createDate_from_scanner"),
            #   "last_seen_at" => vuln.fetch("introducedDate_from_scanner"),
            #   "due_date" => vuln.fetch("dueDate_from_scanner"),
            #   "triage_state" => mapped_from_scanner_status,
            #   "additional_fields" => details_additional_fields
            # }
            # # in case any values are null, it's good to remove them
            # finding.compact!
            # end finding section

            # craft the vuln def hash
            vuln_def = {
              # PICK (CVE OR CWE OR WASC) OR none but not all three
              "cve_id" => vuln_cve,
              "cwe_id" => vuln.fetch("cwe_id_from_scanner"),
              "wasc_id" => vuln.fetch("wasc_id_from_scanner"),
              # desc & solution can be left blank for cve and cwe and Kenna will pull in data
              "description" => vuln.fetch("description_from_scanner"),
              "solution" => vuln.fetch("solution_from_scanner"),
              "scanner_type" => hardcodedscannervalue,
              # FOR KDI V1 matches scanner_id in vuln / CANNOT be present in KDI V2
              "scanner_identifier" => scanner_id,
              # FOR KDI V2 matches vuln_def_name in vuln / MAY still be present in KDI V1
              "name" => vuln_name
            }
            # in case any values are null, it's good to remove them
            vuln_def.compact!

            # Create the KDI entries for vulns or findings
            create_kdi_asset_vuln(asset, vuln)
            # create_kdi_asset_finding(asset, finding)

            # if processing items by assets and you want to create an asset with no vulns
            # find_or_create_kdi_asset(asset)

            # create the KDI vuln def entry
            create_kdi_vuln_def(vuln_def)
          end

          # check if there are more records using appropriate pagination
          # for the scanner might be page #, line, data_key etc
          if vuln_json_response.key?("@odata.nextLink")
            vuln_next_link = vuln_json_response.fetch("@odata.nextLink")
          else
            morevuln = false
          end

        end
        print_debug "should be at the end of all the data and now making the final push to the server and running the connector"
        submit_count += 1
        print_debug "#{submit_count} about to run connector"
        # uniquely name the file and process any remaining records
        filename = "scanner_kdi_#{submit_count}.json"
        # this method will efficiently write out the KDI file, upload to kenna if connector
        # information has been provided, and delete the file if debug = false and upload completes
        # it also saves the returned file id in an array for later
        kdi_upload @output_directory, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, skip_autoclose, retries, kdi_version
        # this method will automatically use the stored array of uploaded files when calling the connector
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end
    end
  end
end
