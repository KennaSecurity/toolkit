require_relative "lib/synack_helper"

module Kenna
  module Toolkit
    class Synack < Kenna::Toolkit::BaseTask
      include Kenna::Toolkit::SynackHelper

      def self.metadata
        {id: "synack",
          name: "Synack",
          description: "Pulls assets and vulnerabilitiies from Synack",
          options: [
            { name: "synack_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Synack API Token" },
            { name: "synack_api_url",
              type: "hostname",
              required: true,
              default: "",
              description: "Synack API Hostname" },
            { name: "synack_cert_file",
              type: "filename",
              required: true,
              default: "",
              description: "Synack Cert Filname" },
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
              default: "output/synack",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }

          ]
        }
      end

      def run(opts)
        super

        synack_api_token = @options[:synack_api_token]
        synack_api_host = @options[:synack_api_url]
        synack_cert_file = @options[:synack_cert_file]
        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]


        date_format_KDI = "%Y-%m-%d-%H:%M:%S"

        print_debug 'Attempting to fetch vulns from Synack'

        synack_json = get_synack_vulnerabilities(@options[:synack_api_url], @options[:synack_api_token], @options[:synack_cert_file])

        print_debug "Got #{synack_json.length} vulns from Synack"

        print_debug 'Converting Synack vulns to Kenna format'

        # this is a dev solution to always create new vulns with unique ID. Used for debugging purpose only
        # @unique_suffix = "_#{DateTime.now.strftime('%Y%m%d%H%M%S')}"
        @unique_suffix = ""

        synack_json.each do |item|

          ##################
          # Asset settings #
          ##################

          ### CREATE THE ASSET
          exploitable_locations = []

          #########################
          # Vulnerability Section #
          #########################
          last_seen = item.fetch("updated_at")
          # Kenna uses this date as a closed date if specified, and it overwrites the closed date. This creates confusion
          # avoiding to use this date for now
          # last_fixed_on = item.fetch("resolved_at")
          scanner_id = item.fetch("id") + "#{@unique_suffix}"
          name = item.fetch("title")
          description = item.fetch("description")
          solution = item.fetch("recommended_fix")
          closed = item.fetch("closed_at")
          #scanner_score = item.fetch("cve_score")
          item["exploitable_locations"].each do |el|

            if el.has_key?("type")
              type = el.fetch("type").gsub(/\s+/, "")
              if type == 'ip'
                address = el.fetch("address").gsub(/\s+/, "")
                port = el.fetch("port")
                exploitable_location = {type: type, address: address, port: port}
              else
                value = el.fetch("value").gsub(/\s+/, "")
                exploitable_location = {type: type, value: value}
              end
              exploitable_locations << exploitable_location
            end

          end
          application = item["listing"].fetch("codename")
          scanner_type = "Synack"
          scanner_score = item.fetch("cvss_final")

          vuln_status_info = item["vulnerability_status"]

          created = item.fetch("resolved_at")
          synack_status = vuln_status_info.fetch("text")
          status = ""

          case synack_status
            when "Pending Review"
              status = "open"
            when "Fixed"
              status = "closed"
            when "Won't Fix"
              status = "closed"
            when "Not Valid"
              status = "closed"
            else
              status = "open"
          end

          # status = "open"

          validation_steps = item.fetch("validation_steps")

          details = []
          validation_steps.each do |step|
            number = step.fetch("number")
            detail = step.fetch("detail")
            detail_url = step.fetch("url")
            details << "#{number}. #{detail} \n #{detail_url} \n"
          end

          details = details.sort
          details = details.join('')

          ############################
          # Vulnerability Definition #
          ############################
          closed = DateTime.strptime(closed, "%Y-%m-%dT%T%:z").strftime(date_format_KDI) unless closed.nil? || closed.empty?
          last_seen = DateTime.strptime(last_seen, "%Y-%m-%dT%T%:z").strftime(date_format_KDI) unless last_seen.nil? || last_seen.empty?
          last_fixed_on = DateTime.strptime(last_fixed_on, "%Y-%m-%dT%T%:z").strftime(date_format_KDI) unless last_fixed_on.nil? || last_fixed_on.empty?
          created = DateTime.strptime(created, "%Y-%m-%dT%T%:z").strftime(date_format_KDI) unless created.nil? || created.empty?

          exploitable_locations.each do |location|
            new_assets = create_asset(location, application, assets)
            (assets << new_assets) unless new_assets.empty?
            create_asset_vuln(assets, location, scanner_type, scanner_id, last_seen, last_fixed_on, created, scanner_score.to_i, details, closed, status)
            # CREATE A VULN DEF THAT HAS THE SAME ID AS OUR VULN
            vuln_defs << create_vuln_def(scanner_type, scanner_id, name, description, solution)
          end

        end

        print_good "Converted #{synack_json.length} Synack vulns to #{assets.length} Kenna assets and #{vuln_defs.length} Kenna vulns"

        ### Write KDI format
        kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "synack_kdi.json"
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