# frozen_string_literal: true

module Kenna
  module Toolkit
    module Edgescan
      class KennaApi
        include Kenna::Toolkit::KdiHelpers

        def initialize(options)
          @kenna_api_host = options[:kenna_api_host]
          @kenna_api_key = options[:kenna_api_key]
          @kenna_connector_id = options[:kenna_connector_id]
          @output_dir = "#{$basedir}/#{options[:output_directory]}"
          @assets_from_hosts = options[:assets_from_hosts]
          @skip_autoclose = false
          @max_retries = 3
          @kdi_version = 2
        end

        # Converts Edgescan hosts, vulnerabilities (and location specifiers) into Kenna assets and vulnerabilities/findings
        def add_vulnerabilities_and_hosts(vulnerabilities, hosts, to_kenna_findings = false)
          assets = hosts.count.positive? ? hosts.map(&:to_kenna_asset) : vulnerabilities.map(&:to_kenna_asset).uniq
          vulnerabilities.each do |vuln|
            asset = assets.find { |a| a["external_id"] == vuln.external_id }
            asset = vuln.to_kenna_asset if asset.nil?
            if to_kenna_findings
              create_kdi_asset_finding(asset, vuln.to_kenna_finding, "external_id")
            else
              create_kdi_asset_vuln(asset, vuln.to_kenna_vulnerability, "external_id")
            end
          end
        end

        # Converts Edgescan definitions into Kenna ones and adds them into memory
        def add_definitions(edgescan_definitions)
          edgescan_definitions.each do |edgescan_definition|
            add_definition(edgescan_definition.to_kenna_definition)
          end
        end

        # Uploads whatever's in memory into Kenna and then clears memory
        #
        # Note: Uploaded data does not get imported into Kenna automatically. It just sits there
        #       until `kickoff` is called.
        #       This allows for uploading in batches. Once a few batches have been uploaded and
        #       you're happy for whatever is there to get imported into Kenna you can call `kickoff`
        def upload
          kdi_upload(@output_dir, "batch-#{millis}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @max_retries, @kdi_version)
        end

        # Kicks off connector tasks so that whatever was uploaded actually gets imported into Kenna
        def kickoff
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        end

        private

        # Adds Kenna definition into memory
        def add_definition(kenna_definition)
          create_kdi_vuln_def(kenna_definition)
        end

        # Gets current time in milliseconds
        def millis
          (Time.now.to_f * 1000).round
        end
      end
    end
  end
end
