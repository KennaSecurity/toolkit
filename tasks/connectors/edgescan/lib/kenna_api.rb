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
        end

        # Converts an Edgescan asset into Kenna friendly ones and adds them into memory
        #
        # Note: Edgescan and Kenna assets don't map one to one. A Kenna asset is more like an
        #       Edgescan location specifier. Because of that, one Edgescan asset usually gets turned
        #       into multiple Kenna assets.
        def add_assets(edgescan_asset, existing_kenna_assets)
          edgescan_asset.to_kenna_assets(existing_kenna_assets).each do |kenna_asset|
            add_asset(kenna_asset)
          end
        end

        # Converts Edgescan vulnerabilities into Kenna ones and adds them into memory
        def add_vulnerabilities(edgescan_vulnerabilities)
          edgescan_vulnerabilities.each do |vulnerability|
            add_vulnerability(vulnerability.external_asset_id, vulnerability.to_kenna_vulnerability)
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
          kdi_upload(@output_dir, "batch-#{millis}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key)
        end

        # Kicks off connector tasks so that whatever was uploaded actually gets imported into Kenna
        def kickoff
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        end

        # Fetches existing assets tagged with these Edgescan IDs from the Kenna API
        def fetch_assets_with_edgescan_ids(edgescan_ids)
          ids = edgescan_ids.map { |id| "'(ES#{id})'" }.join(",")
          query = "?vulnerability[q]=application:(#{ids}) AND vulnerability_score:>0"

          all_assets = []
          get_in_pages("assets/search#{query}") { |page| all_assets += page["assets"] }
          all_assets.group_by { |asset| asset["application"] }
        end

        private

        # Adds Kenna asset into memory (if one with the same `external_id` doesn't exist already)
        def add_asset(kenna_asset)
          return if (@assets || []).map { |asset| asset["external_id"] }.include?(kenna_asset["external_id"])

          create_kdi_asset(kenna_asset, false)
        end

        # Adds Kenna vulnerability into memory
        def add_vulnerability(external_asset_id, kenna_vulnerability)
          create_kdi_asset_vuln({ "external_id" => external_asset_id }, kenna_vulnerability, "external_id")
        end

        # Adds Kenna definition into memory
        def add_definition(kenna_definition)
          create_kdi_vuln_def(kenna_definition)
        end

        # Gets current time in milliseconds
        def millis
          (Time.now.to_f * 1000).round
        end

        # Attempts to fetch all pages of a request to the Kenna API
        def get_in_pages(url)
          current = 1
          total = 1

          while current <= total
            response = get("#{url}&page=#{current}")
            yield(response)

            current += 1
            total = response["meta"]["pages"]
          end
        end

        # Makes GET requests to the Kenna API
        def get(url)
          response = http_get("https://#{@kenna_api_host}/#{url}", { "X-Risk-Token": @kenna_api_key })
          JSON.parse(response.body)
        end
      end
    end
  end
end
