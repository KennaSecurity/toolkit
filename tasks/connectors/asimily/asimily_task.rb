# frozen_string_literal: true

require_relative "lib/asimily_client"
module Kenna
  module Toolkit
    module Asimily
      class Task < Kenna::Toolkit::BaseTask
        def self.metadata
          {
            id: "Asimily",
            name: "Asimily",
            description: "Pulls assets and vulnerabilities from Asimily",
            options: [
              { name: "asimily_api_endpoint",
                type: "hostname",
                required: true,
                default: nil,
                description: "Asimily portal endpoint url" },
              { name: "asimily_user",
                type: "user",
                required: true,
                default: nil,
                description: "Asimily User" },
              { name: "asimily_password",
                type: "password",
                required: true,
                default: nil,
                description: "Asimily password." },
              { name: "asimily_page_size",
                type: "integer",
                required: false,
                default: 100,
                description: "Maximum number of assets to retrieve in batches." },
              { name: "asimily_filter",
                type: "string",
                required: false,
                default: '',
                description: "Apply filter to sync filtered devices." },
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
              { name: "kenna_batch_size",
                type: "integer",
                required: false,
                default: 1000,
                description: "Maximum number of vulnerabilities to upload to Kenna in each batch." },
              { name: "output_directory",
                type: "filename",
                required: false,
                default: "output/asimily",
                description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
            ]
          }
        end

        def run(opts)
          super

          initialize_options

          @client = Kenna::Toolkit::Asimily::Client.new(@host, @username, @password, @page_size)

          fetch_assets

          print_error("Kenna_connector_id is null. File can't be uploaded.") if @kenna_connector_id.nil?
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        rescue Kenna::Toolkit::Asimily::Client::ApiError => e
          fail_task e.message
        rescue StandardError => e
          fail_task "An error occurred: #{e.message}"
        end

        private

        def initialize_options
          @host = @options[:asimily_api_endpoint]
          @username = @options[:asimily_user]
          @password = @options[:asimily_password]
          @output_directory = @options[:output_directory]
          @kenna_api_host = @options[:kenna_api_host]
          @kenna_api_key = @options[:kenna_api_key]
          @kenna_connector_id = @options[:kenna_connector_id]
          @page_size = @options[:asimily_page_size].to_i
          @filter = string_to_hash(@options[:asimily_filter])
          @skip_autoclose = false
          @kenna_batch_size = @options[:kenna_batch_size].to_i
          @retries = 3
          @kdi_version = 2
        end

        def string_to_hash(input_string)
          return {} if input_string.nil? || input_string.strip.empty?

          hash = {}
          key_value_pairs = input_string.split(',')
          key_value_pairs.each do |pair|
            key, value = pair.split('=')
            hash[key] = value
          end
          hash
        end

        def fetch_assets
          print("Initiating the API call for Assets")
          current_page = 0
          kdi_batch_upload(@kenna_batch_size, @output_directory, "asimily_devices.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version) do |batch|
            loop do
              devices, has_more_pages = @client.fetch_devices(@page_size, current_page, @filter)
              devices.each do |device|
                device_id = device['deviceID']
                vulnerabilities = @client.fetch_vulnerabilities(device_id)
                asset = @client.transform_device(device)
                if vulnerabilities.empty?
                  create_kdi_asset(asset)
                else
                  vulnerabilities.each do |vuln|
                    vuln_def = @client.transform_vulnerability_def(vuln)
                    curr_vuln = @client.transform_vulnerability(vuln)
                    batch.append do
                      create_kdi_asset_vuln(asset, curr_vuln)
                      create_kdi_vuln_def(vuln_def)
                    end
                  end
                end
                print("Fetched Vulnerabilities for device: #{device_id}")
              end
              break unless has_more_pages

              current_page += 1
            end
          end
        end
      end
    end
  end
end
