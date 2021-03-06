# frozen_string_literal: true

require_relative "lib/veracode_av_client"

module Kenna
  module Toolkit
    class VeracodeAssetVulns < Kenna::Toolkit::BaseTask
      include Kenna::Toolkit::VeracodeAV

      def self.metadata
        {
          id: "veracode_asset_vulns",
          name: "Veracode Asset Vulns",
          description: "Pulls assets and vulns from Veracode",
          options: [
            { name: "veracode_id",
              type: "string",
              required: true,
              default: nil,
              description: "Veracode id" },
            { name: "veracode_key",
              type: "string",
              required: true,
              default: nil,
              description: "Veracode key" },
            { name: "veracode_page_size",
              type: "string",
              required: true,
              default: nil,
              description: "Veracode page size" },
            { name: "veracode_scan_types",
              type: "string",
              required: false,
              default: "STATIC,DYNAMIC,SCA",
              description: "Veracode scan types to include. Comma-delimited list of the three scan types." },
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
              default: "output/veracode",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }

          ]
        }
      end

      def run(opts)
        super # opts -> @options

        veracode_id = @options[:veracode_id]
        veracode_key = @options[:veracode_key]
        veracode_scan_types = @options[:veracode_scan_types]
        page_size = @options[:veracode_page_size]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @output_dir = "#{$basedir}/#{@options[:output_directory]}"
        @filename = ".json"

        client = Kenna::Toolkit::VeracodeAV::Client.new(veracode_id, veracode_key, @output_dir, @filename, @kenna_api_host, @kenna_connector_id, @kenna_api_key)
        client.category_recommendations(500)
        client.cwe_recommendations(500)

        app_list = client.applications(page_size)

        app_list.each do |application|
          guid = application.fetch("guid")
          appname = application.fetch("name")
          tags = application.fetch("tags")
          client.issues(guid, appname, tags, page_size, veracode_scan_types)
        end

        return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

        client.kdi_kickoff
      end
    end
  end
end
