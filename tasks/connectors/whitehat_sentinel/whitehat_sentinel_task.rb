# frozen_string_literal: true

require "addressable"
require "sanitize"

require_relative "lib/api_client"
require_relative "lib/mapper"

module Kenna
  module Toolkit
    class WhitehatSentinelTask < Kenna::Toolkit::BaseTask
      SEVERITY_RANGE = (1..5).freeze

      def self.metadata
        {
          id: "whitehat_sentinel",
          name: "Whitehat Sentinel",
          description: "This task connects to the Whitehat Sentinel API and pulls results into the Kenna Platform.",
          options: [
            { name: "whitehat_api_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the Whitehat key used to query the API." },
            { name: "minimum_severity_level",
              type: "integer",
              required: false,
              default: 1,
              description: "The minimum severity level of vulns to retrieve from the API." },
            { name: "whitehat_scoring",
              type: "string",
              required: false,
              default: "legacy",
              description: "The scoring system used by Whitehat.  Choices are legacy and advanced." },
            { name: "kenna_api_key",
              type: "api_key",
              required: true,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: true,
              default: "api.kennasecurity.com",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: true,
              default: nil,
              description: "The connector we will upload to." },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/whitehat_sentinel",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }

          ]
        }
      end

      def run(options)
        super

        # Process:
        # 1. Retrieve findings from API
        # 2. Retrieve tags from API
        # 3. Group findings by canonical URL
        # 4. Generate KDI doc from findings

        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]

        scoring_system = @options[:whitehat_scoring].downcase.to_sym
        unless %i[advanced legacy].include? scoring_system
          print_error "The #{@options[:whitehat_scoring]} scoring system is not supported.  Choices are legacy and advanced."
          exit
        end
        mapper = Kenna::Toolkit::WhitehatSentinel::Mapper.new(scoring_system)

        key = @options[:whitehat_api_key]
        client = Kenna::Toolkit::WhitehatSentinel::ApiClient.new(api_key: key)

        unless client.api_key_valid?
          print_error "The Whitehat API does not accept the provided API key."
          exit
        end

        filter = {}
        filter[:query_severity] = query_severity_for(@options[:minimum_severity_level])

        findings = client.vulns(filter.compact)
        client.assets.each { |node| mapper.register_asset(node) }

        findings.group_by { |node| sanitize(node[:url]) }.each do |url, nodes|
          asset = mapper.asset_hash(nodes.first, url)

          nodes.each do |node|
            finding = mapper.finding_hash(node)
            vuln_def = mapper.vuln_def_hash(node)

            create_kdi_asset_finding(asset, finding)
            create_kdi_vuln_def(vuln_def.stringify_keys)
          end
        end

        ### Write KDI format
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "whitehat_sentinel_kdi.json"
        kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
        kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key if @kenna_connector_id && @kenna_api_host && @kenna_api_key
      rescue Kenna::Toolkit::WhitehatSentinel::ApiClient::Error
        print_error "Problem connecting to Whitehat API, please verify the API key."
        exit
      end

      def sanitize(raw_url)
        return nil unless raw_url
        return nil if /\A[[:space:]]*\z/.match?(raw_url)
        return nil if %w[http:// http:/].member? raw_url

        u = Addressable::URI.parse(raw_url)
        scheme = u.scheme || "http"
        sanitizer.fragment([scheme, "://", u.authority, u.path].join)
      end

      def sanitizer
        @sanitizer ||= Sanitize.new({ remove_contents: false, parser_options: { max_attributes: -1 } })
      end

      def query_severity_for(level)
        level = level.to_i
        raise ArgumentError, "Unsupported minimum severity level.  Must be between 1 and 5." unless SEVERITY_RANGE.include? level
        return if level == 1

        level.upto(5).to_a.join(",")
      end
    end
  end
end
