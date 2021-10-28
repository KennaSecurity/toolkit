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
            { name: "whitehat_page_size",
              type: "integer",
              required: false,
              default: 1_000,
              description: "The number of items to retrieve from Whitehat with each API call." },
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
            { name: "kenna_batch_size",
              type: "integer",
              required: false,
              default: 0,
              description: "The number of findings to upload to Kenna at a time.  If not set, or set to 0, findings will not be batched, instead they will all be uploaded at once." },
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

        # Extract given options
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        scoring_system = @options[:whitehat_scoring].downcase.to_sym
        key = @options[:whitehat_api_key]
        page_size = @options[:whitehat_page_size].to_i
        @batch_size = @options[:kenna_batch_size].to_i
        query_severity = query_severity_for(@options[:minimum_severity_level])
        output_dir = "#{$basedir}/#{@options[:output_directory]}"

        # Validate given options
        unless %i[advanced legacy].include? scoring_system
          print_error "The #{@options[:whitehat_scoring]} scoring system is not supported.  Choices are legacy and advanced."
          exit
        end

        unless page_size.positive?
          print_error "The page size of #{@options[:whitehat_page_size]} is not supported."
          exit
        end

        print_error "The batch size of #{@options[:kenna_batch_size]} is not supported." if @batch_size.negative?

        mapper = Kenna::Toolkit::WhitehatSentinel::Mapper.new(scoring_system)

        client = Kenna::Toolkit::WhitehatSentinel::ApiClient.new(api_key: key, page_size: page_size)
        unless client.api_key_valid?
          print_error "The Whitehat API does not accept the provided API key."
          exit
        end

        filter = {}
        filter[:query_severity] = query_severity

        findings = client.vulns(filter.compact)
        client.assets.each { |node| mapper.register_asset(node) }

        batched(findings).each_with_index do |batch, i|
          batch.group_by { |node| sanitize(node[:url]) }.each do |url, nodes|
            asset = mapper.asset_hash(nodes.first, url)

            nodes.each do |node|
              finding = mapper.finding_hash(node)
              vuln_def = mapper.vuln_def_hash(node)

              create_kdi_asset_finding(asset, finding)
              create_kdi_vuln_def(vuln_def.stringify_keys)
            end
          end

          ### Write KDI format
          filename = "whitehat_sentinel_kdi_#{i}.json"
          kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
        end
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

      def batched(findings)
        if @batch_size.zero?
          print_debug "Batch size of zero means we won't batch."
          return [findings]
        end

        findings.each_slice(@batch_size)
      end
    end
  end
end
