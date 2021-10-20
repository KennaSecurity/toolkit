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
              description: "The scoring system used by Whitehat.  Choices are legacy and advanced." }
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

        severity_proc = case @options[:whitehat_scoring].downcase
                        when "legacy"
                          ->(node) { node[:severity].to_i * 2 }
                        when "advanced"
                          ->(node) { node[:risk].to_i * 2 }
                        else
                          print_error "The #{@options[:whitehat_scoring]} scoring system is not supported.  Choices are legacy and advanced."
                          exit
                        end

        key = @options[:whitehat_api_key]
        client = Kenna::Toolkit::WhitehatSentinel::ApiClient.new(api_key: key)

        unless client.api_key_valid?
          print_error "The Whitehat API does not accept the provided API key."
          exit
        end

        filter = {}
        filter[:query_severity] = query_severity_for(@options[:minimum_severity_level])

        findings = client.vulns(filter.compact)
        tag_hash = client.assets.map { |node| node[:asset] }.map { |asset| [asset[:id], tags_for(asset)] }.to_h

        findings.group_by { |node| sanitize(node[:url]) }.each do |url, nodes|
          site_id = nodes.first[:site].to_i
          asset = {
            application: nodes.first[:site_name],
            url: url,
            tags: tag_hash[site_id]
          }

          nodes.each do |node|
            closed_at = Time.parse(node[:closed]) if node[:closed]

            finding = {
              scanner_identifier: node[:id],
              scanner_type: "Whitehat Sentinel",
              severity: severity_proc.call(node),
              created_at: Time.parse(node[:found]),
              last_seen_at: closed_at || Time.now,
              last_fixed_on: closed_at,
              closed_at: closed_at,
              vuln_def_name: node[:class],
              triage_state: map_status_to_triage_state(node[:status])
            }.compact

            create_kdi_asset_finding(asset, finding)
          end
        end
      rescue Kenna::Toolkit::WhitehatSentinel::ApiClient::Error
        print_error "Problem connecting to Whitehat API, please verify the API key."
        exit
      end

      def tags_for(asset)
        [asset[:tags],
         asset[:label],
         asset[:asset_owner_name],
         asset[:custom_asset_id]].flatten.compact.reject(&:empty?)
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

      def map_status_to_triage_state(status)
        case status.upcase
        when "OPEN"
          "in_progress"
        when "CLOSED"
          "resolved"
        when "ACCEPTED"
          "risk_accepted"
        when "INVALID"
          "not_a_security_issue"
        else
          "new"
        end
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
