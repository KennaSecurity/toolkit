# frozen_string_literal: true

require "addressable"
require "sanitize"

require_relative "lib/api_client"

module Kenna
  module Toolkit
    class WhitehatSentinelTask < Kenna::Toolkit::BaseTask
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
              description: "This is the Whitehat key used to query the API." }
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

        key = @options[:whitehat_api_key]
        client = Kenna::Toolkit::WhitehatSentinel::ApiClient.new(api_key: key)

        unless client.api_key_valid?
          print_error "The Whitehat API does not accept the provided API key."
          exit
        end

        findings = client.vulns
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
              severity: node[:severity].to_i * 2,
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
    end
  end
end
