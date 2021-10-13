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
        # 1. Retrieve sites from API
        # 2. Retrieve vulns from API
        # 3. Retrieve tags from API
        # 4. Group vulns by URL
        # 5. Generate KDI doc from vulns

        key = @options[:whitehat_api_key]
        client = Kenna::Toolkit::WhitehatSentinel::ApiClient.new(api_key: key)

        unless client.api_key_valid?
          print_error "The Whitehat API does not accept the provided API key."
          exit
        end

        sites = client.sites
        vulns = client.vulns
        tag_hash = client.assets.map { |node| node[:asset] }.map { |asset| [asset[:id], tags_for(asset)] }.to_h

        [sites, vulns, tag_hash]
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
    end
  end
end
