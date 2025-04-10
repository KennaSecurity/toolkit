# frozen_string_literal: true

module Kenna
  module Toolkit
    module Synack
      class SynackClient
        class ApiError < StandardError; end

        def initialize(api_domain, token, asset_defined_in_tag)
          @url_base = api_domain
          @asset_defined_in_tag = asset_defined_in_tag
          @headers = {
            "Authorization" => "Bearer #{token}"
          }
        end

        def fetch_synack_vulnerabilities
          [].tap do |result|
            (1..).each do |page_number|
              page_vulnerabilities = fetch_synack_vulnerabilities_page(page_number)
              break if page_vulnerabilities.empty? || result.length > 5000

              result.concat(page_vulnerabilities)
              puts "Fetched page #{page_number} with #{page_vulnerabilities.length} vulnerabilities from Synack."
            end
          end
        end

        def fetch_synack_vulnerabilities_page(page_number, page_size = 50)
          query = {
            filter: { include_attachments: 0 },
            page: { size: page_size, number: page_number }
          }
          query[:filter][:search] = "kenna::" if @asset_defined_in_tag
          url = URI::HTTPS.build(host: @url_base, path: "/v1/vulnerabilities", query: query.to_query).to_s
          response = http_get(url, @headers)
          raise ApiError, "Unable to retrieve vulnerabilities from Synack, please check url and token." unless response

          JSON.parse(response.body)
        end
      end
    end
  end
end
