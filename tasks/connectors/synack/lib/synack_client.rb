module Kenna
  module Toolkit
    module Synack
      class SynackClient
        class ApiError < StandardError; end

        def initialize(api_domain, token, asset_defined_in_tag)
          @token = token
          @api_url = "https://#{api_domain}"
          @asset_defined_in_tag = asset_defined_in_tag
          @headers = {
            "Authorization" => "Bearer #{@token}"
          }
        end

        def fetch_synack_vulnerabilities
          vulnerabilities = []
          page_number = 1
          loop do
            page_vulnerabilities = fetch_synack_vulnerabilities_page(page_number)
            break if page_vulnerabilities.empty? || vulnerabilities.length > 5000

            page_vulnerabilities.each { |vulnerability| vulnerabilities << vulnerability }
            print_good "Fetched page #{page_number} with #{page_vulnerabilities.length} vulnerabilities from Synack. Total #{vulnerabilities.length}"
            page_number += 1
          end
          vulnerabilities
        end

        def fetch_synack_vulnerabilities_page(page_number)
          filter = @asset_defined_in_tag ? "filter[search]=kenna::" : ""
          url = "#{@api_url}/v1/vulnerabilities?#{filter}&filter[include_attachments]=0&page[size]=50&page[number]=#{page_number}"
          response = http_get(url, @headers)
          raise ApiError, "Unable to retrieve vulnerabilities from Synack, please check url and token." unless response

          JSON.parse(response.body)
        end

      end
    end
  end
end
