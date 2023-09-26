# frozen_string_literal: true

module Kenna
  module Toolkit
    module NTTSentinelDynamic
      class ApiClient
        class Error < StandardError; end

        BASE_PATH = "https://sentinel.whitehatsec.com/api"
        DEFAULT_PAGE_SIZE = 1_000
        V1_VULNS_ENDPOINT = "/vuln"
        V1_ASSETS_ENDPOINT = "/asset" # NOTE: deprecation occurs Nov 6th 2023
        V2_ASSETS_ENDPOINT = "/assets"

        attr_reader :api_key, :page_size
        attr_accessor :logger

        def initialize(api_key:, page_size: DEFAULT_PAGE_SIZE)
          @api_key = api_key
          @page_size = page_size
        end

        def vulns(filters = {}, &)
          query = {
            "display_description" => "custom",
            "display_default_description" => "1",
            "display_solution" => "custom",
            "display_default_solution" => "1",
            "display_risk" => "1",
            "display_qanda" => "0",
            "display_attack_vectors" => "1",
            "display_attack_vector_notes" => "1",
            "display_param" => "1",
            "display_request" => "1",
            "display_response" => "1",
            "display_headers" => "1",
            "display_body" => "1",
            "display_abbr" => "0"
          }.merge(filters)

          paginated(V1_VULNS_ENDPOINT, query,
                    { limit: 'page:limit', offset: 'page:offset' }, &)
        end

        def assets(&)
          query = {}

          paginated(V2_ASSETS_ENDPOINT, query,
                    { limit: 'limit', offset: 'offset' }, &)
        end

        private

        def paginated(endpoint, query, pagination_keys, &block)
          return to_enum(__method__, endpoint, query, pagination_keys) unless block

          query[pagination_keys[:limit]] = page_size
          offset = 0
          loop do
            query[pagination_keys[:offset]] = offset
            response = get(endpoint, query)
            parsed = JSON.parse(response, symbolize_names: true)
            parsed[:collection].each(&block)
            offset += page_size

            break if parsed[:collection].size < page_size
            break if parsed.key?(:page) && parsed[:page][:total].to_i <= offset
          end
        end

        def get(path, options = {})
          retries = options.delete(:retries) { |_k| 5 }

          url = "#{BASE_PATH}#{path}"
          params = { key: @api_key, accept: "application/json" }.merge({ params: options })
          response = Kenna::Toolkit::Helpers::Http.http_get(url, params, retries)

          raise Error unless response

          response
        end
      end
    end
  end
end
