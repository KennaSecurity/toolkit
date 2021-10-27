# frozen_string_literal: true

module Kenna
  module Toolkit
    module WhitehatSentinel
      class ApiClient
        class Error < StandardError; end

        BASE_PATH = "https://sentinel.whitehatsec.com/api"
        ASSET_LIMIT = 10

        attr_reader :api_key
        attr_accessor :logger

        def initialize(api_key:)
          @api_key = api_key
        end

        def api_key_valid?
          get("/", retries: 0)
          true
        rescue Error
          false
        end

        def vulns(filters = {})
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

          JSON.parse(get("/vuln", query), symbolize_names: true)[:collection]
        end

        def assets(page_size: ASSET_LIMIT, &block)
          return to_enum(__method__, page_size: page_size) unless block_given?

          offset = 0
          loop do
            query = {
              "display_asset" => 1,
              "display_all" => 1,
              "page:limit" => page_size,
              "page:offset" => offset
            }

            response = get("/asset", query)
            parsed = JSON.parse(response, symbolize_names: true)
            parsed[:collection].each(&block)
            offset += page_size
            break if parsed[:page][:total].to_i <= offset
          end
        end

        private

        def get(path, options = {})
          retries = options.delete(:retries) { |_k| 5 }

          url = "#{BASE_PATH}#{path}"
          params = { key: @api_key, format: :json }.merge(options)
          response = Kenna::Toolkit::Helpers::Http.http_get(url, { params: params }, retries)

          raise Error unless response

          response
        end
      end
    end
  end
end
