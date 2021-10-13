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
          login
          true
        rescue Error
          false
        end

        def login
          get("/")
        end

        def vulns
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
          }

          get("/vuln", query)
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

        def sites
          # We need to know the satellite attribute for all sites, but that data
          # is only available when requesting an individual site.  Instead of
          # making a request per-site, we request all sites where satellite is
          # true and all sites where satellite is false, then combine the results
          # (while setting the attribute manually).
          fetch_sites_by_satellite(true).merge(fetch_sites_by_satellite(false))
        end

        private

        def fetch_sites_by_satellite(satellite)
          query = {
            display_entry_points: 1,
            query_satellite: satellite ? 1 : 0
          }

          JSON.parse(get("/site", query))
              .fetch("sites", [])
              .each_with_object({}) do |site, data|
            data[site["id"]] = site.slice("label", "entry_points").merge(satellite: satellite)
          end
        end

        def get(path, options = {})
          url = "#{BASE_PATH}#{path}"
          params = { key: @api_key, format: :json }.merge(options)
          response = Kenna::Toolkit::Helpers::Http.http_get(url, { params: params })

          raise Error unless response

          response
        end
      end
    end
  end
end
