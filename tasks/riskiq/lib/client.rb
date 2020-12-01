# frozen_string_literal: true

module Kenna
  module Toolkit
    module RiskIq
      class Client
        def initialize(api_key, api_secret)
          @api_url = "https://api.riskiq.net/v1/"

          raise "Bad key?" unless api_key && api_secret

          creds = "#{api_key}:#{api_secret}"
          token = Base64.strict_encode64(creds)
          @headers = {
            "Authorization" => "Basic #{token}",
            "Content-Type" => "application/json"
          }
        end

        def successfully_authenticated?
          true # TODO: ... let's sort
        end

        ##
        def ssl_cert_query
          '{ "filters": { "operator": "EQ",  "name": "type",  "value": "SSL_CERT" } }'
        end

        ##
        def open_port_query
          '{ "filters": { "operator": "EQ",  "name": "type",  "value": "IP_ADDRESS" } }'
        end

        ##
        def cve_footprint_query
          '{
      "filters": {
        "condition": "AND",
          "value": [
            {
                "name": "type",
                "operator": "EQ",
                "value": "PAGE"
            },
            {
                "name": "state",
                "operator": "EQ",
                "value": "CONFIRMED"
            },
            {
                "name": "cvssScore",
                "operator": "NOT_NULL",
                "value": true
            }
          ]
        }
    }'
        end

        def search_global_inventory(query = cve_footprint_query, max_pages = -1)
          # start with sensible defaults
          current_page = 1
          out = []

          while current_page <= max_pages || max_pages == -1
            puts "DEBUG Getting page: #{current_page} / #{max_pages}"

            endpoint = "#{@api_url}globalinventory/search?page=#{current_page}&size=100"

            begin
              response = RestClient::Request.execute({
                                                       method: :post,
                                                       url: endpoint,
                                                       payload: query,
                                                       headers: @headers
                                                     })

              result = JSON.parse(response.body)
            rescue RestClient::Exceptions::ReadTimeout => e
              puts "Error making request - server timeout?! #{e}. Retrying."
              sleep rand(10)
              retry
            rescue RestClient::InternalServerError => e
              puts "Error making request - server 500?! #{e}. Retrying."
              sleep rand(10)
              retry
            rescue RestClient::ServerBrokeConnection => e
              puts "Error making request - server dropped us?! #{e}. Retrying."
              sleep rand(10)
              retry
            rescue RestClient::NotFound => e
              puts "Error making request - bad endpoint?! #{e}"
            rescue RestClient::BadRequest => e
              puts "Error making request - bad query or creds?! #{e}"
            rescue JSON::ParserError => e
              puts "Error parsing json! #{e}"
            end

            # handle empty result
            return [] unless result

            # do stuff with the data
            out.concat(result["content"])

            # prepare the next request
            if max_pages == -1
              puts "Total Pages: #{result['totalPages']}"
              max_pages = result["totalPages"].to_i
            end

            current_page += 1
          end

          out
        end
      end
    end
  end
end
