# frozen_string_literal: true

require 'faraday'
require 'faraday/middleware'
require 'net/http'
require 'uri'
require 'openssl'

module Kenna
  module Toolkit
    module Helpers
      module Http
        def normalize_url(url)
          uri = URI.parse(url)
          sorted_query = URI.encode_www_form(URI.decode_www_form(uri.query || '').sort)
          uri.query = sorted_query unless sorted_query.empty?
          uri.to_s
        end

        def connection(url, headers, verify_ssl = true)
          normalized_url = normalize_url(url)
          normalized_headers = headers.transform_keys(&:to_sym)

          Faraday.new(url: normalized_url) do |faraday|
            faraday.headers = normalized_headers
            faraday.request :json
            faraday.ssl.verify = verify_ssl
            faraday.response :raise_error
            # Faraday can automatically parse JSON responses, but client code expects RestClient responses that didn't.
            # faraday.response :json
          end
        end

        def http_get(url, headers, max_retries = 5, verify_ssl = true)
          http_request(:get, url, headers, nil, max_retries, verify_ssl)
        end

        def http_post(url, headers, payload, max_retries = 5, verify_ssl = true)
          http_request(:post, url, headers, payload, max_retries, verify_ssl)
        end

        def http_request(method, url, headers, payload = nil, max_retries = 5, verify_ssl = true)
          retries = 0

          begin
            conn = connection(url, headers, verify_ssl)

            conn.run_request(method, url, payload, headers)
          rescue Faraday::ConnectionFailed, Faraday::TimeoutError, Faraday::ClientError => e
            log_exception(e)
            retries += 1

            raise "Max retries reached for #{method.upcase} request to #{url}: #{e.message}" unless retries < max_retries

            sleep_time = [2**retries, 30].min # Exponential backoff with a cap at 30 seconds
            puts "Retrying request (attempt #{retries}) after #{sleep_time} seconds..."
            sleep(sleep_time)
            retry
          rescue Errno::ECONNREFUSED => e
            log_exception(e)
            raise "Connection refused for #{method.upcase} request to #{url}: #{e.message}"
          end
        end

        def log_exception(error)
          print_error "Exception! #{error}"
          return unless log_request?

          if error.response&.request
            print_debug "#{error.response.request.method.upcase}: #{error.response.request.url}"
            print_debug "Request Payload: #{error.response.request.payload}"
            print_debug "Server Response: #{error.response.body}"
          else
            print_debug "No response or request details available for this error."
          end
        end

        def log_request?
          debug? && running_local?
        end
      end
    end
  end
end
