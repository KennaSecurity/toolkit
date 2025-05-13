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

        def http_get(url, headers, max_retries = 5, verify_ssl = true)
          normalized_url = normalize_url(url)
          conn = Faraday.new(url: normalized_url) do |faraday|
            faraday.headers = headers
            faraday.headers['Content-Type'] = 'application/json'
            faraday.adapter Faraday.default_adapter
          end

          conn.get
        end

        def http_post(url, headers, payload, max_retries = 5, verify_ssl = true)
          normalized_url = normalize_url(url)
          http_request(:post, normalized_url, headers, payload, max_retries, verify_ssl)
        end

        def connection(verify_ssl)
          Faraday.new do |faraday|
            faraday.request :json
            faraday.response :raise_error
            faraday.response :logger, nil, { headers: true, bodies: false }

            faraday.ssl.verify = verify_ssl
          end
        end

        def http_request(method, url, headers, payload = nil, max_retries = 5, verify_ssl = true)
          normalized_url = normalize_url(url)
          retries = 0
          begin
            conn = connection(normalized_url, verify_ssl) # Create a new connection for each retry
            normalized_headers = headers.transform_keys(&:to_sym)
            conn.run_request(method, normalized_url, payload, normalized_headers)
          rescue Faraday::ConnectionFailed, Faraday::TimeoutError, Faraday::ClientError => e
            log_exception(e)
            retries += 1
            if retries < max_retries
              puts "Retrying request (attempt #{retries})..."
              sleep(5)
              retry
            end
          rescue Errno::ECONNREFUSED => e
            log_exception(e)
          end
        end

        def log_exception(error)
          print_error "Exception! #{error}"
          return unless log_request?

          # print_debug "#{error.response.request.method.upcase}: #{error.response.request.url}"
          # print_debug "Request Payload: #{error.response.request.payload}"
          # print_debug "Server Response: #{error.response.body}"
        end

        def log_request?
          debug? && running_local?
        end

        def handle_retry(exception, retries, max_retries, rate_limit_reset: false)
          return unless retries < max_retries

          sleep_time = rate_limit_reset && exception.response[:headers].key?('RateLimit-Reset') ? exception.response[:headers]['RateLimit-Reset'].to_i + 1 : 15
          puts rate_limit_reset ? "RateLimit-Reset header provided. sleeping #{sleep_time}" : "Retrying!"
          sleep(sleep_time)
        end
      end
    end
  end
end
