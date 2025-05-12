# frozen_string_literal: true

require 'faraday'
require 'faraday/middleware'

module Kenna
  module Toolkit
    module Helpers
      module Http
        def http_get(url, headers, max_retries = 5, verify_ssl = true)
          puts "faraday get request url #{url} headers: #{headers} verify_ssl #{verify_ssl}" 
          http_request(:get, url, headers, nil, max_retries, verify_ssl)
        end

        def http_post(url, headers, payload, max_retries = 5, verify_ssl = true)
          http_request(:post, url, headers, payload, max_retries, verify_ssl)
        end

        def connection(url, verify_ssl)
          Faraday.new(url: url) do |faraday|
            faraday.request :json
            faraday.response :raise_error
            faraday.response :logger, nil, { headers: true, bodies: false }

            faraday.ssl.verify = verify_ssl
            faraday.adapter Faraday.default_adapter
          end
        end

        def http_request(method, url, headers, payload = nil, max_retries = 5, verify_ssl = true)
          conn = connection(url, verify_ssl)
          normalized_headers = headers.transform_keys(&:to_sym)
          retries = 0
          begin
            response = conn.run_request(method, url, payload, normalized_headers)
            response
          rescue Faraday::ConnectionFailed, Faraday::TimeoutError => e
            log_exception(e)
            handle_retry(e, retries, max_retries)
            retries += 1
            retry if retries < max_retries
          rescue Faraday::ClientError => e
            log_exception(e)
            handle_retry(e, retries, max_retries)
            retries += 1
            retry if retries < max_retries
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
