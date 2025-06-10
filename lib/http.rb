# frozen_string_literal: true

require 'faraday'
require 'faraday/retry'

module Kenna
  module Toolkit
    module Helpers
      module Http
        RETRY_EXCEPTIONS = Faraday::Retry::Middleware::DEFAULT_EXCEPTIONS + [
          Faraday::ConnectionFailed, Faraday::ClientError, Net::OpenTimeout, Errno::ECONNREFUSED, EOFError
        ]

        def connection(verify_ssl = true, max_retries = 5)
          Faraday.new do |faraday|
            faraday.request :json
            faraday.ssl.verify = verify_ssl
            faraday.request :retry, {
              max: max_retries,
              interval: 0.1,
              max_interval: 30,
              backoff_factor: 5,
              methods: %i[get post],
              exceptions: RETRY_EXCEPTIONS,
              retry_statuses: [429, 500, 502, 503, 504],
              retry_block: method(:log_retry),
              exhausted_retries_block: method(:log_retries_exhausted)
            }
            faraday.response :raise_error
            # Faraday can automatically parse JSON responses if this is enabled. However, we shouldn't use JSON.parse if this is enabled
            # faraday.response :json
          end
        end

        def http_get(url, headers, max_retries = 5, verify_ssl = true)
          connection(verify_ssl, max_retries).run_request(:get, url, nil, headers)
        end

        def http_post(url, headers, payload, max_retries = 5, verify_ssl = true)
          connection(verify_ssl, max_retries).run_request(:post, url, payload, headers)
        end

        def log_retry(retry_count:, exception:, will_retry_in:, **kwargs)
          log_exception(exception)
          puts "Retrying request (attempt #{retry_count + 1}) after #{will_retry_in} seconds..."
        end

        def log_retries_exhausted(env:, exception:, _options:, **kwargs)
          puts "Max retries reached for #{env.method.upcase} request to #{env.url}: #{exception.message}"
        end

        def log_exception(error)
          print_error error.message
          return unless log_request?

          if (request = error&.response&.fetch(:request, false))
            print_debug "#{request[:method].upcase}: #{request[:url]}"
            print_debug "Request Body: #{request[:body]}"
            print_debug "Server Response: #{error.response[:body]}"
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
