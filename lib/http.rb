# frozen_string_literal: true

module Kenna
  module Toolkit
    module Helpers
      module Http
        def http_get(url, headers, max_retries = 5, verify_ssl = true)
          http_request(:get, url, headers, nil, max_retries, verify_ssl)
        end

        def http_post(url, headers, payload, max_retries = 5, verify_ssl = true)
          http_request(:post, url, headers, payload, max_retries, verify_ssl)
        end

        def http_request(method, url, headers, payload = nil, max_retries = 5, verify_ssl = true)
          retries = 0
          begin
            RestClient::Request.execute(
              method: method,
              url: url,
              headers: headers,
              payload: payload,
              verify_ssl: verify_ssl
            )
          rescue RestClient::TooManyRequests => e
            log_exception(e)
            handle_retry(e, retries, max_retries, rate_limit_reset: true)
            retries += 1
            retry if retries < max_retries
          rescue RestClient::UnprocessableEntity, RestClient::BadRequest,
                 RestClient::NotFound => e
            log_exception(e)
          rescue RestClient::Exception => e
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
          return unless log_request? && error.is_a?(RestClient::Exception)

          print_debug "#{error.response.request.method.upcase}: #{error.response.request.url}"
          print_debug "Request Payload: #{error.response.request.payload}"
          print_debug "Server Response: #{error.response.body}"
        end

        def log_request?
          debug? && running_local?
        end

        def handle_retry(exception, retries, max_retries, rate_limit_reset: false)
          return unless retries < max_retries

          sleep_time = rate_limit_reset && e.response.headers.key?('RateLimit-Reset') ? e.response.headers['RateLimit-Reset'].to_i + 1 : 15
          puts rate_limit_reset ? "RateLimit-Reset header provided. sleeping #{sleep_time}" : "Retrying!"
          sleep(sleep_time)
        end
      end
    end
  end
end
