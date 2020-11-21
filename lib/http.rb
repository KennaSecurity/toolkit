# rubocop:disable Lint/DuplicateBranch

module Kenna
  module Toolkit
    module Helpers
      module Http
        def http_get(url, headers, max_retries = 5)
          RestClient::Request.execute(
            method: :get,
            url: url,
            headers: headers
          )
        rescue RestClient::TooManyRequests => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            sleep(15)
            puts "Retrying!"
            retry
          end
        rescue RestClient::UnprocessableEntity => e
          puts "Exception! #{e}"
        rescue RestClient::BadRequest => e
          puts "Exception! #{e}"
        rescue RestClient::Exception => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            sleep(15)
            puts "Retrying!"
            retry
          end
        end

        def http_post(url, headers, payload, max_retries = 5)
          RestClient::Request.execute(
            method: :post,
            url: url,
            payload: payload,
            headers: headers
          )
        rescue RestClient::TooManyRequests => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            puts "Retrying!"
            sleep(15)
            retry
          end
        rescue RestClient::UnprocessableEntity => e
          puts "Exception! #{e}"
        rescue RestClient::BadRequest => e
          puts "Exception! #{e}"
        rescue RestClient::Exception => e
          puts "Exception! #{e}"
          retries ||= 0
          if retries < max_retries
            retries += 1
            puts "Retrying!"
            sleep(15)
            retry
          end
        end
      end
    end
  end
end

# rubocop:enable Lint/DuplicateBranch
