# frozen_string_literal: true

require "cgi"
require "faraday"

module Kenna
  module Toolkit
    module Armis
      class Client
        class ApiError < StandardError; end
        include Kenna::Toolkit::Helpers::Http

        VULNERABILITY_MATCH_ENDPOINT = "/api/v1/vulnerability-match/"
        SEARCH_ENDPOINT = "/api/v1/search/"
        ACCESS_TOKEN_ENDPOINT = "/api/v1/access_token/"

        DEVICE_FIELDS = "id,customProperties,ipAddress,macAddress,manufacturer,model,name,operatingSystem,operatingSystemVersion,site,type,tags,lastSeen"
        VULNS_FIELDS = "cveUid,description,avmRating"

        VULN_BATCH_SIZE = 2000
        DEVICES_SLICE_SIZE = 100
        FETCH_VULNS_BATCH_SIZE = 50
        SECONDS_IN_A_DAY = 84_600
        MAX_DURATION_IN_DAYS = 90

        def initialize(armis_instance, secret_token)
          @base_path = "https://#{armis_instance}.armis.com"
          @secret_token = secret_token
          @access_token = nil
          @expiration_time = nil
        end

        def get_devices(aql:, offset:, length:, from_date:, to_date: Time.now.utc)
          unescaped_aql = CGI.unescape(aql)

          raise ApiError, "from/to date is missing." if from_date.nil? || to_date.nil?
          raise ApiError, "Can't fetch data for more than 90 days" if duration_exceeds_max_limit?(from_date, to_date)
          raise ApiError, "AQL is missing." if unescaped_aql.blank?
          raise ApiError, "Invalid AQL format: #{unescaped_aql}" unless unescaped_aql.start_with?("in:devices")

          endpoint = "#{@base_path}#{SEARCH_ENDPOINT}"

          response_dict = make_http_get_request do
            time_diff_in_seconds = (to_date - from_date).to_i
            headers = {
              "Authorization" => get_access_token,
              "params" => {
                "aql": "timeFrame:\"#{time_diff_in_seconds} seconds\" #{unescaped_aql}",
                "from": offset,
                "length": length,
                "fields": DEVICE_FIELDS,
                "orderBy": "lastSeen"
              }
            }

            http_get(endpoint, headers) if headers['Authorization']
          end

          response_dict ? response_dict["data"] : {}
        end

        def get_vulnerability_descriptions(cve_ids)
          vulnerability_descriptions_map = {}
          cve_ids.each_slice(FETCH_VULNS_BATCH_SIZE) do |ids|
            current_vulnerability_descriptions_map = get_vuln_description_by_id(ids)
            vulnerability_descriptions_map.merge!(current_vulnerability_descriptions_map)
          end

          vulnerability_descriptions_map
        end

        def get_batch_vulns(devices)
          device_vulnerabilities = {}
          devices.each_slice(DEVICES_SLICE_SIZE) do |batched_devices|
            current_device_vulnerabilities = fetch_vulnerabilities_by_devices(batched_devices)
            device_vulnerabilities.merge!(current_device_vulnerabilities)
          end

          device_vulnerabilities
        end

        private

        def get_vuln_description_by_id(vuln_ids)
          endpoint = "#{@base_path}#{SEARCH_ENDPOINT}"
          vulnerability_description_map = {}

          return vulnerability_description_map if vuln_ids.empty?

          response_dict = make_http_get_request do
            headers = {
              "Authorization" => get_access_token,
              "params" => {
                "aql": "in:vulnerabilities id:(#{vuln_ids.join(',')})",
                "length": VULN_BATCH_SIZE,
                "fields": VULNS_FIELDS
              }
            }
            http_get(endpoint, headers) if headers["Authorization"]
          end

          return vulnerability_description_map if response_dict.nil?

          vulns_response = response_dict.dig("data", "results") || []
          vulns_response.each do |vuln|
            vuln_id = vuln["cveUid"]
            vulnerability_description_map[vuln_id] = vuln["description"]
          end

          vulnerability_description_map
        end

        def fetch_vulnerabilities_by_devices(devices)
          endpoint = "#{@base_path}#{VULNERABILITY_MATCH_ENDPOINT}"
          device_vulnerabilities = {}
          from = 0

          device_ids = devices.filter_map { |device| device["id"] }
          return device_vulnerabilities if device_ids.empty?

          loop do
            response_dict = make_http_get_request do
              headers = {
                "Authorization" => get_access_token,
                "params" => {
                  "device_ids": device_ids.join(","),
                  "from": from,
                  "length": VULN_BATCH_SIZE
                }
              }

              http_get(endpoint, headers) if headers["Authorization"]
            end
            break if response_dict.nil?

            vulns_response = response_dict.dig("data", "sample") || []
            vulns_response.each do |vuln|
              vuln_device_id = vuln["deviceId"]
              device_vulnerabilities[vuln_device_id] = device_vulnerabilities.fetch(vuln_device_id, []).append(vuln)
            end
            # loop will break if there is no data in next page, i.e next is null
            break if response_dict.dig("data", "paging", "next").nil?

            from += VULN_BATCH_SIZE
          end

          # returning the device_vulnerabilities hash
          device_vulnerabilities
        end

        def get_access_token(force: false)
          return @access_token if !force && !need_to_refresh_token?

          url = "#{@base_path}#{ACCESS_TOKEN_ENDPOINT}"
          headers = { "params": { "secret_key": @secret_token } }
          begin
            response = http_post(url, headers, nil)
            json_response = JSON.parse(response.body)

            @access_token = json_response.dig("data", "access_token")
            @expiration_time = json_response.dig("data", "expiration_utc")
            print_debug("Generated Secret Token!")
          rescue Faraday::ClientError,
                 Faraday::ServerError,
                 Faraday::Error,
                 Errno::ECONNREFUSED => e
            print_error(
              "Unable to generate access token, Please check task options armis_api_host and armis_api_secret_token!"
            )
            log_exception(e)
          rescue TypeError, JSON::ParserError => e
            print_error("Unable to parse response: #{e.message}")
          end
          @access_token
        end

        def make_http_get_request(max_retries = 5)
          response = yield()
          JSON.parse(response.body) if response
          retries ||= 0
        rescue Faraday::ClientError => e
          status = begin
            e.response[:status]
          rescue StandardError
            nil
          end

          case status
          when 429, 401
            log_exception(e)
            if retries < max_retries
              prev = 2**(retries - 1).to_f
              curr = 2**retries.to_f
              sleep_time = curr + Random.rand(prev..curr)
              sleep(sleep_time)
              print "Retrying!"
              get_access_token(force: true)
              retries += 1
              retry
            end
          when 422, 400, 404
            log_exception(e)
          else
            log_exception(e)
          end
        rescue Faraday::ConnectionFailed, Faraday::ServerError, Errno::ECONNREFUSED, Faraday::Error => e
          log_exception(e)
          retries ||= 0
          if retries < max_retries
            retries += 1
            sleep(15)
            print "Retrying!"
            retry
          end
        rescue JSON::ParserError => e
          print_error "Unable to parse response #{e.message}"
        end

        def duration_exceeds_max_limit?(from_date, to_date)
          ((to_date - from_date).to_i / SECONDS_IN_A_DAY) - 1 > MAX_DURATION_IN_DAYS
        end

        def need_to_refresh_token?
          @access_token.blank? || @expiration_time <= Time.now.utc
        end
      end
    end
  end
end
