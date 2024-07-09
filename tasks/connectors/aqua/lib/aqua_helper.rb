# frozen_string_literal: true

require "json"

module Kenna
  module Toolkit
    module AquaHelper
      SAAS_AUTH_URL = "https://api.cloudsploit.com/v2/signin"
      WP_URL_API    = "https://prov.cloud.aquasec.com/v1/envs"

      def aqua_get_token(aqua_url, username, password)
        if cloud_url?(aqua_url)
          get_token_from_cloud(username, password)
        else
          get_token_from_on_prem(aqua_url, username, password)
        end
      end

      def get_token_from_on_prem(aqua_url, username, password)
        get_token("#{aqua_url}/api/v1/login", username, password)
      end

      def get_token_from_cloud(username, password)
        get_token(SAAS_AUTH_URL, username, password)
      end

      def get_token(auth_url, username, password)
        print_debug "Getting Auth Token from #{auth_url}"

        headers = { "Content-Type" => "application/json" }
        payload = if auth_url == SAAS_AUTH_URL
                    { "email": username, "password": password }.to_json
                  else
                    { "id": username.to_s, "password": password }.to_json
                  end

        begin
          auth_response = http_post(auth_url, headers, payload)

          if auth_response.code == 200
            auth_json = JSON.parse(auth_response.body)
            token = auth_json.dig("data", "token")

            print_error "Login failed: No token received" unless token
          else
            print_error "Request failed with response code #{auth_response.code} and message #{auth_response.body}"
          end

          token
        rescue JSON::ParserError => e
          print_error "Failed to parse JSON response: #{e.message}"
          nil
        rescue StandardError => e
          print_error "Exception occurred: #{e.message}"
          nil
        end
      end

      def get_wp_url(token)
        print_debug "Getting Workload Protection URL"
        headers  = { "Authorization" => "Bearer #{token}", "Content-Type" => "application/json" }
        response = safe_http_get(WP_URL_API, headers)

        return unless response

        wp_url = "https://#{JSON.parse(response.body).dig('data', 'ese_url')}"

        if wp_url
          print_debug("Workload Protection URL retrieved successfully")
        else
          print_error("Failed to retrieve Workload Protection URL")
        end
        wp_url
      end

      def safe_http_get(url, headers)
        http_get(url, headers)
      rescue JSON::ParserError
        print_error "Unable to process response!"
      rescue StandardError => e
        print_error "HTTP GET request failed: #{e.message}"
        nil
      end

      def cloud_url?(url)
        uri = URI.parse(url)
        return false unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
        return false if uri.host.nil?

        !!(uri.host =~ /(\.|^)cloud\.aquasec\.com$/)
      rescue URI::InvalidURIError
        false
      end

      def aqua_get_vuln(aqua_url, token, pagesize, pagenum)
        print_debug "Getting All Image Vulnerabilities"
        aqua_query_api = "#{aqua_url}/api/v2/risks/vulnerabilities?pagesize=#{pagesize}&page=#{pagenum}"
        puts "finding #{aqua_query_api}"
        @headers = { "Content-Type" => "application/json",
                     "accept" => "application/json",
                     "Authorization" => "Bearer #{token}" }

        response = http_get(aqua_query_api, @headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process Vulnerabilities response!"
        end

        json["result"]
      end

      def aqua_get_containers(aqua_url, token, pagesize, pagenum)
        print_debug "Getting All Containers"
        aqua_cont_api = "#{aqua_url}/api/v2/containers?pagesize=#{pagesize}&page=#{pagenum}"
        puts "finding #{aqua_cont_api}"
        @headers = { "Content-Type" => "application/json",
                     "accept" => "application/json",
                     "Authorization" => "Bearer #{token}" }

        response = http_get(aqua_cont_api, @headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process Containers response!"
        end

        json["result"]
      end

      def aqua_get_vuln_for_container(aqua_url, token, image, pagesize, pagenum)
        print_debug "Getting Vulnerabilities for a Container image"
        aqua_cont_img_api = "#{aqua_url}/api/v2/risks/vulnerabilities?image_name=#{image}&pagesize=#{pagesize}&page=#{pagenum}"
        puts "finding #{aqua_cont_img_api}"
        @headers = { "Content-Type" => "application/json",
                     "accept" => "application/json",
                     "Authorization" => "Bearer #{token}" }

        response = http_get(aqua_cont_img_api, @headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process Image vulnerabilities for Containers response!"
        end

        json["result"]
      end
    end
  end
end
