# frozen_string_literal: true

require "json"
require "uri"

module Kenna
  module Toolkit
    module AquaHelper
      REGION_URLS = {
        "default" => { auth: "https://api.cloudsploit.com/v2/signin",
                       wp: "https://prov.cloud.aquasec.com/v1/envs" },
        "ap-2" => { auth: "https://ap-2.api.cloudsploit.com/v2/signin",
                    wp: "https://prov-ap-2.cloud.aquasec.com/v1/envs" },
        "asia-1" => { auth: "https://asia-1.api.cloudsploit.com/v2/signin",
                      wp: "https://prov-asia-1.cloud.aquasec.com/v1/envs" },
        "eu-1" => { auth: "https://eu-1.api.cloudsploit.com/v2/signin",
                    wp: "https://prov-eu-1.cloud.aquasec.com/v1/envs" }
      }.freeze

      def setup(aqua_url, username, password)
        @aqua_url = aqua_url
        @username = username
        @password = password
        @cloud = cloud_url?(aqua_url)
      end

      def cloud?
        @cloud
      end

      def select_region_urls
        region = case @aqua_url
                 when /eu-1\.cloud\.aquasec\.com/
                   "eu-1"
                 when /asia-1\.cloud\.aquasec\.com/
                   "asia-1"
                 when /ap-2\.cloud\.aquasec\.com/
                   "ap-2"
                 else
                   "default"
                 end

        REGION_URLS[region]
      end

      def aqua_get_token
        if cloud?
          region_urls = select_region_urls
          get_token(region_urls[:auth], @username, @password)
        else
          get_token("#{@aqua_url}/api/v1/login", @username, @password)
        end
      end

      def get_token(auth_url, username, password)
        print_debug "Getting Auth Token from #{auth_url}"

        headers = { "Content-Type" => "application/json" }
        payload = if cloud?
                    { email: username, password: }.to_json
                  else
                    { id: username.to_s, password: }.to_json
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
        region_urls = select_region_urls
        headers = { "Authorization" => "Bearer #{token}",
                    "Content-Type" => "application/json" }
        response = safe_http_get(region_urls[:wp], headers)

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
        headers = { "Content-Type" => "application/json",
                    "accept" => "application/json",
                    "Authorization" => "Bearer #{token}" }

        response = http_get(aqua_query_api, headers)
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
        headers = { "Content-Type" => "application/json",
                    "accept" => "application/json",
                    "Authorization" => "Bearer #{token}" }

        response = http_get(aqua_cont_api, headers)
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
        headers = { "Content-Type" => "application/json",
                    "accept" => "application/json",
                    "Authorization" => "Bearer #{token}" }

        response = http_get(aqua_cont_img_api, headers)
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
