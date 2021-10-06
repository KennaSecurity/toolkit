# frozen_string_literal: true

module Kenna
  module Toolkit
    module ScannerToolkitNameHelper
      # Are there any global variables needed here to make connections and retrieve data?
      # API path, creds, auth tokens
      # if methods in this class can just be called with the data as parameters no global variables needed
      @client_id = nil
      @api_key = nil
      @token = nil

      # methods here will vary based on called needed to get data from scanner API examples
      # get projects, get business lines, get vuln types, etc.
      # Be sure to understand pagination for these calls
      def get_assets(page_param = nil)
        print_debug "Getting machines"
        # on some services the session token will time out
        # if that is true for your scanner make sure you check the session token and re-authenticate again if needed
        get_auth_token if @token.nil?
        # make sure to account for 1st page vs subsequent calls
        url = if page_param.nil?
                "#{@scanner_api_host}/api/machines?$orderby=id"
              # url = "#{url}&#{page_param}" if !page_param.nil?
              else
                page_param
              end
        print_debug "url = #{url}"

        headers = { "Content-Type" => "application/json", "Accept" => "application/json", "Authorization" => "Bearer #{@token}" }
        # tookit has built in HTTP helper methods with error handling
        response = http_get(url, headers, 1)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        json
      end

      def atp_get_vulns(page_param = nil)
        print_debug "Getting vulns"
        get_auth_token if @token.nil?

        url = if page_param.nil?
                "#{@scanner_api_host}/api/vulnerabilities/machinesVulnerabilities?$orderby=machineId"
              # url = "#{url}&#{page_param}" if !page_param.nil?
              else
                page_param
              end
        # ComputerDnsName, LastSeen, HealthStatus, OsPlatform,
        print_debug "url = #{url}"

        headers = { "content-type" => "application/json", "accept" => "application/json", "Authorization" => "Bearer #{@token}", "accept-encoding" => "identity" }
        response = http_get(url, headers, 1)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        json
      end

      def auth_token
        print_debug "Getting token"
        oauth_url = "https://#{@oath_url}/#{@client_id}/oauth2/token"
        headers = { "content-type" => "application/x-www-form-urlencoded" }
        mypayload = {
          "resource" => @query_api,
          "client_secret" => @api_key.to_s,
          "grant_type" => "client_credentials"
        }
        print_debug "oauth_url = #{oauth_url}"
        response = http_post(oauth_url, headers, mypayload)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        @token = json.fetch("access_token")
      end

      def set_client_data(client_id, secret, query_api)
        @client_id = client_id
        @client_secret = secret
        @query_api = "https://#{query_api}"
      end
    end
  end
end
