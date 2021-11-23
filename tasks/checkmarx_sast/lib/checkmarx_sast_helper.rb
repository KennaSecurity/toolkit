# frozen_string_literal: true

require "json"

module Kenna
  module Toolkit
    module CheckmarxSastHelper

      # Method for generating token using username & pwd , client ID and secret
      def request_checkmarx_sast_token(checkmarx_sast_url, username, password)
        print_debug "Getting Auth Token"
        checkmarx_sast_auth_api_url = "https://#{checkmarx_sast_url}/cxrestapi/auth/identity/connect/token"
        grant_type = "password"
        scope = "access_control_api sast_api"
        #TODO=> For now client_id & client_secret are static
        client_id = "resource_owner_sast_client"
        client_secret = "014DF517-39D1-4453-B7B3-9930C563627C"

        # Retrieve an OAuth access token to be used against Checkmarx SAST API"
        headers = { "content-type" => "application/x-www-form-urlencoded" }
        payload = "grant_type=password&scope=access_control_api sast_api&username=#{username}&password=#{password}&client_id=#{client_id}&client_secret=#{client_secret}"
        begin
          auth_response = http_post(checkmarx_sast_auth_api_url, headers, payload)
          return unless auth_response

          token = JSON.parse(auth_response)["access_token"]
          print_debug token.to_s
          token
        rescue JSON::ParserError
          print_error "Unable to process Auth Token response!"
        rescue StandardError => e
          print_error "Failed to retrieve Auth Token #{e.message}"
        end
      end

      # method to get all projects using user credentials
      def fetch_checkmarx_sast_projects(checkmarx_sast_url, token)
        print_good "Getting Projects \n"
        checkmarx_sast_projects_api_url = "https://#{checkmarx_sast_url}/cxrestapi/projects"
        headers = {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Bearer #{token}"
        }
        auth_response = http_get(checkmarx_sast_projects_api_url, headers)
        return nil unless auth_response

        begin
          project_results = JSON.parse(auth_response.body)
        rescue JSON::ParserError
          print_error "Unable to process Projects response!"
        end
        project_results
      end

      # method to fetch all scans of each project
      def fetch_all_scans_of_project(checkmarx_sast_url, token, project_id)
        print_good "\n"
        print_good "Getting All Scans of Project ID: #{project_id} \n"
        checkmarx_sast_scans_api_url = "https://#{checkmarx_sast_url}/cxrestapi/sast/scans?projectId=#{project_id}"
        headers = {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Bearer #{token}"
        }
        auth_response = http_get(checkmarx_sast_scans_api_url, headers)
        return nil unless auth_response

        begin
          scan_results = JSON.parse(auth_response.body)
          print_good "Scan Results: \n"
          print_good "#{scan_results}"
        rescue JSON::ParserError
          print_error "Unable to process scans response!"
        end
        scan_results
      end

    end
  end
end
