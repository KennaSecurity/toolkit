# frozen_string_literal: true

module Kenna
  module Toolkit
    module SnykV2
      class SnykV2Client
        class ApiError < StandardError; end

        def initialize(token, api_base_url)
          @token = token
          @api_base_url = "https://#{api_base_url}/rest"
          @headers = {
            "Content-Type" => "application/json",
            "Accept" => "application/json",
            "Authorization" => "Token #{@token}"
          }
        end

        def snyk_get_orgs
          print "Getting list of orgs"

          response = http_get("#{@api_base_url}/orgs?version=2024-04-29", @headers)
          raise ApiError, "Unable to retrieve organizations, please check credentials." unless response

          JSON.parse(response)["data"]
        end

        def snyk_get_projects(org)
          print "Getting list of projects"

          response = http_get("#{@api_base_url}/orgs/#{org}/projects?version=2024-04-29", @headers)
          raise ApiError, "Unable to retrieve projects, please check credentials." unless response

          JSON.parse(response)["data"]
        end

        def snyk_get_issues(per_page, search_json, page_num, from_date, to_date, org)
          print "Getting list of issues"

          snyk_query_api = "#{@api_base_url}/orgs/#{org}/issues?version=2024-04-29&perPage=#{per_page}&page=#{page_num}&from=#{from_date}&to=#{to_date}"

          print_debug("Get issues query: #{snyk_query_api}")

          response = http_get(snyk_query_api, @headers)
          raise ApiError, "Unable to retrieve issues, please check credentials." unless response

          JSON.parse(response)["data"]
        end
      end
    end
  end
end
