# frozen_string_literal: true

module Kenna
  module Toolkit
    module SnykV2
      class SnykV2Client
        class ApiError < StandardError; end

        def initialize(token, api_base_url)
          @token = token
          @api_base_url = "https://#{api_base_url}/v1"
          @headers = {
            "Content-Type" => "application/json",
            "Accept" => "application/json",
            "Authorization" => "token #{@token}"
          }
        end

        def snyk_get_orgs
          print "Getting list of orgs"

          response = http_get("#{@api_base_url}/orgs", @headers)
          raise ApiError, "Unable to retrieve submissions, please check credentials." unless response

          JSON.parse(response)["orgs"]
        end

        def snyk_get_projects(org)
          print "Getting list of projects"

          response = http_get("#{@api_base_url}/orgs/#{org}/projects", @headers)
          raise ApiError, "Unable to retrieve submissions, please check credentials." unless response

          JSON.parse(response)["projects"]
        end

        def snyk_get_issues(per_page, search_json, page_num, from_date, to_date)
          print "Getting issues"
          snyk_query_api = "#{@api_base_url}/reporting/issues?perPage=#{per_page}&page=#{page_num}&from=#{from_date}&to=#{to_date}"
          print_debug("Get issues query: #{snyk_query_api}")

          response = http_post(snyk_query_api, @headers, search_json)
          raise ApiError, "Unable to retrieve submissions, please check credentials." unless response

          JSON.parse(response)["results"]
        end
      end
    end
  end
end
