# frozen_string_literal: true

module Kenna
  module Toolkit
    module SnykV2
      class SnykV2Client
        class ApiError < StandardError; end

        def initialize(token, snyk_api_base)
          @token = token
          @api_base_url = "https://#{snyk_api_base}/rest"
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

          response = http_get("#{@api_base_url}/orgs/#{org}/projects?version=2024-04-29&limit=100", @headers)
          raise ApiError, "Unable to retrieve projects, please check credentials." unless response

          JSON.parse(response)["data"]
        end

        def snyk_get_issues(per_page, page_num, from_date, to_date, org)
          print "Getting list of issues"
          pages = page_num

          all_issues = []
          next_url = "#{@api_base_url}/orgs/#{org}/issues?version=2024-04-29&limit=#{per_page}&created_after=#{from_date}&created_before=#{to_date}"

          pages.times do
            print_debug("Fetching data from URL: #{next_url}")

            response = http_get(next_url, @headers)
            raise ApiError, "Unable to retrieve issues, please check credentials." unless response

            data = JSON.parse(response)
            page_issues = data["data"]
            all_issues << page_issues

            next_url = data.dig("links", "next")
            break unless next_url

            next_url = URI.join(@api_base_url, next_url).to_s
          end

          all_issues
        end
      end
    end
  end
end
