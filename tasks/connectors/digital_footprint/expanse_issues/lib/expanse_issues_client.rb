# frozen_string_literal: true

require "uri"
require "csv"

module Kenna
  module Toolkit
    module ExpanseIssues
      class ExpanseIssuesClient
        BASE_URL = "https://expander.expanse.co/api/v1/issues"

        def initialize(api_key)
          url = "https://expander.qadium.com/api/v1/idtoken"
          response = http_get(url, { Authorization: "Bearer #{api_key}" })
          @token = JSON.parse(response.body)["token"]
          @headers = { Authorization: "JWT #{@token}" }
        end

        def successfully_authenticated?
          @token&.length&.positive?
        end

        def issue_types
          url = "#{BASE_URL}/issueTypes?includeArchived=false&sort=id"
          response = http_get(url, @headers)
          result = JSON.parse(response.body)
          result["data"].map { |x| x["id"] }
        end

        def business_units
          url = "#{BASE_URL}/businessUnits"
          response = http_get(url, @headers)
          result = JSON.parse(response.body)
          result["data"].map { |x| x["id"] }
        end

        def issues(limit_per_page, issue_type, business_unit, priorities, tags, lookback)
          return nil unless successfully_authenticated?

          out = []
          page = 0
          modified_after = (DateTime.now - lookback.to_i).strftime("%FT%TZ")
          url = "#{BASE_URL}/issues?&activityStatus=Active&progressStatus=New,Investigating,InProgress&limit=#{limit_per_page}&issueTypeId=#{issue_type}&businessUnit=#{business_unit}&modifiedAfter=#{modified_after}"
          url += "&priority=#{priorities}" unless priorities.nil?
          url += "&tagName=#{tags}" unless tags.nil?

          until url.nil?
            page += 1
            response = http_get(url, @headers)
            result = JSON.parse(response.body)

            out.concat(result["data"])
            url = result["pagination"].fetch("next")
            raise "Potential SSRF detected: URL does not match base URL" unless url&.start_with?(BASE_URL)
          end

          out
        end
      end
    end
  end
end
