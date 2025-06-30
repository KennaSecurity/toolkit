# frozen_string_literal: true

require "csv"

module Kenna
  module Toolkit
    module Ssc
      class Client
        def initialize(key)
          @key = key
          @baseapi = "https://api.securityscorecard.io"
          @headers = {
            "Accept" => "application/json",
            "Content-Type" => "application/json",
            "Cache-Control" => "none",
            "Authorization" => "Token #{@key}"
          }
        end

        def successfully_authenticated?
          json = portfolios
          return true if json && json["entries"]

          false
        end

        def portfolios
          endpoint = "#{@baseapi}/portfolios"

          begin
            response = http_get(endpoint, @headers)
            JSON.parse(response.body.to_s)
          rescue Faraday::ResourceNotFound => e
            print_debug "Resource not found for portfolios: #{e.message}"
            { "entries" => [] }
          end
        end

        def companies_by_portfolio(portfolio_id)
          endpoint = "#{@baseapi}/portfolios/#{portfolio_id}/companies"
          print_debug "Requesting #{endpoint}"

          begin
            response = http_get(endpoint, @headers)
            JSON.parse(response.body)
          rescue Faraday::ResourceNotFound => e
            print_debug "Resource not found for portfolio #{portfolio_id}: #{e.message}"
            { "entries" => [] }
          end
        end

        def issues_by_type_for_company(company_id, itype = "patching_cadence_low")
          endpoint = "#{@baseapi}/companies/#{company_id}/issues/#{itype}"
          print_debug "Requesting #{endpoint}"

          begin
            response = http_get(endpoint, @headers, 0)
            JSON.parse(response.body.to_s) unless response.nil?
          rescue Faraday::ResourceNotFound => e
            print_debug "Resource not found for company #{company_id}, issue type #{itype}: #{e.message}"
            nil
          end
        end

        def issues_by_factors(detail_url)
          begin
            response = http_get(detail_url, @headers)
            JSON.parse(response.body.to_s) unless response.nil?
          rescue Faraday::ResourceNotFound => e
            print_debug "Resource not found for URL #{detail_url}: #{e.message}"
            nil
          end
        end

        def types_by_factors(company_id)
          endpoint = "#{@baseapi}/companies/#{company_id}/factors"

          begin
            response = http_get(endpoint, @headers)
            factors = JSON.parse(response.body.to_s)["entries"] unless response.nil?
            types = []
            factors&.each do |factor|
              factor["issue_summary"]&.each do |detail|
                types << detail
              end
            end
            types
          rescue Faraday::ResourceNotFound => e
            print_debug "Resource not found for company #{company_id} factors: #{e.message}"
            []
          end
        end

        def issue_types_list(ssc_exclude_severity)
          endpoint = "#{@baseapi}/metadata/issue-types"

          begin
            response = http_get(endpoint, @headers)
            JSON.parse(response.body.to_s)["entries"].filter_map { |x| x["key"] unless ssc_exclude_severity.include? x["severity"] }
          rescue Faraday::ResourceNotFound => e
            print_debug "Resource not found for issue types: #{e.message}"
            []
          end
        end
      end
    end
  end
end
