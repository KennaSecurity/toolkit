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

        # def issues_for_portfolio(portfolio_id, issue_types = nil)
        #   out_issues = []
        #   companies = companies_by_portfolio(portfolio_id)
        #   puts "DEBUG Got #{companies.count} companies"

        #   if companies.count.positive?

        #     companies["entries"].each do |c|
        #       puts "Working on company #{c}"

        #       # default to all issues
        #       issue_types ||= issue_types_list

        #       issue_types.each do |it|
        #         issues = issues_by_type_for_company(c["domain"], it)["entries"]
        #         if issues
        #           puts "#{issues.count} issues of type #{it}"
        #           out_issues.concat(issues.map { |i| i.merge({ "type" => it }) })
        #         else
        #           puts "Missing (or error) on #{it} issues"
        #         end
        #       end
        #     end
        #   else
        #     out_issues = []
        #   end

        #   out_issues.flatten
        # end

        def portfolios
          endpoint = "#{@baseapi}/portfolios"

          response = http_get(endpoint, @headers)

          JSON.parse(response.body.to_s)
        end

        def companies_by_portfolio(portfolio_id)
          endpoint = "#{@baseapi}/portfolios/#{portfolio_id}/companies"

          print_debug "Requesting #{endpoint}"

          response = http_get(endpoint, @headers)
          JSON.parse(response.body)
        end

        def issues_by_type_for_company(company_id, itype = "patching_cadence_low")
          endpoint = "#{@baseapi}/companies/#{company_id}/issues/#{itype}"
          response = http_get(endpoint, @headers, 0)
          JSON.parse(response.body.to_s) unless response.nil?
        end

        def issue_types_list
          endpoint = "#{@baseapi}/metadata/issue-types"

          response = http_get(endpoint, @headers)
          JSON.parse(response.body.to_s)["entries"].map { |x| x["key"] unless x["severity"] == "info" || x["severity"] == "low" }.compact
        end

        #  "https://api.securityscorecard.io/reports/issues";     payload=''
        def issues_report_for_domain(domain)
          ###
          ### Generate an issues report
          ###
          puts "DEBUG Generating issues report"
          endpoint = "#{@baseapi}/reports/issues"
          http_post(endpoint, @headers, { "domain" => domain, "format" => "csv" })
          now = Time.now.utc
          puts "DEBUG #{now}"

          ###
          ### Now get the list of recently generated reports
          ###
          puts "DEBUG getting list of recent reports"
          endpoint = "https://api.securityscorecard.io/reports/recent"
          response = http_get(endpoint, @headers)

          report_list = JSON.parse(response.body)["entries"]

          ###
          ### Now wait for our report to be generated, and then get it
          ###
          latest_report_completed_at = now
          tries = 0
          max_retries = 10

          while latest_report_completed_at <= now
            puts "DEBUG Waiting for report to be generatd. Last report generated: #{latest_report_completed_at}"

            last_report = report_list.max_by { |x| (x["completed_at"]).to_s }

            download_url = last_report["download_url"]
            latest_report_completed_at = Time.parse(last_report["completed_at"])
            puts "DEBUG Latest report completed at: #{latest_report_completed_at}"

            ### Max retries
            if latest_report_completed_at == now && tries < max_retries
              puts "DEBUG Waiting 10s for report generation"
              sleep 10
              tries += 1
              next
            end

            puts "DEBUG Got download url: #{download_url}"
            response = http_get(download_url, @headers)
            puts response

            puts "DEBUG Returning parsed version"
            return CSV.parse(response.body)
          end

          nil
        end
      end
    end
  end
end
