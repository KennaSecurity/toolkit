# frozen_string_literal: true

require "open-uri"

module Kenna
  module Toolkit
    module Burp
      class BurpClient
        def initialize(host, api_token)
          @endpoint = "#{host}/graphql/v1"
          @headers = { "content-type": "application/json", "Authorization": api_token }
        end

        def get_last_schedule_scan(schedule_id)
          response = http_post(@endpoint, @headers, query(last_schedule_scan_query, schedule_id: schedule_id))
          JSON.parse(response)['data']['scans'].first
        end

        def get_scan(id)
          response = http_post(@endpoint, @headers, query(scan_query, id: id))
          JSON.parse(response)['data']['scan']
        end

        private

        def query(string, params = {})
          query = { query: string, variables: params }
          query.to_json
        end

        def last_schedule_scan_query
          "query ScanInfo($schedule_id: ID!){
            scans(offset: 0, limit: 1, scan_status:[succeeded], sort_column: start, sort_order: desc, schedule_item_id: $schedule_id){
              id
              site_id
              status
              issue_counts {
                total
              }
            }
          }"
        end

        def scan_query
          "query GetScan ($id: ID!) {
            scan(id: $id) {
                id
                status
                issues(start: 0, count: 100) {
                    issue_type {
                        name
                        description_html
                        remediation_html
                        vulnerability_classifications_html
                        references_html
                    }
                    confidence
                    display_confidence
                    serial_number
                    severity
                    path
                    origin
                    novelty
                }
            }
          }"
        end
      end
    end
  end
end
