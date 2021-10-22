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

        def get_site_scans(site_id)
          response = http_post(@endpoint, @headers, query(site_scans_query, site_id: site_id))
          JSON.parse(response)['data']['scans']
        end

        def get_last_site_scan(site_id)
          response = http_post(@endpoint, @headers, query(last_site_scan_query, site_id: site_id))
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

        def site_scans_query
          "query ScanInfo($site_id: ID!){
            scans(offset: 0, limit: 1000, scan_status:[succeeded], site_id: $site_id){
              id
              site_id
              status
              issue_counts {
                total
              }
            }
          }"
        end

        def last_site_scan_query
          "query ScanInfo($site_id: ID!){
            scans(offset: 0, limit: 1, scan_status:[succeeded], sort_column: start, sort_order: desc, site_id: $site_id){
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
