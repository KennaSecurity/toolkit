# frozen_string_literal: true

module Kenna
  module Toolkit
    module CheckmarxSast
      class Client
        class ApiError < StandardError; end

        def initialize(hostname, port, username, password, client_secret, page_size, batch_size)
          @base_path = "https://#{hostname}#{":#{port}" if port}"
          @page_size = page_size
          @batch_size = batch_size
          @token = request_checkmarx_sast_token(username, password, client_secret)
        end

        def projects
          endpoint = "#{@base_path}/cxrestapi/projects"
          response = http_get(endpoint, headers)
          raise ApiError, "Unable to retrieve projects." unless response

          JSON.parse(response.body)
        end

        def sast_scans(project_id)
          endpoint = "#{@base_path}/cxrestapi/sast/scans?last=1&scanStatus=Finished&projectId=#{project_id}"
          response = http_get(endpoint, headers)
          raise ApiError, "Unable to retrieve sast scans." unless response

          JSON.parse(response.body)
        end

        def generate_sast_scan_report(scan_id)
          endpoint = "#{@base_path}/cxrestapi/reports/sastScan"
          payload = {
            ScanId: scan_id,
            reportType: "XML"
          }
          response = http_post(endpoint, post_headers, payload)
          raise ApiError, "Unable to generate sast scan report." unless response

          report = JSON.parse(response.body)
          report.fetch("reportId")
        end

        def sast_scan_report(report_id)
          endpoint = "#{@base_path}/cxrestapi/reports/sastScan/#{report_id}"
          response = http_get(endpoint, headers)
          raise ApiError, "Unable to retrieve sast scan report." unless response

          Hash.from_xml(response.body)
        end

        def osa_scans(project_id)
          endpoint = "#{@base_path}/cxrestapi/osa/scans?projectId=#{project_id}"
          response = http_get(endpoint, headers)
          raise ApiError, "Unable to retrieve osa scans." unless response

          JSON.parse(response.body)
        end

        def osa_vulnerabilities(scan_id, page)
          endpoint = "#{@base_path}/cxrestapi/osa/vulnerabilities?scanId=#{scan_id}&page=#{page}&itemsPerPage=#{@page_size}"
          response = http_get(endpoint, headers)
          raise ApiError, "Unable to retrieve osa vulnerabilities." unless response

          JSON.parse(response.body)
        end

        def paged_osa_vulnerabilities(scan_id, &block)
          return to_enum(__method__, scan_id) unless block

          page = 1
          loop do
            response = osa_vulnerabilities(scan_id, page)
            response.each_slice(@batch_size, &block)
            break if response.count < @page_size

            page += 1
          end
        end

        private

        def request_checkmarx_sast_token(username, password, client_secret)
          endpoint = "#{@base_path}/cxrestapi/auth/identity/connect/token"
          headers = { "content-type" => "application/x-www-form-urlencoded" }
          payload = {
            grant_type: "password",
            scope: "sast_api",
            username:,
            password:,
            client_id: "resource_owner_sast_client",
            client_secret:
          }

          response = http_post(endpoint, headers, payload)
          raise ApiError, "Unable to retrieve Auth Token. Check credentials." unless response

          JSON.parse(response.body)["access_token"]
        end

        def headers
          {
            "Content-Type" => "application/json",
            "Accept" => "application/json",
            "Authorization" => "Bearer #{@token}"
          }.dup
        end

        def post_headers
          headers.merge("Content-Type" => "application/x-www-form-urlencoded")
        end
      end
    end
  end
end
