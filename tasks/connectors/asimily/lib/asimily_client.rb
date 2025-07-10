# frozen_string_literal: true

module Kenna
  module Toolkit
    module Asimily
      class Client
        class ApiError < StandardError; end
        SCANNER_TYPE = "Asimily"
        def initialize(base_url, username, password, page_size)
          @base_url = base_url
          @page_size = page_size
          @headers = {
            "content-type": "application/json",
            "accept": "application/json",
            "Authorization": "Basic #{Base64.strict_encode64("#{username}:#{password}")}"
          }
        end

        def fetch_devices(page_size, current_page = 0, filters = {})
          endpoint = '/api/extapi/assets'
          uri = URI.parse("https://#{@base_url}#{endpoint}")

          filters.merge!({ size: page_size, page: current_page })

          query_string = URI.encode_www_form(filters)

          uri.query = query_string
          url = uri.to_s

          devices = []
          response = http_get(url, @headers)
          json_resp = JSON.parse(response.body)
          devices.concat(json_resp['content'])

          total_elements = json_resp['totalElements']
          total_pages = (json_resp['totalElements'] / page_size).to_i

          print("Total pages: #{total_pages} and total elements: #{total_elements}") if current_page.zero?
          print("Fetching devices for page #{current_page + 1}") unless devices.empty?
          print("No devices found with matching filter criteria") if devices.empty? && current_page.zero?

          has_more_pages = !(json_resp['last'] || json_resp['content'].nil? || json_resp['content'].empty?)

          [devices, has_more_pages]
        end

        def fetch_vulnerabilities(device_id)
          endpoint = "/api/extapi/assets/cves/#{device_id}"
          uri = URI.parse("https://#{@base_url}#{endpoint}")
          url = uri.to_s

          vul_response = http_get(url, @headers)
          vul_response = JSON.parse(vul_response.body)

          vulnerabilities = []
          vulnerabilities = transform_vulnurebilities(vul_response.first['cves'], device_id) if vul_response.first['cves'].is_a?(Array) && !vul_response.first['cves'].empty?

          vulnerabilities
        end

        def transform_vulnurebilities(vul, device_id)
          transformed_vulnerabilities = []

          vul.each do |cve|
            transformed_vulnerabilities << {
              "status" => check_cve_status(cve),
              "scanner_type" => SCANNER_TYPE,
              "scanner_identifier" => "#{cve['cveName']}|#{device_id}",
              "cve_identifiers" => cve['cveName'],
              "name" => (nil_if(cve['cveTitle']).nil? ? nil : cve['cveTitle']),
              "desciption" => (nil_if(cve['desciption']).nil? ? nil : cve['desciption']),
              "scanner_score" => [(cve['score']&.to_f || 1), 1].max.ceil.to_i,
              "last_seen_at" => date_to_iso8601(nil),
              "vuln_def_name" => (cve['cveName']),
              "solution" => cve_solution(cve),
              "details" => cve_details(cve),
              "created_at" => date_to_iso8601(nil_if(cve['openDate']).nil? ? nil : cve['openDate']),
              "last_fixed_on" => date_to_iso8601(nil_if(cve['fixedDate']).nil? ? nil : cve['fixedDate'])
            }.compact
          end
          transformed_vulnerabilities
        end

        def cve_solution(cve)
          return "" unless cve["ruleTextTypeMap"]&.any?

          solution = cve["ruleTextTypeMap"].map do |rule_type, messages|
            next if ['TRIGGER_TEXT', 'TRIGGER_CONDITION'].include?(rule_type)

            recommmendation_type = rule_type.split.map(&:capitalize).join(' ')
            recommendations = messages.map { |message| "  - #{message}" }.join("\n")
            "#{recommmendation_type}\n#{recommendations}"
          end

          solution.join("\n")
        end

        def cve_details(cve)
          return "" unless cve["ruleTextTypeMap"]&.any?

          details = cve["ruleTextTypeMap"].map do |rule_type, messages|
            next unless rule_type == 'TRIGGER_TEXT'

            recommendations = messages.map { |message| "  - #{message}" }.join("\n")
            recommendations
          end.compact

          details.join("\n")
        end

        def check_cve_status(cve)
          status = nil_if(cve['status'])&.downcase || "open"
          status == "fixed" ? "closed" : "open"
        end

        def transform_vulnerability(cve)
          {
            "scanner_identifier" => cve["scanner_identifier"],
            "scanner_type" => cve["scanner_type"],
            "scanner_score" => cve["scanner_score"],
            "last_seen_at" => cve["last_seen_at"],
            "created_at" => cve["created_at"],
            "status" => cve["status"],
            "last_fixed_on" => cve["last_fixed_on"],
            "vuln_def_name" => cve["vuln_def_name"]
          }.compact
        end

        def transform_vulnerability_def(cve)
          {
            "scanner_identifier" => cve["scanner_identifier"],
            "scanner_type" => cve["scanner_type"],
            "cve_identifiers" => cve["cve_identifiers"],
            "name" => cve["vuln_def_name"],
            "desciption" => cve["desciption"],
            "solution" => cve["solution"],
            "details" => cve["details"]
          }.compact
        end

        def extract_tags(device)
          tags = (device["deviceTag"] || []) # (device["deviceTag"]&.is_a?(Hash) ? device["deviceTag"].map { |k, v| "#{k}:#{v}" } : [])
          tags << "Facility: #{device['facility']}" if nil_if(device['facility'])
          tags << "DeviceModel: #{device['deviceModel']}" if nil_if(device['deviceModel'])
          tags << "DeviceType: #{device['deviceType']}" if nil_if(device['deviceType'])
          tags << "Manufacturer: #{device['manufacturer']}" if nil_if(device['manufacturer'])
          tags << "DeviceMasterFamily: #{device['deviceMasterFamily']}" if nil_if(device['deviceMasterFamily'])
        end

        def transform_device(device)
          {
            "ip_address" => (device['v4IpAddrs'] || []).first,
            "external_id" => device['deviceID'].to_s,
            "mac_address" => nil_if(device['macAddr']),
            "hostname" => nil_if(device['hostName']),
            "os" => nil_if(device['os'], ["", "unknown"]),
            "last_seen_time" => date_to_iso8601(nil_if(device['lastDiscoveredAt']).nil? ? DateTime.now : device['lastDiscoveredAt']),
            "tags" => extract_tags(device)
          }.compact
        end

        def date_to_iso8601(string_date)
          parsed_date = begin
            Date.parse(string_date)
          rescue StandardError
            nil
          end
          parsed_date&.to_datetime&.iso8601
        end

        def nil_if(value, nil_values = [""])
          nil_values.include?(value) ? nil : value
        end
      end
    end
  end
end
