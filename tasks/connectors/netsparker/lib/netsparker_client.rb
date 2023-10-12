# frozen_string_literal: true

module Kenna
  module Toolkit
    module Netsparker
      class NetsparkerClient

        def initialize(user_id, token, hostname)
          auth_token = Base64.strict_encode64("#{user_id}:#{token}")
          @endpoint = "https://#{hostname}/api/1.0"
          @headers = {
            "content-type": "application/json",
            "Accept": "application/json",
            "Authorization": "Basic #{auth_token}"
          }
          print_debug "API Client Successfully initialized with hostname: #{hostname}"
        end

        def get_last_scan_vulnerabilities(schedule_id, schedule_scans)
          id = get_last_scan_id(schedule_id, schedule_scans)
          return unless id

          response = http_get(get_vulnerabilities_url(id), @headers)
          JSON.parse(response)
        end

        def retrieve_all_scheduled_scans
          print_debug "starting retrieve_all_scheduled_scans..."
          page = 1
          print_debug "querying page 1..."
          scheduled_scan_result = scheduled_scan_result(page)

          print_debug "printing scheduled_scan_result..."
          print_debug "#{scheduled_scan_result}"
          schedule_scans = []
          
          print_debug = "starting the loop..."
          x = 1
          loop do
            print_debug "Loop number #{x}"
            schedule_scans.push(*scheduled_scan_result.fetch("List"))
            print_debug "scheduled_scan_result Is Last Page = #{scheduled_scan_result["IsLastPage"]}"
            break if scheduled_scan_result["IsLastPage"]

            page += 1
            print_debug "finished with page #{page}, continuing..."
            x +=1
          end

          schedule_scans.uniq
        rescue KeyError
          fail_task "There are no scheduled scans"
        end

        private

        def scheduled_scan_result(page)
          response = http_get(list_scheduled_url(page), @headers)
          JSON.parse(response)
        end

        def get_last_scan_id(schedule_id, schedule_scans)
          found = schedule_scans.detect { |scheduled_scan| scheduled_scan["Id"] == schedule_id }

          if found
            found["LastExecutedScanTaskId"]
          else
            fail_task "Not found scheduled scan with ID #{schedule_id}"
          end
        end

        def list_scheduled_url(page)
          fill_params("#{@endpoint}/scans/list-scheduled?page=:page", page:)
        end

        def get_vulnerabilities_url(id)
          fill_params("#{@endpoint}/scans/report?id=:id&format=Json&type=Vulnerabilities", id:)
        end

        def fill_params(params_string, options)
          options.inject(params_string) { |string, (key, value)| string.gsub(key.inspect, value.to_s) }
        end
      end
    end
  end
end
