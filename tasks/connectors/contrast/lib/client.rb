# frozen_string_literal: true

require "json"

module Kenna
  module Toolkit
    module Contrast
      class Client
        def initialize(contrast_host, contrast_port, contrast_api_key, contrast_auth_header, contrast_org_id, contrast_use_https)
          protocol = contrast_use_https ? "https://" : "http://"
          @base_url = "#{protocol}#{contrast_host}#{contrast_port.nil? ? '' : ':'}#{contrast_port}/Contrast/api/ng/#{contrast_org_id}"
          print "Base URL is #{@base_url}"
          @headers = { "Authorization": contrast_auth_header.to_s, "API-Key": contrast_api_key.to_s, "Content-Type": "application/json" }
          @recs = {}
          @tags = {}
        end

        def get_vulns(tags, environments, severities)
          print "Getting vulnerabilities from the Contrast API"

          more_results = true
          offset = 0
          limit = 25
          out = []

          while more_results
            url = "#{@base_url}/orgtraces/filter?expand=application&offset=#{offset}&limit=#{limit}&applicationTags=#{tags}&environments=#{environments}&severities=#{severities}&licensedOnly=true"

            response = RestClient.get(url, @headers)
            body = JSON.parse response.body

            # prepare the next request
            offset += limit

            if response.nil? || response.empty? || offset > body["count"]
              # morepages = false
              more_results = false
              break
            end

            # do stuff with the data
            out.concat(body["traces"])

            print "Fetched #{out.length} of #{body['count']} vulnerabilities"

          end

          out
        end

        def get_vulnerable_libraries(apps)
          print "Getting vulnerable libraries from the Contrast API"

          more_results = true
          offset = 0
          limit = 25
          out = []

          payload = {
            quickFilter: "VULNERABLE",
            "apps": apps
          }

          while more_results
            url = "#{@base_url}/libraries/filter?offset=#{offset}&limit=#{limit}&sort=score&expand=skip_links%2Capps%2Cvulns%2Cstatus%2Cusage_counts"

            response = RestClient.post(url, payload.to_json, @headers)
            body = JSON.parse response.body

            # prepare the next request
            offset += limit

            if response.nil? || response.empty? || body["libraries"].count.zero?
              # morepages = false
              more_results = false
              break
            end

            # do stuff with the data
            out.concat(body["libraries"])

            print "Fetched #{offset} libraries"

          end

          out
        end

        def get_application_ids(tags)
          print "Getting applications from the Contrast API"
          url = "#{@base_url}/applications/filter/short?filterTags=#{tags}"
          response = RestClient.get(url, @headers)
          temp = JSON.parse response.body
          temp["applications"]
        end

        def get_application_tags(app_id)
          if @tags[app_id].nil?
            url = "#{@base_url}/tags/application/list/#{app_id}"

            response = RestClient.get(url, @headers)
            temp = JSON.parse response.body
            @tags[app_id] = temp["tags"]
          end
          @tags[app_id]
        end

        def get_trace_recommendation(id, rule_name)
          if @recs[rule_name].nil?
            # print "Getting recommendation for rule #{rule_name}"
            url = "#{@base_url}/traces/#{id}/recommendation"
            response = RestClient.get(url, @headers)

            @recs[rule_name] = JSON.parse response.body
          end
          @recs[rule_name]
        end

        def get_trace_story(id)
          # begin
          url = "#{@base_url}/traces/#{id}/story"

          response = RestClient.get(url, @headers)
          JSON.parse response.body
        rescue RestClient::ExceptionWithResponse => e
          print "Error fetching trace story for #{id}: #{e} (unlicensed?)"
        end
      end
    end
  end
end
