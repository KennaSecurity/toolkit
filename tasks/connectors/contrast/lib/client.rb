# frozen_string_literal: true

require 'json'

module Kenna
  module Toolkit
    module Contrast
      class Client
        def initialize(contrast_host, contrast_api_key, contrast_auth_header, contrast_org_id, contrast_use_https)
          protocol = contrast_use_https ? "https://" : "http://"
          @base_url = "#{protocol}#{contrast_host}/Contrast/api/ng/#{contrast_org_id}"
          @headers = { "Authorization": "#{contrast_auth_header}", "API-Key": "#{contrast_api_key}", "Content-Type": "application/json" }
          @recs = Hash.new
          @tags = Hash.new
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

            # do stuff with the data
            out.concat(body["traces"])

            print "Fetched #{out.length} of #{body['count']} vulnerabilities"

            # prepare the next request
            offset += limit

            if response.nil? || response.empty? || offset > body["count"]
              morepages = false
              break
            end
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

            # do stuff with the data
            out.concat(body["libraries"])

            print "Fetched #{offset} libraries"

            # prepare the next request
            offset += limit

            if response.nil? || response.empty? || body["libraries"].count == 0
              morepages = false
              break
            end
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


        def get_application_tags(appId)
          if @tags[appId].nil?
            url = "#{@base_url}/tags/application/list/#{appId}"

            response = RestClient.get(url, @headers)
            temp = JSON.parse response.body
            @tags[appId] = temp["tags"]
          end
          @tags[appId]
        end

        def get_trace_recommendation(id, rule_name)
          if @recs[rule_name].nil?
            #print "Getting recommendation for rule #{rule_name}"
            url = "#{@base_url}/traces/#{id}/recommendation"
            response = RestClient.get(url, @headers)

            @recs[rule_name] = JSON.parse response.body
          end
          @recs[rule_name]
        end

        def get_trace_story(id)
          begin
            url = "#{@base_url}/traces/#{id}/story"

            response = RestClient.get(url, @headers)
            JSON.parse response.body
          rescue => exception
            print "Error fetching trace story for #{id}: #{exception} (unlicensed?)"
          end
        end
      end
    end
  end
end
