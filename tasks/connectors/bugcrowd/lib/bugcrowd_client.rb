# frozen_string_literal: true

require "open-uri"

module Kenna
  module Toolkit
    module Bugcrowd
      class Client
        BUGCROWD_VERSION = "2021-10-28"

        def initialize(host, api_user, api_password)
          @endpoint = host.start_with?("http") ? host : "https://#{host}"
          @headers = { "Accept": "application/vnd.bugcrowd.v4+json",
                       "Content-Type": "application/json",
                       "Authorization": "Token #{api_user}:#{api_password}",
                       "Bugcrowd-Version": BUGCROWD_VERSION }
        end

        def get_submissions(offset = 0, limit = 100)
          url = submissions_url(offset: offset, limit: limit)
          response = http_get(url, @headers, 2)
          build_issues(JSON.parse(response))
        end

        private

        def submissions_url(options = {})
          params_string = "page[offset]=:offset&page[limit]=:limit&fields[submission]=bug_url,custom_fields,description,extra_info,http_request,remediation_advice,source,submitted_at,title,vrt_id,vrt_version,vulnerability_references,severity,state,target,program,cvss_vector&fields[organization]=name&fields[target]=name,category&include=target,program,program.organization,cvss_vector&fields[program]=name,organization"
          params = fill_params(params_string, options)
          "#{@endpoint}/submissions?#{params}"
        end

        def fill_params(params_string, options)
          options.inject(params_string) { |string, (key, value)| string.gsub(key.inspect, CGI.escape(value.to_s)) }
        end

        # The API returns the data separated in submissions and it's associations in the "included" hash.
        # To make things easier, we associate each association hash with it's corresponding owner.
        def build_issues(api_data)
          submissions = api_data["data"]
          included = {}
          api_data["included"].each do |info|
            index = included[info["type"]] ||= {}
            index[info["id"]] = info
          end

          submissions.each do |submission|
            submission["relationships"].each do |type, info|
              if info["data"]
                relationship_id = info["data"]["id"]
                relationship = included[type][relationship_id]
                submission[type] = relationship["attributes"]
              end
              if type == "program"
                organization_id = relationship["relationships"]["organization"]["data"]["id"]
                submission["organization"] = included["organization"][organization_id]["attributes"]
              end
            end
          end

          {
            issues: submissions,
            total_hits: api_data["meta"]["total_hits"],
            count: api_data["meta"]["count"]
          }
        end
      end
    end
  end
end
