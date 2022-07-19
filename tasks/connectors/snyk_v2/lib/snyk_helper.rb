# frozen_string_literal: true

module Kenna
  module Toolkit
    module SnykHelper
      def snyk_get_orgs(token)
        # print "Getting list of orgs"
        # snyk_query_api = "https://snyk.io/api/v1/orgs"
        # response = http_get(snyk_query_api, headers(token))
        # return nil unless response
        #
        # json = parse_json(response.body)
        # json["orgs"]

        [
          {
            "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa",
            "name" => "org_name",
            "slug" => "org-name",
            "url" => "https://app.snyk.io/org/org-name",
            "group" => { "name" => "Orgname", "id" => "1ee11111-e111-1111-11e1-11ee11eee1e1" }
          }
        ]
      end

      # [
      #   {
      #     "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa",
      #     "name" => "org_name",
      #     "slug" => "org-name",
      #     "url" => "https://app.snyk.io/org/org-name",
      #     "group" => { "name" => "Orgname", "id" => "1ee11111-e111-1111-11e1-11ee11eee1e1" }
      #   }
      # ]

      def snyk_get_projects(token, org)
        # print "Getting list of projects"
        # snyk_query_api = "https://snyk.io/api/v1/org/#{org}/projects?perPage=#{page_size}&page=#{page_num}"
        # response = http_get(snyk_query_api, headers(token))
        # return nil unless response
        #
        # json = parse_json(response.body)
        # json["projects"]

        [
          {
            "attributes" => {
              "businessCriticality" => ["medium"],
              "created" => "2021-05-29T09:50:54.014Z",
              "environment" => ["external", "hosted"],
              "lifecycle" => ["production"],
              "name" => "snyk/proj_name",
              "origin" => "github",
              "status" => "active",
              "tags" => [{ "key" => "tag-key", "value" => "tag-value" }],
              "targetReference" => "master",
              "type" => "maven"
            },
            "id" => "222ooo2o-oo22-222o-o222-222ooooo22oo",
            "relationships" => {
              "importingUser" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
              "org" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
              "owner" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
              "target" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } }
            },
            "type" => "projects"
          }, {
            "attributes" => {
              "businessCriticality" => ["medium"],
              "created" => "2021-05-29T09:50:54.014Z",
              "environment" => ["external", "hosted"],
              "lifecycle" => ["production"],
              "name" => "snyk/proj_name",
              "origin" => "github",
              "status" => "active",
              "tags" => [{ "key" => "tag-key", "value" => "tag-value" }],
              "targetReference" => "master",
              "type" => "maven"
            },
            "id" => "999qqq9q-qq99-999q-q999-999qqqqq9999",
            "relationships" => {
              "importingUser" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
              "org" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
              "owner" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
              "target" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } }
            },
            "type" => "projects"
          }
        ]
      end

      # [
      #   {
      #     "attributes" => {
      #       "businessCriticality" => ["medium"],
      #       "created" => "2021-05-29T09:50:54.014Z",
      #       "environment" => ["external", "hosted"],
      #       "lifecycle" => ["production"],
      #       "name" => "snyk/proj_name",
      #       "origin" => "github",
      #       "status" => "active",
      #       "tags" => [{ "key" => "tag-key", "value" => "tag-value" }],
      #       "targetReference" => "master",
      #       "type" => "maven"
      #     },
      #     "id" => "222ooo2o-oo22-222o-o222-222ooooo22oo",
      #     "relationships" => {
      #       "importingUser" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
      #       "org" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
      #       "owner" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
      #       "target" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } }
      #     },
      #     "type" => "projects"
      #   }, {
      #     "attributes" => {
      #       "businessCriticality" => ["medium"],
      #       "created" => "2021-05-29T09:50:54.014Z",
      #       "environment" => ["external", "hosted"],
      #       "lifecycle" => ["production"],
      #       "name" => "snyk/proj_name",
      #       "origin" => "github",
      #       "status" => "active",
      #       "tags" => [{ "key" => "tag-key", "value" => "tag-value" }],
      #       "targetReference" => "master",
      #       "type" => "maven"
      #     },
      #     "id" => "999qqq9q-qq99-999q-q999-999qqqqq9999",
      #     "relationships" => {
      #       "importingUser" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
      #       "org" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
      #       "owner" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } },
      #       "target" => { "data" => { "id" => "88888aaa-88a8-888a-aaa8-8aaa8888a8aa", "type" => "org" }, "links" => { "self" => { "href" => "/v3/orgs/88888aaa-88a8-888a-aaa8-8aaa8888a8aa" } } }
      #     },
      #     "type" => "projects"
      #   }
      # ]

      def snyk_get_issues(token, perpage, search_json, pagenum, from_date, to_date)
        # print "Getting issues"
        # snyk_query_api = "https://snyk.io/api/v1/reporting/issues?perPage=#{perpage}&page=#{pagenum}&from=#{from_date}&to=#{to_date}"
        # print_debug("Get issues query: #{snyk_query_api}")
        # response = http_post(snyk_query_api, headers(token), search_json)
        # return nil unless response
        #
        # json = parse_json(response.body)
        # json["results"]
        [{ "Test" => "IT WORKS!!!" }]
      end

      private

      def headers(token)
        { "content-type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "token #{token}" }
      end

      def parse_json(json_string)
        JSON.parse(json_string)
      rescue JSON::ParserError
        print_error "Unable to process response!"
        {}
      end
    end
  end
end
