# frozen_string_literal: true

require "json"
require "active_support"
require "active_support/core_ext"
require "rest_client"
require "base64"

module Kenna
  module Toolkit
    module QualysWasHelper
      def qualys_was_get_token(username, password)
        auth_details = "#{username}:#{password}"
        Base64.encode64(auth_details)
      end

      def qualys_was_get_webapp(token, qualys_was_url = "qualysapi.qg3.apps.qualys.com/qps/rest/3.0/")
        print_good "Getting Webapp \n"
        qualys_was_auth_api = "https://#{qualys_was_url}search/was/webapp"

        @headers = {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Basic #{token}"
        }
        payload = {
          "ServiceRequest" => {
            "preferences" => {
              "verbose" => "true",
              "limitResults" => "100"
            }
          }
        }

        auth_response = http_post(qualys_was_auth_api, @headers, payload.to_json)
        return nil unless auth_response

        begin
          response = JSON.parse(auth_response.body)
        rescue JSON::ParserError
          print_error "Unable to process Auth Token response!"
        end

        print_good response
        print_good "\n\n \n\n"
        response
      end

      def qualys_was_get_webapp_findings(webapp_id, token, qualys_was_url = "qualysapi.qg3.apps.qualys.com/qps/rest/3.0/")
        print_good "Getting Webapp Findings For #{webapp_id} \n"
        qualys_was_auth_api = "https://#{qualys_was_url}search/was/finding"

        @headers = {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Basic #{token}"
        }

        payload = {
          "ServiceRequest": {
            "preferences": {
              "verbose": "true",
              "limitResults": "100"
            },
            "filters": {
              "Criteria": {
                "field": "webApp.id",
                "operator": "EQUALS",
                "value": webapp_id.to_s
              }
            }
          }
        }

        auth_response = http_post(qualys_was_auth_api, @headers, payload.to_json)
        return nil unless auth_response

        begin
          response = JSON.parse(auth_response.body)
        rescue JSON::ParserError
          print_error "Unable to process Auth Token response!"
        end

        print_good response
        print_good "\n\n \n\n"
        response
      end

      def qualys_was_get_vuln(qids, token, qualys_was_url = "qualysapi.qg3.apps.qualys.com/api/2.0/fo/")
        print_good "Getting VULN For #{qids} \n"
        qualys_was_auth_api = URI("https://#{qualys_was_url}knowledge_base/vuln/")

        @headers = {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Basic #{token}",
          "X-Requested-With" => "QualysPostman"
        }

        payload = {
          "action" => "list",
          "ids" => qids.join(",")
        }

        qualys_was_auth_api.query = URI.encode_www_form(payload)
        auth_response = http_get(qualys_was_auth_api.to_s, @headers)
        return nil unless auth_response

        begin
          response = Hash.from_xml(auth_response.body).to_json
        rescue JSON::ParserError
          print_error "Unable to process XML response!"
        end

        print_good response
        print_good "\n\n \n\n"
        response
      end

      def qualys_was_get_containers(qualys_was_url, token, pagesize, pagenum)
        print_debug "Getting All Containers"
        qualys_was_cont_api = "http://#{qualys_was_url}/api/v2/containers?pagesize=#{pagesize}&page=#{pagenum}"
        puts "finding #{qualys_was_cont_api}"
        @headers = { "Content-Type" => "application/json",
                     "accept" => "application/json",
                     "Authorization" => "Bearer #{token}" }

        response = http_get(qualys_was_cont_api, @headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process Containers response!"
        end

        json["result"]
      end

      def qualys_was_get_vuln_for_container(qualys_was_url, token, image, pagesize, pagenum)
        print_debug "Getting Vulnerabilities for a Container image"
        qualys_was_cont_img_api = "http://#{qualys_was_url}/api/v2/risks/vulnerabilities?image_name=#{image}&pagesize=#{pagesize}&page=#{pagenum}"
        puts "finding #{qualys_was_cont_img_api}"
        @headers = { "Content-Type" => "application/json",
                     "accept" => "application/json",
                     "Authorization" => "Bearer #{token}" }

        response = http_get(qualys_was_cont_img_api, @headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process Image vulnerabilities for Containers response!"
        end

        json["result"]
      end
    end
  end
end
