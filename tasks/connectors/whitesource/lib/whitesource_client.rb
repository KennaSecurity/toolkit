# frozen_string_literal: true

module Kenna
  module Toolkit
    module Whitesource
      class Client
        class ApiError < StandardError; end

        def initialize(user_key, request_type, request_token, alert_type, days_back, api_base_url)
          @endpoint = "https://#{api_base_url}/api/v1.4"
          @headers = { "accept": "application/json", "content-type": "application/json" }
          @user_key = user_key
          @request_type = request_type
          @request_token = request_token
          @alert_type = alert_type
          @from_date = Date.today - days_back if days_back.present?
        end

        def alerts
          response = http_post(@endpoint, @headers, request_body)
          raise ApiError, "Unable to retrieve alerts, please check credentials" unless response

          JSON.parse(response.body)["alerts"]
        end

        private

        def request_body
          payload = {
            "requestType": api_request_type,
            "userKey": @user_key,
            "alertType": "SECURITY_VULNERABILITY"
          }
          payload["fromDate"] = @from_date if @from_date
          payload[api_token_param_name] = @request_token
          payload.to_json
        end

        def api_request_type
          {
            "organization" => "getOrganizationAlertsByType",
            "product" => "getProductAlertsByType",
            "project" => "getProjectAlertsByType"
          }.fetch(@request_type)
        end

        def api_token_param_name
          {
            "organization" => "orgToken",
            "product" => "productToken",
            "project" => "projectToken"
          }.fetch(@request_type)
        end
      end
    end
  end
end
