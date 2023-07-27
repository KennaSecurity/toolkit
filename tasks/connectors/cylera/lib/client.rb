# frozen_string_literal: true

require_relative 'vcr'

module Kenna
  module Toolkit
    module Cylera
      class Client
        class ApiError < StandardError; end

        def initialize(api_host, api_user, api_password)
          @api_host = "https://#{api_host}"
          @api_user = api_user
          @api_password = api_password
          @headers = {
            accept: 'application/json',
            Authorization: "Bearer #{api_token}"
          }
        end

        def get_inventory_devices(params)
          response = http_get("#{@api_host}/inventory/devices?#{params.compact.to_query}", @headers)

          raise ApiError, 'Unable to retrieve inventory devices' unless response

          JSON.parse(response)
        end

        def get_risk_vulnerabilities(params)
          response = http_get("#{@api_host}/risk/vulnerabilities?#{params.compact.to_query}", @headers)

          raise ApiError, 'Unable to retrieve risk vulnerabilities' unless response

          JSON.parse(response)
        end

        def get_risk_mitigations(vulnerability_name)
          response = http_get("#{@api_host}/risk/mitigations?vulnerability=#{vulnerability_name}", @headers)

          raise ApiError, 'Unable to retrieve risk mitigations' unless response

          JSON.parse(response)
        end

        private

        def api_token
          @api_token ||= auth_login_user['token']
        end

        def auth_login_user
          response = http_post("#{@api_host}/auth/login_user", {}, { email: @api_user, password: @api_password })

          raise ApiError, 'Unable to authenticate, please check credentials' unless response

          JSON.parse(response)
        end
      end
    end
  end
end
