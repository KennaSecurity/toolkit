# frozen_string_literal: true

# rubocop:disable Naming/AccessorMethodName
module Kenna
  module Api
    class Client
      include Kenna::Toolkit::Helpers::Http

      def version
        "1.1.0"
      end

      def initialize(api_token, api_host)
        @token = api_token
        @base_url = "https://#{api_host}"
      end

      class << self
        attr_accessor :task_name
      end

      def get_http_headers
        {
          "content-type" => "application/json",
          "X-Risk-Token" => @token,
          "accept" => "application/json",
          "User-Agent" => "Toolkit.#{self.class.task_name}/#{version} (Cisco Secure)"
        }
      end

      def get_connectors
        _kenna_api_request(:get, "connectors")
      end

      def get_connector(connector_id)
        _kenna_api_request(:get, "connectors/#{connector_id}")
      end

      def get_connector_runs(connector_id)
        _kenna_api_request(:get, "connectors/#{connector_id}/connector_runs")
      end

      # TODO: add page and per_page params
      def get_asset_groups
        _kenna_api_request(:get, "asset_groups")
      end

      def get_asset_group(asset_group_id)
        _kenna_api_request(:get, "asset_groups/#{asset_group_id}")
      end

      def get_assets
        _kenna_api_request(:get, "assets")
      end

      def get_assets_with_query(query)
        query = URI.parse(CGI.escape(query)).to_s
        _kenna_api_request(:get, "assets/search?q=#{query}&per_page=5000")
      end

      def get_asset(asset_id)
        _kenna_api_request(:get, "assets/#{asset_id}")
      end

      def get_asset_tags(asset_id)
        _kenna_api_request(:get, "assets/#{asset_id}/tags")
      end

      def get_applications
        _kenna_api_request(:get, "applications")
      end

      def get_application(application_id)
        _kenna_api_request(:get, "applications/#{application_id}")
      end

      # TODO: add page and per_page params
      def get_fixes
        _kenna_api_request(:get, "fixes")
      end

      def get_fix(fix_id)
        _kenna_api_request(:get, "fixes/#{fix_id}")
      end

      def get_asset_group_fixes(asset_group_id)
        _kenna_api_request(:get, "asset_groups/#{asset_group_id}/fixes")
      end

      def get_scanner_vuln_details(vuln_id)
        _kenna_api_request(:get, "vulnerabilities/#{vuln_id}/scanner_vulnerabilities")
      end

      def get_asset_vulns(asset_id)
        _kenna_api_request(:get, "assets/#{asset_id}/vulnerabilities")
      end

      def get_users
        _kenna_api_request(:get, "users")
      end

      def get_user(user_id)
        _kenna_api_request(:get, "users/#{user_id}")
      end

      def get_roles
        _kenna_api_request(:get, "roles")
      end

      def get_role(role_id)
        _kenna_api_request(:get, "roles/#{role_id}")
      end

      def get_vulns
        _kenna_api_request(:get, "vulnerabilities")
      end

      def get_vuln(vuln_id)
        _kenna_api_request(:get, "vulnerabilities/#{vuln_id}")
      end

      def get_cve_ids
        _kenna_api_request(:get, "vulnerability_definitions/cve_identifiers")
      end

      # cve_id - CVE-2020-0601 as an example id to pass
      def get_cve_id(cve_id)
        _kenna_api_request(:get, "vulnerability_definitions/#{cve_id}")
      end

      def get_dashboard_groups
        _kenna_api_request(:get, "dashboard_groups")
      end

      def upload_to_connector(connector_id, filepath, run_now = true, max_retries = 3, debug = false)
        resource = "connectors/#{connector_id}/data_file"
        resource += "?run=true" if run_now

        payload = { multipart: true, file: File.new(filepath, "rb") }
        retries = 0
        
        begin
          print_good "Sending request"
          out = _kenna_api_request(:post, resource, payload)
          raise StandardError, "File upload failed. Kenna response: #{out[:results]}" unless out[:status] == "success" && out[:results].fetch("success", nil) == "true"

          print_good "Success!"
          File.delete(filepath) unless debug

          if run_now
            running = true
            check_resource = "connectors/#{connector_id}"
            while running
              sleep(20)
              check_out = _kenna_api_request(:get, check_resource)

              begin
                connector_check_json = check_out[:results]["connector"]
              rescue StandardError
                connector_check_json = nil
              end

              print_good "#{connector_check_json['name']} connector running" if connector_check_json && connector_check_json["running"]
              running = connector_check_json ? connector_check_json["running"] : false
            end
          end
        rescue StandardError => e
          print_error "Exception: #{e.message}"
          retries += 1
          if retries <= max_retries
            print_error "Retrying in 60s... (#{retries}/#{max_retries})"
            sleep(60)
            retry
          else
            print_error "Max retries hit, failing with... #{e}"
            return { status: "fail", message: e.message, results: {} }
          end
        end

        print_good "Done!"
        out[:results]
      end

      def run_files_on_connector(connector_id, upload_ids, max_retries = 3)
        resource = "connectors/#{connector_id}/run"
        payload = { "data_files" => upload_ids }
        retries = 0
        out = nil

        begin
          print_good "Sending request"
          out = _kenna_api_request(:post, resource, payload)
          raise StandardError, "Run request failed. Kenna response: #{out[:results]}" unless out[:status] == "success" && out[:results].fetch("success", nil)

          print_good "Success!" if out[:results].fetch("success", nil)

          running = true
          check_resource = "connectors/#{connector_id}"
          while running
            sleep(20)
            check_out = _kenna_api_request(:get, check_resource)

            begin
              connector_check_json = check_out[:results]["connector"]
            rescue StandardError
              connector_check_json = nil
            end

            print_good "#{connector_check_json['name']} connector running" if connector_check_json && connector_check_json["running"]
            running = connector_check_json ? connector_check_json["running"] : false
          end

          # Get connector run status if connector_run_id is present
          if out[:results]["connector_run_id"]
            run_status_resource = "connectors/#{connector_id}/connector_runs/#{out[:results]['connector_run_id']}"
            run_status_out = _kenna_api_request(:get, run_status_resource)
            return run_status_out[:results]
          end
        rescue StandardError => e
          print_error "Exception: #{e.message}"
          retries += 1
          if retries <= max_retries
            print_error "Retrying in 60s... (#{retries}/#{max_retries})"
            sleep(60)
            retry
          else
            print_error "Max retries hit, failing with... #{e}"
            return { status: "fail", message: e.message, results: {} }
          end
        end

        print_good "Done!"
        out[:results]
      end

      private

      def _kenna_api_request(method, resource, body = nil)
        headers = { "X-Risk-Token": @token.to_s }
        endpoint = "#{@base_url}/#{resource}"
        out = { method: method.to_s, resource: resource.to_s }

        begin
          case method
          when :get
            response = http_get(endpoint, headers)
          when :post
            response = http_post(endpoint, headers, body.to_json)
          else
            out.merge!({ status: "fail", message: "unknown method", results: {} })
            return out
          end

          parsed_results = JSON.parse(response.body)
          out.merge!({ status: "success", results: parsed_results })
        rescue Faraday::ClientError => e
          out.merge!({ status: "fail", message: e.message, results: {} })
          log_exception(e)
        rescue StandardError => e
          out.merge!({ status: "fail", message: e.message, results: {} })
          log_exception(e)
        end
        out
      end
    end
  end
end
# rubocop:enable Naming/AccessorMethodName
