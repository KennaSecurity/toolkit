# frozen_string_literal: true

require_relative 'lib/client'

module Kenna
  module Toolkit
    class CyleraTask < Kenna::Toolkit::BaseTask
      CVE_PREFIX = 'CVE'
      SCANNER_TYPE = 'Cylera'
      SEVERITY_VALUES = {
        'Low' => 3,
        'Medium' => 6,
        'High' => 8,
        'Critical' => 10
      }.freeze
      STATUS_VALUES = {
        'Open' => 'Open',
        'In Progress' => 'Open',
        'Resolved' => 'Closed',
        'Suppressed' => 'Closed'
      }.freeze
      SECONDS = "s"

      def self.metadata
        {
          id: 'cylera',
          name: 'Cylera',
          description: 'Pulls assets and vulnerabilitiies from Cylera',
          options: [
            {
              name: 'cylera_api_host',
              type: 'hostname',
              required: true,
              default: nil,
              description: 'Cylera instance hostname, e.g. partner.us1.cylera.com'
            },
            {
              name: 'cylera_api_user',
              type: 'api_key',
              required: true,
              default: nil,
              description: 'Cylera API user email'
            },
            {
              name: 'cylera_api_password',
              type: 'api_key',
              required: true,
              default: nil,
              description: 'Cylera API user password'
            },
            {
              name: 'cylera_ip_address',
              type: 'string',
              required: false,
              default: nil,
              description: 'Partial or complete IP or subnet'
            },
            {
              name: 'cylera_mac_address',
              type: 'string',
              required: false,
              default: nil,
              description: 'Partial or complete MAC address'
            },
            {
              name: 'cylera_first_seen_before',
              type: 'string',
              required: false,
              default: nil,
              description: 'Finds devices that were first seen before this epoch timestamp'
            },
            {
              name: 'cylera_first_seen_after',
              type: 'string',
              required: false,
              default: nil,
              description: 'Finds devices that were first seen after this epoch timestamp'
            },
            {
              name: 'cylera_last_seen_before',
              type: 'string',
              required: false,
              default: nil,
              description: 'Finds devices that were last seen before this epoch timestamp'
            },
            {
              name: 'cylera_last_seen_after',
              type: 'string',
              required: false,
              default: nil,
              description: 'Finds devices that were last seen after this epoch timestamp'
            },
            {
              name: 'cylera_vendor',
              type: 'string',
              required: false,
              default: nil,
              description: 'Device vendor or manufacturer (e.g. Natus)'
            },
            {
              name: 'cylera_type',
              type: 'string',
              required: false,
              default: nil,
              description: 'Device type (e.g. EEG)'
            },
            {
              name: 'cylera_model',
              type: 'string',
              required: false,
              default: nil,
              description: 'Device model (e.g. NATUS NeuroWorks XLTECH EEG Unit)'
            },
            {
              name: 'cylera_class',
              type: 'string',
              required: false,
              default: nil,
              description: 'Device class (e.g. Medical). One of [Medical, Infrastructure, Misc IoT]'
            },
            {
              name: 'cylera_confidence',
              type: 'string',
              required: false,
              default: nil,
              description: 'Confidence in vulnerability detection. One of [LOW, MEDIUM, HIGH]'
            },
            {
              name: 'cylera_detected_after',
              type: 'integer',
              required: false,
              default: nil,
              description: 'Epoch timestamp after which a vulnerability was detected'
            },
            {
              name: 'cylera_name',
              type: 'string',
              required: false,
              default: nil,
              description: 'Name of the vulnerability (complete or partial)'
            },
            {
              name: 'cylera_severity',
              type: 'string',
              required: false,
              default: nil,
              description: 'Vulnerability severity. One of [LOW, MEDIUM, HIGH, CRITICAL]'
            },
            {
              name: 'cylera_status',
              type: 'string',
              required: false,
              default: nil,
              description: 'Vulnerability status. One of [OPEN, IN_PROGRESS, RESOLVED, SUPPRESSED]'
            },
            {
              name: 'cylera_page',
              type: 'integer',
              required: false,
              default: 0,
              description: 'Controls which page of results to return'
            },
            {
              name: 'cylera_page_size',
              type: 'integer',
              required: false,
              default: 100,
              description: 'Controls number of results in each response. Max 100.'
            },
            {
              name: 'incremental',
              type: 'boolean',
              required: false,
              default: false,
              description: 'Pulls data from the last successful run'
            },
            {
              name: 'kenna_api_key',
              type: 'api_key',
              required: false,
              default: nil,
              description: 'Kenna API Key'
            },
            {
              name: 'kenna_api_host',
              type: 'hostname',
              required: false,
              default: 'api.kennasecurity.com',
              description: 'Kenna API Hostname'
            },
            {
              name: 'kenna_connector_id',
              type: 'integer',
              required: false,
              default: nil,
              description: 'If set, we\'ll try to upload to this connector'
            },
            {
              name: 'output_directory',
              type: 'filename',
              required: false,
              default: 'output/cylera',
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}"
            }
          ]
        }
      end

      def run(opts)
        super

        initialize_options

        if @incremental
          api_client = Kenna::Api::Client.new(@kenna_api_key, @kenna_api_host)
          connector_runs = api_client.get_connector_runs(@kenna_connector_id)[:results]
          last_connector_run_start_time = connector_runs.find { |e| e['success'] }.try(:[], 'start_time')&.to_datetime
          @inventory_devices_params[:last_seen_after] = 1.day.ago(last_connector_run_start_time).to_i if last_connector_run_start_time
        end

        client = Kenna::Toolkit::Cylera::Client.new(@api_host, @api_user, @api_password)

        vulnerabilities = []

        loop do
          risk_vulnerabilities = client.get_risk_vulnerabilities(@risk_vulnerabilities_params)
          vulnerabilities << risk_vulnerabilities['vulnerabilities']

          break if risk_vulnerabilities['vulnerabilities'].count < @risk_vulnerabilities_params[:page_size]

          @risk_vulnerabilities_params[:page] += 1
        end

        vulnerabilities = vulnerabilities.flatten.group_by { |e| e['mac_address'] }
        mitigations = {}

        loop do
          inventory_devices = client.get_inventory_devices(@inventory_devices_params)

          inventory_devices['devices'].each do |device|
            asset = extract_asset(device)

            if vulnerabilities[device['mac_address']].present?
              vulnerabilities[device['mac_address']].each do |vulnerability|
                cylera_vulnerability_name = vulnerability['vulnerability_name']
                vulnerability['vulnerability_name'] = vulnerability_name(cylera_vulnerability_name)
                mitigations[vulnerability['vulnerability_name']] ||= client.get_risk_mitigations(cylera_vulnerability_name)

                vuln = extract_vuln(vulnerability)
                vuln_def = extract_vuln_def(vulnerability, mitigations[vulnerability['vulnerability_name']])

                create_kdi_asset_vuln(asset, vuln)
                create_kdi_vuln_def(vuln_def)
              end
            else
              find_or_create_kdi_asset(asset)
            end
          end

          kdi_upload(@output_directory, "cylera_#{inventory_devices['page']}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)

          break if inventory_devices['devices'].count < @inventory_devices_params[:page_size]

          @inventory_devices_params[:page] += 1
        end

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::Toolkit::Cylera::Client::ApiError => e
        fail_task e.message
      end

      private

      def initialize_options
        @api_host = @options[:cylera_api_host]
        @api_user = @options[:cylera_api_user]
        @api_password = @options[:cylera_api_password]
        @inventory_devices_params = {
          ip_address: @options[:cylera_ip_address],
          mac_address: @options[:cylera_mac_address],
          first_seen_before: handle_time_delta(@options[:cylera_first_seen_before]),
          first_seen_after: handle_time_delta(@options[:cylera_first_seen_after]),
          last_seen_before: handle_time_delta(@options[:cylera_last_seen_before]),
          last_seen_after: handle_time_delta(@options[:cylera_last_seen_after]),
          vendor: @options[:cylera_vendor],
          type: @options[:cylera_type],
          model: @options[:cylera_model],
          class: @options[:cylera_class],
          page: @options[:cylera_page].to_i,
          page_size: @options[:cylera_page_size]
        }
        @risk_vulnerabilities_params = {
          confidence: @options[:cylera_confidence],
          detected_after: @options[:cylera_detected_after],
          mac_address: @options[:cylera_mac_address],
          name: @options[:cylera_name],
          severity: @options[:cylera_severity],
          status: @options[:cylera_status],
          page: 0,
          page_size: 100
        }
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @incremental = @options[:incremental]
        @skip_autoclose = true
        @retries = 3
        @kdi_version = 2
      end

      def extract_asset(device)
        {
          'ip_address' => device['ip_address'],
          'mac_address' => device['mac_address'],
          'os' => device['os'],
          'hostname' => device['hostname'],
          'external_id' => device['id'],
          'tags' => tags(device)
        }.compact
      end

      def extract_vuln(vulnerability)
        {
          'scanner_identifier' => vulnerability['vulnerability_name'],
          'scanner_type' => SCANNER_TYPE,
          'scanner_score' => SEVERITY_VALUES[vulnerability['severity']],
          'created_at' => Time.at(vulnerability['first_seen']),
          'last_seen_at' => Time.at(vulnerability['last_seen']),
          'status' => STATUS_VALUES[vulnerability['status']],
          'vuln_def_name' => vulnerability['vulnerability_name']
        }.compact
      end

      def extract_vuln_def(vulnerability, mitigations)
        {
          'scanner_type' => SCANNER_TYPE,
          'cve_identifiers' => cve_id(vulnerability['vulnerability_name']),
          'name' => vulnerability['vulnerability_name'],
          'solution' => remove_html_tags(solution(mitigations)),
          'description' => (remove_html_tags(mitigations['description']) if mitigations['description'])
        }.compact
      end

      def tags(device)
        tags = []
        tags.push("Vendor:#{device['vendor']}") if device['vendor']
        tags.push("Type:#{device['type']}") if device['type']
        tags.push("Model:#{device['model']}") if device['model']
        tags.push("Class:#{device['class']}") if device['class']
        tags.push("Location:#{device['location']}") if device['location']
        tags.push("FDA Class:#{device['fda_class']}") if device['fda_class'] and device['fda_class'] != ""
        tags.push("Serial Number:#{device['serial_number']}") if device['serial_number']
        tags.push("Version:#{device['version']}") if device['version']
        tags.push("VLAN:#{device['vlan']}") if device['vlan']
        tags.push("AETitle:#{device['aetitle']}") if device['aetitle']
        tags
      end

      def vulnerability_name(cylera_vulnerability_name)
        return cylera_vulnerability_name unless cve_id(cylera_vulnerability_name)

        parts = cylera_vulnerability_name.split('-')
        parts[2] = "000#{parts[2]}".last(4) if parts[2].length < 4
        parts.join('-')
      end

      def cve_id(vulnerability_name)
        vulnerability_name if vulnerability_name.start_with?(CVE_PREFIX)
      end

      def solution(mitigations)
        result = mitigations['mitigations'].map do |mitigation|
          "#{mitigation['name']} - #{mitigation['items'].pluck('description').join('; ')}"
        end
        if mitigations['additional_info'].present?
          result << 'Additional Info'
          result << mitigations['additional_info']
        end
        if mitigations['vendor_response'].present?
          result << 'Vendor Response'
          result << mitigations['vendor_response']
        end
        result.join("\n") if result.present?
      end

      def handle_time_delta(time)
        case time
        when nil
          time
        when /^\d+#{SECONDS}$/i
          Time.now.to_i - time.to_i
        when /^\d+$/
          time.to_i
        else
          raise "Invalid time value: #{time}. Only epoch timestamp and delta in seconds are supported."
        end
      end
    end
  end
end
