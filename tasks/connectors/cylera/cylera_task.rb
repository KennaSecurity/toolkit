# frozen_string_literal: true

require_relative 'lib/client'

module Kenna
  module Toolkit
    class CyleraTask < Kenna::Toolkit::BaseTask
      CVE_PREFIX = 'CVE'
      NO_SOLUTION_TEXT = 'No solution provided by vendor'
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
              name: 'cylera_mac_address',
              type: 'string',
              required: false,
              default: nil,
              description: 'MAC address of device'
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

        client = Kenna::Toolkit::Cylera::Client.new(@api_host, @api_user, @api_password)

        risk_mitigations = {}

        loop do
          risk_vulnerabilities = client.get_risk_vulnerabilities(@risk_vulnerabilities_params)

          risk_vulnerabilities['vulnerabilities'].each do |vulnerability|
            cylera_vulnerability_name = vulnerability['vulnerability_name']
            vulnerability['vulnerability_name'] = vulnerability_name(cylera_vulnerability_name)
            risk_mitigations[vulnerability['vulnerability_name']] ||= client.get_risk_mitigations(cylera_vulnerability_name)['mitigations']

            asset = extract_asset(vulnerability)
            vuln = extract_vuln(vulnerability)
            vuln_def = extract_vuln_def(vulnerability, risk_mitigations[vulnerability['vulnerability_name']])

            create_kdi_asset_vuln(asset, vuln)
            create_kdi_vuln_def(vuln_def)
          end

          kdi_upload(@output_directory, "cylera_#{risk_vulnerabilities['page']}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)

          break if risk_vulnerabilities['vulnerabilities'].count < @risk_vulnerabilities_params[:page_size]

          @risk_vulnerabilities_params[:page] += 1
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
        @risk_vulnerabilities_params = {
          confidence: @options[:cylera_confidence],
          detected_after: @options[:cylera_detected_after],
          mac_address: @options[:cylera_mac_address],
          name: @options[:cylera_name],
          severity: @options[:cylera_severity],
          status: @options[:cylera_status],
          page: @options[:cylera_page].to_i,
          page_size: @options[:cylera_page_size]
        }
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def extract_asset(vulnerability)
        {
          'ip_address' => vulnerability['ip_address'],
          'mac_address' => vulnerability['mac_address'],
          'tags' => tags(vulnerability)
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
          'solution' => remove_html_tags(solution(mitigations))
        }.compact
      end

      def tags(vulnerability)
        tags = []
        tags.push("Vendor:#{vulnerability['vendor']}") if vulnerability['vendor']
        tags.push("Type:#{vulnerability['type']}") if vulnerability['type']
        tags.push("Model:#{vulnerability['model']}") if vulnerability['model']
        tags.push("Class:#{vulnerability['class']}") if vulnerability['class']
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
        return NO_SOLUTION_TEXT if mitigations.empty?

        mitigations.map do |mitigation|
          "#{mitigation['name']} - #{mitigation['items'].pluck('description').join('; ')}"
        end.join("\n")
      end
    end
  end
end
