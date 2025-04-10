# frozen_string_literal: true

require_relative "lib/synack_client"
module Kenna
  module Toolkit
    class SynackTask < Kenna::Toolkit::BaseTask
      SCANNER_TYPE = "Synack"
      DATE_FORMAT_KDI = '%Y-%m-%d-%H:%M:%S'

      def self.metadata
        {
          id: "synack",
          name: "Synack",
          description: "Pulls vulnerability data from Synack into Kenna.",
          options: [
            { name: "synack_api_host",
              type: "hostname",
              required: false,
              default: "api.synack.com",
              description: "Synack API hostname, usually api.synack.com" },
            { name: "synack_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Synack API token" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.kennasecurity.com",
              description: "Kenna API Hostname" },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "asset_defined_in_tag",
              type: "boolean",
              required: false,
              default: false,
              description: "If set to true, will only process Synack vulnerabilities tagged with special asset-defining tags." },
            { name: "page_size",
              type: "integer",
              required: false,
              default: 50,
              description: "Maximum number of vulnerabilities to retrieve per page from the Synack API." },
            { name: "kenna_batch_size",
              type: "integer",
              required: false,
              default: 1000,
              description: "Maximum number of vulnerabilities to upload to Kenna in each batch. Increasing this value could improve performance." },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/synack",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        initialize_options

        client = Kenna::Toolkit::Synack::SynackClient.new(@synack_api_host, @synack_api_token, @asset_defined_in_tag)

        print_good "Fetching vulns from Synack at #{@synack_api_host}"
        vulnerabilities = client.fetch_synack_vulnerabilities(page_size: @page_size)

        vulnerabilities.select! { |v| extract_kenna_tag(v) } if @asset_defined_in_tag
        print_good "Found #{vulnerabilities.length} total vulns for Kenna in Synack"

        kdi_batch_upload(@kenna_batch_size, @output_directory, 'synack.json', @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, @retries, @kdi_version) do |batch|
          vulnerabilities.each do |vulnerability|
            kenna_asset_tag = extract_kenna_tag(vulnerability)
            next if @asset_defined_in_tag && kenna_asset_tag.nil?

            vuln = extract_vulnerability(vulnerability)

            batch.append do
              if @asset_defined_in_tag
                # if by kenna tag
                asset_proxy = extract_asset_from_tag(kenna_asset_tag)
                create_kdi_asset_vuln(asset_proxy, vuln)
              else
                # if by exploitable locations
                vulnerability["exploitable_locations"].each do |exploitable_location|
                  asset_proxy = extract_asset_from_exploitable_location(exploitable_location, vulnerability["listing"])
                  create_kdi_asset_vuln(asset_proxy, vuln)
                end
              end

              create_kdi_vuln_def extract_vuln_def(vulnerability)
            end
          end
        end
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::Toolkit::Synack::SynackClient::ApiError => e
        fail_task e.message
      end

      private

      def initialize_options
        @synack_api_host = @options[:synack_api_host]
        @synack_api_token = @options[:synack_api_token]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @asset_defined_in_tag = @options[:asset_defined_in_tag]
        @output_directory = @options[:output_directory]
        @page_size = @options[:page_size].to_i
        @kenna_batch_size = @options[:kenna_batch_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def extract_vulnerability(vuln)
        created = vuln.fetch('resolved_at')
        created = DateTime.strptime(created, '%Y-%m-%dT%T%:z').strftime(DATE_FORMAT_KDI) unless created.nil? || created.empty?
        closed = vuln.fetch('closed_at')
        closed = DateTime.strptime(closed, '%Y-%m-%dT%T%:z').strftime(DATE_FORMAT_KDI) unless closed.nil? || closed.empty?
        kenna_status = vuln.dig('vulnerability_status', 'flow_type') == 2 ? 'closed' : 'open'

        {
          "scanner_identifier" => vuln.fetch('id').to_s,
          "scanner_type" => SCANNER_TYPE,
          "scanner_score" => vuln.fetch('cvss_final').to_i,
          "vuln_def_name" => vuln['title'],
          "status" => kenna_status,
          "created_at" => created,
          "closed_at" => closed
        }.compact
      end

      def extract_vuln_def(vuln)
        details = vuln.fetch('validation_steps').sort_by { |step| step['number'] }.map do |step|
          "#{step['number']}. #{step['detail']}\n#{step['url']}"
        end.join("\n")

        {
          "name" => vuln['title'],
          "scanner_identifier" => vuln.fetch('id').to_s,
          "scanner_type" => SCANNER_TYPE,
          "scanner_score" => vuln.fetch('cvss_final').to_i,
          "description" => vuln['description'],
          "solution" => vuln['recommended_fix'],
          "details" => details,
          "cve_identifiers" => vuln.fetch('cve_ids').join(","),
          "cwe_identifiers" => vuln.fetch('cwe_ids').join(",")
        }.compact
      end

      def extract_asset_from_tag(kenna_tag_in_synack)
        # supported kenna asset type values:
        #  file, ip_address, mac_address, hostname, ec2, netbios, url, fqdn, external_id, database, application
        kenna_asset_tag_value = kenna_tag_in_synack.fetch('name')

        tag_data = kenna_asset_tag_value.to_s.split('::')
        return nil if tag_data.nil? || tag_data.length != 3

        _, asset_type, asset_value = kenna_asset_tag_value.to_s.split('::')
        { asset_type => asset_value }
      end

      def extract_asset_from_exploitable_location(exploitable_location, assessment)
        url = nil
        file = nil
        ip_address = nil
        location_value = exploitable_location['value']
        location_address = exploitable_location['address']
        application_value = assessment.nil? ? '' : assessment['codename']

        case exploitable_location['type']
        when 'url'
          url = location_value
        when 'other', 'app-location'
          application_value = [application_value, location_value].compact.join(' ').strip
        when 'file'
          file = location_value
        when 'ip'
          ip_address = location_address
        end

        {
          "url" => url,
          "file" => file,
          "ip_address" => ip_address,
          "application" => application_value
        }.compact
      end

      def extract_kenna_tag(vulnerability)
        vulnerability.fetch('tag_list').find { |tag| tag.fetch('name').start_with?('kenna::') }
      end
    end
  end
end
