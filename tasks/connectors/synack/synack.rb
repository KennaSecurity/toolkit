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
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Maximum number of issues to retrieve in batches." },
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

        print_good "Attempting to fetch vulns from Synack at #{@synack_api_host}"
        synack_vulnerabilities = client.fetch_synack_vulnerabilities
        print_good "Found #{synack_vulnerabilities.length} total vulns in Synack"

        vulns_for_kenna = synack_vulnerabilities
        if @asset_defined_in_tag
          vulns_for_kenna = synack_vulnerabilities.select do |vulnerability|
            tags = vulnerability.fetch('tag_list')
            tags.select { |tag| tag.fetch('name').start_with?('kenna::') }.length.positive?
          end
        end
        print_good "Found #{vulns_for_kenna.length} total vulns for Kenna in Synack"

        vulns_in_batch = 0
        batch_number = 1
        vulns_for_kenna.each do |synack_vulnerability|

          tags = synack_vulnerability.fetch('tag_list')
          kenna_asset_tag = tags.find { |tag| tag.fetch('name').start_with?('kenna::') }
          next if @asset_defined_in_tag && kenna_asset_tag.nil?

          asset_vuln_proxy = create_asset_vuln_proxy(synack_vulnerability)
          vuln_def_proxy = create_vuln_def_proxy(synack_vulnerability)

          if @asset_defined_in_tag
            # if by kenna tag
            asset_proxy = create_asset_proxy_from_tag(kenna_asset_tag)
            create_kdi_asset_vuln(asset_proxy, asset_vuln_proxy)
          else
            # if by exploitable locations
            synack_vulnerability["exploitable_locations"].each do |exploitable_location|
              asset_proxy = create_asset_proxy_from_exploitable_location(exploitable_location, synack_vulnerability["listing"])
              create_kdi_asset_vuln(asset_proxy, asset_vuln_proxy)
            end
          end

          create_kdi_vuln_def vuln_def_proxy
          vulns_in_batch += 1
          if vulns_in_batch >= @batch_size
            filename = "synack-#{batch_number}.json"
            kdi_upload(@output_directory, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, @retries, @kdi_version)
            batch_number += 1
            vulns_in_batch = 0
          end
        end
        if vulns_in_batch.positive?
          filename = "synack-#{batch_number}.json"
          kdi_upload(@output_directory, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, @retries, @kdi_version)
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
        @batch_size = @options[:batch_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def create_asset_vuln_proxy(synack_vulnerability)
        scanner_id = synack_vulnerability.fetch('id')
        vuln_name = synack_vulnerability.fetch('title')
        scanner_score = synack_vulnerability.fetch('cvss_final')

        vuln_status_info = synack_vulnerability['vulnerability_status']

        created = synack_vulnerability.fetch('resolved_at')
        created = DateTime.strptime(created, '%Y-%m-%dT%T%:z').strftime(DATE_FORMAT_KDI) unless created.nil? || created.empty?
        closed = synack_vulnerability.fetch('closed_at')
        closed = DateTime.strptime(closed, '%Y-%m-%dT%T%:z').strftime(DATE_FORMAT_KDI) unless closed.nil? || closed.empty?
        synack_status_type = vuln_status_info.fetch('flow_type')
        kenna_status = synack_status_type == 2 ? 'closed' : 'open'

        {
          "scanner_identifier" => scanner_id.to_s,
          "scanner_type" => "Synack",
          "scanner_score" => scanner_score.to_i,
          "vuln_def_name" => vuln_name,
          "status" => kenna_status,
          "created_at" => created,
          "closed_at" => closed
        }.compact
      end

      def create_vuln_def_proxy(synack_vulnerability)
        scanner_id = synack_vulnerability.fetch('id')
        vuln_name = synack_vulnerability.fetch('title')
        description = synack_vulnerability.fetch('description')
        solution = synack_vulnerability.fetch('recommended_fix')
        scanner_score = synack_vulnerability.fetch('cvss_final')
        validation_steps = synack_vulnerability.fetch('validation_steps')

        details = []
        validation_steps.each do |step|
          number = step.fetch('number')
          detail = step.fetch('detail')
          detail_url = step.fetch('url')
          details << "#{number}. #{detail} \n #{detail_url} \n"
        end

        details = details.sort
        details = details.join('')

        cve_ids = synack_vulnerability.fetch('cve_ids')
        cve_identifiers = cve_ids.join(",") unless cve_ids.empty?
        cwe_ids = synack_vulnerability.fetch('cwe_ids')
        cwe_identifiers = cwe_ids.join(",") unless cwe_ids.empty?

        {
          "name" => vuln_name,
          "scanner_identifier" => scanner_id.to_s,
          "scanner_type" => "Synack",
          "scanner_score" => scanner_score.to_i,
          "description" => description,
          "solution" => solution,
          "details" => details,
          "cve_identifiers" => cve_identifiers,
          "cwe_identifiers" => cwe_identifiers
        }.compact
      end

      def create_asset_proxy_from_tag(kenna_tag_in_synack)
        # supported kenna asset type values:
        #  file, ip_address, mac_address, hostname, ec2, netbios, url, fqdn, external_id, database, application
        kenna_asset_tag_value = kenna_tag_in_synack.fetch('name')

        tag_data = kenna_asset_tag_value.to_s.split('::')
        return nil if tag_data.nil? || tag_data.length != 3

        asset_type = kenna_asset_tag_value.to_s.split('::')[1]
        asset_value = kenna_asset_tag_value.to_s.split('::')[2]
        asset = {
          asset_type => asset_value
        }
        asset.compact
      end

      def create_asset_proxy_from_exploitable_location(exploitable_location, assessment)

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
          application_value = location_value.nil? ? application_value : "#{application_value} #{location_value}".strip
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

    end
  end
end
