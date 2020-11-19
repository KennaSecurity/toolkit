require_relative 'lib/client'
require_relative 'lib/riskiq_helpers'

module Kenna
  module Toolkit
    class RiskIqTask < Kenna::Toolkit::BaseTask
      include Kenna::Toolkit::RiskIq::Helpers

      def self.metadata
        {
          id: "riskiq",
          name: "RiskIQ",
          maintainers: ["jcran"],
          description: "This task connects to the RiskIQ API and pulls results into the Kenna Platform.",
          options: [
            { name: "riskiq_api_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the RiskIQ key used to query the API." },
            { name: "riskiq_api_secret",
              type: "string",
              required: true,
              default: "",
              description: "This is the RiskIQ secret used to query the API." },
            { name: "riskiq_create_cves",
              type: "boolean",
              required: true,
              default: true,
              description: "Create vulns for CVEs" },
            { name: "riskiq_create_open_ports",
              type: "boolean",
              required: true,
              default: false,
              description: "Create vulns for RiskIQ Open Ports (beta!!)" },
            { name: "riskiq_limit_spurious_ports",
              type: "boolean",
              required: false,
              default: true,
              description: "Limit information for RiskIQ Open Ports (beta!!)" },
            { name: "riskiq_create_ssl_misconfigs",
              type: "boolean",
              required: true,
              default: false,
              description: "Create vulns for SSL Miconfigurations (beta!!)" },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.kennasecurity.com",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/riskiq",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(options)
        super

        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]

        riq_api_key = @options[:riskiq_api_key]
        riq_api_secret = @options[:riskiq_api_secret]

        @riq_create_cves = @options[:riskiq_create_cves]
        @riq_create_open_ports = @options[:riskiq_create_open_ports]
        @riq_limit_spurious_ports = @options[:riskiq_limit_spurious_ports]
        @riq_create_ssl_misconfigs = @options[:riskiq_create_ssl_misconfigs]

        # create an api client
        client = Kenna::Toolkit::RiskIq::Client.new(riq_api_key, riq_api_secret)

        unless client.successfully_authenticated?
          print_error "Unable to proceed, invalid key for RiskIQ?"
          return
        end
        print_good "Valid key, proceeding!"

        if @options[:debug]
          max_pages = 300
          print_debug "Limiting pages to #{max_pages}"
        else
          max_pages = -1 # all
        end

        if @riq_create_cves # 156219
          print_good "Getting CVEs from footprint"
          result = client.search_global_inventory(client.cve_footprint_query, max_pages)
          output = convert_riq_output_to_kdi result
        end

        if @riq_create_open_ports # 156220
          print_good "Getting open ports from footprint... BETA feature!"
          result = client.search_global_inventory(client.open_port_query, max_pages)
          output = convert_riq_output_to_kdi result
        end

        if @riq_create_ssl_misconfigs # 156221
          print_good "Getting ssl misconfigs from footprint... BETA feature!"
          result = client.search_global_inventory(client.ssl_cert_query, max_pages)
          output = convert_riq_output_to_kdi result
        end

        print_good "KDI Conversion complete!"

        ####
        # Write KDI format
        ####
        kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "riskiq-#{Time.now.utc.strftime('%s')}-#{rand(100_000)}.kdi.json"

        # actually write it
        write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        print_good "Output is available at: #{output_dir}/#{filename}"

        ####
        ### Finish by uploading if we're all configured
        ####
        return unless kenna_connector_id && kenna_api_host && kenna_api_key

        print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
        upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
      end
    end
  end
end
