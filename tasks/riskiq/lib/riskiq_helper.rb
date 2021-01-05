# frozen_string_literal: true

module Kenna
  module Toolkit
    module RiskIQHelper
      @api_url = nil
      @pull_incremental = nil
      @uploaded_files = nil
      @kenna_connector_id = nil
      @kenna_api_host = nil
      @kenna_api_key = nil
      @output_directory = nil
      @headers = nil
      @incremental_time = nil
      @port_last_seen = nil

      def set_client_data(api_key, api_secret, kenna_connector_id, kenna_api_host, kenna_api_key, output_directory, incremental_time, pull_incremental, port_last_seen)
        @api_url = "https://api.riskiq.net/v1/"
        @pull_incremental = pull_incremental
        @kenna_connector_id = kenna_connector_id
        @kenna_api_host = kenna_api_host
        @kenna_api_key = kenna_api_key
        @output_directory = output_directory
        @uploaded_files = []
        @incremental_time = incremental_time
        @port_last_seen = port_last_seen

        raise "Bad key?" unless api_key && api_secret

        creds = "#{api_key}:#{api_secret}"
        token = Base64.strict_encode64(creds)
        @headers = {
          "Authorization" => "Basic #{token}",
          "Content-Type" => "application/json"
        }
      end

      def connector_kickoff
        ### Finish by uploading if we're all configured
        return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key && @uploaded_files.size.positive?

        print_good "Attempting to run to Kenna Connector at #{@kenna_api_host}"
        run_files_on_kenna_connector(@kenna_connector_id, @kenna_api_host, @kenna_api_key, @uploaded_files)
      end

      ##
      def ssl_cert_query
        query_string = ""
        query_string += "{"
        query_string << "  \"filters\": {"
        query_string << "  \"condition\": \"AND\","
        query_string << "   \"value\": ["
        query_string << "      {"
        query_string << "        \"name\": \"type\","
        query_string << "        \"operator\": \"EQ\","
        query_string << "        \"value\": \"SSL_CERT\""
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"state\","
        query_string << "        \"operator\": \"IN\","
        query_string << "        \"value\": [\"Approved Inventory\", \"Candidate\"] "
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"selfSigned\","
        query_string << "        \"operator\": \"EQ\","
        query_string << "        \"value\": true"
        query_string << "      }"
        if @pull_incremental
          query_string << ",{"
          query_string << "    \"name\": \"updatedAt\","
          query_string << "    \"operator\": \"GTE\","
          query_string << "    \"value\": \"#{@incremental_time}\""
          query_string << "  }"
        end
        query_string << "]}}"
      end

      ##
      def open_port_query
        query_string = ""
        query_string += "{"
        query_string << "  \"filters\": {"
        query_string << "  \"condition\": \"AND\","
        query_string << "   \"value\": ["
        query_string << "      {"
        query_string << "        \"name\": \"type\","
        query_string << "        \"operator\": \"EQ\","
        query_string << "        \"value\": \"IP_ADDRESS\""
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"state\","
        query_string << "        \"operator\": \"IN\","
        query_string << "        \"value\": [\"Approved Inventory\", \"Candidate\"] "
        query_string << "      }"
        unless @port_last_seen.nil?
          query_string << ",{"
          query_string << "    \"name\": \"portLastSeen\","
          query_string << "    \"operator\": \"EQ\","
          query_string << "    \"value\": \"#{@port_last_seen}\""
          query_string << "  }"
        end
        if @pull_incremental
          query_string << ",{"
          query_string << "    \"name\": \"updatedAt\","
          query_string << "    \"operator\": \"GTE\","
          query_string << "    \"value\": \"#{@incremental_time}\""
          query_string << "  }"
        end
        query_string << "]}}"
      end

      def cve_footprint_query
        query_string = ""
        query_string += "{"
        query_string << "  \"filters\": {"
        query_string << "  \"condition\": \"AND\","
        query_string << "   \"value\": ["
        query_string << "      {"
        query_string << "        \"name\": \"type\","
        query_string << "        \"operator\": \"EQ\","
        query_string << "        \"value\": \"PAGE\""
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"state\","
        query_string << "        \"operator\": \"IN\","
        query_string << "        \"value\": [\"Approved Inventory\", \"Candidate\"] "
        query_string << "      },"
        query_string << "      {"
        query_string << "        \"name\": \"cvssScore\","
        query_string << "        \"operator\": \"NOT_NULL\","
        query_string << "        \"value\": true"
        query_string << "      }"
        if @pull_incremental
          query_string << ",{"
          query_string << "    \"name\": \"updatedAt\","
          query_string << "    \"operator\": \"GTE\","
          query_string << "    \"value\": \"#{@incremental_time}\""
          query_string << "  }"
        end
        query_string << "]}}"
      end

      def search_global_inventory(query, batch_page_size)
        # start with sensible defaults
        current_page = 0
        asset_count = 0
        max_pages = -1
        out = []
        current_asset = ""
        puts query
        while current_page <= max_pages || max_pages == -1
          puts "DEBUG Getting page: #{current_page} / #{max_pages}"

          endpoint = "#{@api_url}globalinventory/search?page=#{current_page}&size=100&recent=true"

          response = http_post(endpoint, @headers, query)

          break if response.nil?

          begin
            result = JSON.parse(response.body)
          rescue JSON::ParserError => e
            puts "Error parsing json! #{e}"
          end

          # prepare the next request
          max_pages = result["totalPages"].to_i - 1 if max_pages == -1

          rows = result["content"]
          if rows.size.positive?
            rows.lazy.each do |item|
              if item["uuid"] != current_asset
                if asset_count == batch_page_size
                  convert_riq_output_to_kdi(out)

                  output_dir = "#{$basedir}/#{@output_directory}"
                  filename = "riskiq-#{Time.now.utc.strftime('%s')}-#{rand(100_000)}.kdi.json"

                  # actually write it
                  if @paged_assets.size.positive?
                    write_file_stream output_dir, filename, false, @paged_assets, @vuln_defs
                    print_good "Output is available at: #{output_dir}/#{filename}"
                    break unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

                    print_good "Attempting to upload to Kenna API at #{@kenna_api_host}"
                    response_json = upload_file_to_kenna_connector @kenna_connector_id, @kenna_api_host, @kenna_api_key, "#{output_dir}/#{filename}", false
                    filenum = response_json.fetch("data_file")
                    @uploaded_files << filenum
                    print_good "Success!" if !response_json.nil? && response_json.fetch("success")
                  end
                  asset_count = 0
                  clear_data_arrays
                  out = []
                end
                current_asset = item["uuid"]
                asset_count += 1
              end
              out << item
            end
          end
          current_page += 1
          result = nil
          response = nil
        end
        if out.size.positive?
          convert_riq_output_to_kdi(out)

          output_dir = "#{$basedir}/#{@output_directory}"
          filename = "riskiq-#{Time.now.utc.strftime('%s')}-#{rand(100_000)}.kdi.json"

          # actually write it
          if @paged_assets.size.positive?
            write_file_stream output_dir, filename, false, @paged_assets, @vuln_defs
            print_good "Output is available at: #{output_dir}/#{filename}"

            return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

            print_good "Attempting to upload to Kenna API at #{@kenna_api_host}"
            response_json = upload_file_to_kenna_connector @kenna_connector_id, @kenna_api_host, @kenna_api_key, "#{output_dir}/#{filename}", false
            filenum = response_json.fetch("data_file")
            @uploaded_files << filenum
            print_good "Success!" if !response_json.nil? && response_json.fetch("success")
          end
        end
        asset_count = 0
        clear_data_arrays
        out = []
      end

      def create_self_signed_cert_vuln(asset, cert, _first_seen, _last_seen)
        vuln = {
          "scanner_identifier" => "self_signed_certificate",
          "scanner_type" => "RiskIQ",
          "details" => JSON.pretty_generate(cert),
          # "first_seen" => first_seen,
          # "last_seen" => last_seen,
          "status" => "open"
        }

        vd = {
          "scanner_identifier" => "self_signed_certificate",
          "scanner_type" => "RiskIQ"
        }

        create_paged_kdi_asset_vuln(asset, vuln, "hostname")

        vuln_def = @fm.get_canonical_vuln_details("RiskIQ", vd)
        create_kdi_vuln_def(vuln_def)
      end

      def create_open_port_vuln(asset, service, _first_seen, _last_seen)
        port_number = service["port"] if service.is_a? Hash
        port_number = port_number.to_i

        ###
        ### handle http ports differently ... todo, standardize this
        ###
        scanner_identifier = if [80, 443, 8080].include?(port_number)
                               "http_open_port"
                             else
                               "other_open_port"
                             end

        vuln = {
          "scanner_identifier" => scanner_identifier,
          "scanner_type" => "RiskIQ",
          "details" => JSON.pretty_generate(service.except("banners", "webComponents", "scanMetadata")),
          "port" => port_number,
          # "first_seen" => first_seen,
          # "last_seen" => last_seen,
          "status" => "open"
        }

        # puts "Creating assetn+vuln:\n#{asset}\n#{vuln}\n"
        if asset["ip_address"]
          create_paged_kdi_asset_vuln(asset, vuln, "ip_address")
        else
          create_paged_kdi_asset_vuln(asset, vuln)
        end

        vd = {
          "scanner_identifier" => scanner_identifier,
          "scanner_type" => "RiskIQ"
        }

        vuln_def = @fm.get_canonical_vuln_details("RiskIQ", vd)
        create_kdi_vuln_def(vuln_def)
      end

      def convert_riq_output_to_kdi(data_items)
        output = []

        # just return empty array if we weren't handed anything
        return output unless data_items

        # kdi_initialize

        @fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper

        print_debug "Working on on #{data_items.count} items"
        data_items.lazy.each do |item|
          ###
          ### First handle dates (same across all assets)
          ###
          first_seen = Time.now.utc
          last_seen = Time.now.utc

          # if item["lastSeen"]
          #   last_seen = Date.iso8601("#{item["lastSeen"]}")
          # else
          #   last_seen = Date.iso8601("#{item["createdAt"]}","%s").to_s
          # end

          # if item["firstSeen"]
          #   first_seen = Date.iso8601("#{item["firstSeen"]}","%s").to_s
          # else
          #   first_seen = Date.iso8601("#{item["createdAt"]}","%s").to_s
          # end

          ###
          ### First handle tags (same across all assets)
          ###
          tags = ["RiskIQ"]
          tags.concat(item["tags"].map { |x| x["name"] }) if item["tags"]

          ###
          ### Always set External ID
          ###
          id = item["id"]

          ###
          ### Handle Assets by type
          ###
          case item["type"]
          when "HOST", "PAGE"

            # Hostname
            begin
              hostname = URI.parse(item["name"]).hostname
              hostname = item["hosts"].first if !hostname && item["hosts"] && !item["hosts"].empty?
              hostname ||= item["name"]
            rescue URI::InvalidURIError
              hostname = nil
            end

            # get ip address
            if item["asset"] && (item["asset"]["ipAddress"] || item["asset"]["ipAddresses"]&.first)
              # TODO: - we should pull all ip addresses when we can support it in KDI
              ip_address = item["asset"]["ipAddresses"].first["value"]
              ip_address ||= item["asset"]["ipAddress"]
            end

            # create base asset, then optional identifiers
            asset = {
              # "first_seen" => "#{first_seen}",
              # "last_seen" => "#{last_seen}",
              "tags" => tags
            }
            asset["external_id"] = id.to_s if id
            asset["hostname"] = hostname.to_s if hostname
            asset["ip_address"] = ip_address.to_s if ip_address

            print_error "UKNOWN item: #{item}" if hostname.to_s.empty? && ip_address.to_s.empty? && id.to_s.empty?

          when "IP_ADDRESS"

            asset = {
              "ip_address" => (item["name"]).to_s,
              # "first_seen" => "#{first_seen}",
              # "last_seen" => "#{last_seen}",
              "tags" => tags
            }
            asset["external_id"] = id.to_s if id

          when "SSL_CERT"

            # grab the sha
            sha_name = item["name"]

            # grab a hostname
            hostname = item["asset"]["subjectAlternativeNames"].first if item["asset"] && item["asset"]["subjectAlternativeNames"]
            hostname = item["asset"]["subject"]["common_name"] if item["asset"] && item["asset"]["subject"] && !hostname
            hostname = item["asset"]["issuer"]["common_name"] if item["asset"] && item["asset"]["issuer"] && !hostname
            hostname ||= "unknown host, unable to get from the certificate"

            asset = {
              "hostname" => hostname.to_s,
              "external_id" => sha_name.to_s,
              # "first_seen" => "#{first_seen}",
              # "last_seen" => "#{last_seen}",
              "tags" => tags
            }
            asset["external_id"] = id.to_s if id
            #  ... only create the asset if we have a self-signed cert
            create_self_signed_cert_vuln(asset, item, first_seen, last_seen) if item["asset"]["selfSigned"]
          else
            raise "Unknown / unmapped type: #{item['type']} #{item}"
          end

          ###
          ### Get the open port out of services
          ###
          if @riq_create_open_ports && item["asset"]["services"]
            (item["asset"]["services"] || []).uniq.lazy.each do |serv|
              create_open_port_vuln(asset, serv, first_seen, last_seen)
            end
          end

          ###
          ### Get the CVES out of web components
          ###
          next unless @riq_create_cves

          next unless item["asset"]["webComponents"]

          (item["asset"]["webComponents"] || []).lazy.each do |wc|
            # default to derived if no port specified
            derived_port = (item["asset"]["service"]).to_s.split(":").last

            # if you want to create open ports, we need to infer the port from the service
            # in addition to whatever else we've gotten
            (wc["ports"] << derived_port).uniq.compact.lazy.each do |port|
              port = port["port"] if port.is_a? Hash

              # if you want to create open ports
              (wc["cves"] || []).uniq.lazy.each do |cve|
                vuln = {
                  "scanner_identifier" => (cve["name"]).to_s,
                  "scanner_type" => "RiskIQ",
                  "port" => port.to_i,
                  # "first_seen" => first_seen,
                  # "last_seen" => last_seen,
                  "status" => "open"
                }

                vuln_def = {
                  "scanner_identifier" => (cve["name"]).to_s,
                  "scanner_type" => "RiskIQ",
                  "cve_identifiers" => (cve["name"]).to_s
                }

                create_paged_kdi_asset_vuln(asset, vuln)

                # vd = fm.get_canonical_vuln_details("RiskIQ", vuln_def)
                create_kdi_vuln_def(vuln_def)
              end
            end
          end
        end
      end
    end
  end
end
