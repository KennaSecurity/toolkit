# frozen_string_literal: true

module Kenna
  module Toolkit
    module BitsightHelpers
      @headers = nil
      @bitsight_api_key = nil
      @company_guid = nil

      def globals(bitsight_api_key)
        @headers = {
          "Authorization" => "Basic #{Base64.strict_encode64(bitsight_api_key)}",
          "accept" => :json,
          "content_type" => :json
        }
        @bitsight_api_key = bitsight_api_key
        my_company
      end

      def bitsight_findings_and_create_kdi(bitsight_create_benign_findings, bitsight_benign_finding_grades)
        limit = 100
        page_count = 0
        from_date = (DateTime.now - 90).strftime("%Y-%m-%d")
        endpoint = "https://api.bitsighttech.com/ratings/v1/companies/#{@company_guid}/findings?limit=#{limit}&last_seen_gte=#{from_date}"

        while endpoint
          response = http_get(endpoint, @headers)
          result = JSON.parse(response.body)

          # do the right thing with the findings here
          result["results"].lazy.each do |finding|
            add_finding_to_working_kdi(finding, bitsight_create_benign_findings, bitsight_benign_finding_grades)
          end

          # check for more
          endpoint = result["links"]["next"]

          if page_count > 10
            filename = "bitsight_kdi#{Time.now.strftime('%Y%m%dT%H%M')}.json"
            kdi_upload @output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
            page_count = 0
          end
          page_count += 1
        end
        filename = "bitsight_kdi#{Time.now.strftime('%Y%m%dT%H%M')}.json"
        kdi_upload @output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
      end

      def my_company
        # First get my company
        response = http_get("https://#{@bitsight_api_key}:@api.bitsighttech.com/portfolio", { accept: :json, content_type: :json })
        portfolio = JSON.parse(response.body)
        @company_guid = portfolio["my_company"]["guid"]
      end

      def valid_bitsight_api_key?
        endpoint = "https://api.bitsighttech.com/"

        response = http_get(endpoint, @headers)

        result = JSON.parse(response.body)
        result.key? "disclaimer"
      end

      private

      def add_finding_to_working_kdi(finding, create_benign_findings, benign_finding_grades)
        scanner_id = finding["risk_vector_label"]
        vuln_def_id = (finding["risk_vector_label"]).to_s.tr(" ", "_").tr("-", "_").downcase.strip
        print_debug "Working on finding of type: #{vuln_def_id}"

        return if create_benign_findings && finding["details"] && finding["details"]["grade"] && benign_finding_grades.include?(finding["details"]["grade"])

        # get the grades labled as benign... Default: GOOD

        finding["assets"].each do |a|
          asset_name = a["asset"]
          default_tags = ["Bitsight"]
          # default_tags.concat ["bitsight_cat_#{a['category']}".downcase]
          asset_attributes = if a["is_ip"] # TODO: ... keep severity  ]
                               {
                                 "ip_address" => asset_name,
                                 "tags" => default_tags
                               }
                             else
                               {
                                 "hostname" => asset_name,
                                 "tags" => default_tags
                               }
                             end

          ### CHECK OPEN PORTS AND LOOK OFOR VULNERABILITIEIS
          if vuln_def_id == "patching_cadence"

            # grab the CVE
            cve_id = finding["vulnerability_name"]
            cve_id ||= finding["details"]["vulnerability_name"] if finding["details"].key?("vulnerability_name")

            if /^CVE-/i.match?(cve_id)
              create_cve_vuln(cve_id, scanner_id, finding, asset_attributes)
            else
              print_error "ERROR! Unknown vulnerability: #{cve_id}!"
              print_debug "#{finding}\n\n"
            end

          ####
          #### OPEN PORTS CAN HAVE BOTH!
          ####
          elsif vuln_def_id == "open_ports"

            # create the sensitive service first
            create_cwe_vuln(vuln_def_id, scanner_id, finding, asset_attributes)

            ###
            ### for each vuln on the service, create a cve
            ###
            finding["details"]["vulnerabilities"].each do |v|
              cve_id = v["name"]
              print_debug "Got CVE: #{cve_id}"
              print_error "ERROR! Unknown vulnerability!" unless /^CVE-/i.match?(cve_id)
              create_cve_vuln(cve_id, scanner_id, finding, asset_attributes)
            end

          ####
          #### NON-CVE CASE, just create the normal finding
          ####
          elsif finding["details"] && finding["details"]["grade"]

            ###
            ### Bitsight sometimes gives us stuff graded positively.
            ### check the options to determine what to do here.
            ###
            print_debug "Got finding #{vuln_def_id} with grade: #{finding['details']['grade']}"

            # if it is labeled as one of our types
            if benign_finding_grades.include?(finding["details"]["grade"])

              print_debug "Adjusting to benign finding due to grade: #{vuln_def_id}"

              # AND we're allowed to create
              if create_benign_findings
                # then create it
                create_cwe_vuln("benign_finding", scanner_id, finding, asset_attributes)
              else # otherwise skip!
                print_debug "Skipping benign finding: #{vuln_def_id}"
              end

            else # we are probably a negative finding, just create it
              create_cwe_vuln(vuln_def_id, scanner_id, finding, asset_attributes)
            end

          else # no grade, so fall back to just creating
            create_cwe_vuln(vuln_def_id, scanner_id, finding, asset_attributes)

          end
        end
      end

      ###
      ### Helper to handle creating a cve vuln
      ###
      def create_cve_vuln(vuln_def_id, scanner_id, finding, asset_attributes)
        # then create each vuln for this asset

        vuln_attributes = {
          "scanner_identifier" => scanner_id,
          "vuln_def_name" => vuln_def_id.upcase,
          "scanner_type" => "Bitsight",
          "details" => JSON.pretty_generate(finding),
          "created_at" => finding["first_seen"],
          "last_seen_at" => finding["last_seen"]
        }

        # set the port if it's available
        vuln_attributes["port"] = (finding["details"]["dest_port"]).to_s.to_i if finding["details"] && finding["details"]["dest_port"].to_s.to_i.positive?

        # def create_kdi_asset_vuln(asset_id, asset_locator, args)
        create_kdi_asset_vuln(asset_attributes, vuln_attributes)

        vd = {
          "scanner_type" => "Bitsight"
        }

        vd["cve_identifiers"] = vuln_def_id.upcase if /^CVE-/i.match?(vuln_def_id)
        vd["name"] = vuln_def_id.upcase
        # vd["scanner_identifier"] = vuln_def_id
        create_kdi_vuln_def(vd)
      end

      ###
      ### Helper to handle creating a cwe vuln
      ###
      def create_cwe_vuln(vuln_def_id, scanner_id, finding, asset_attributes)
        # set the port if it's available
        port_number = (finding["details"]["dest_port"]).to_s.to_i if finding["details"] && finding["details"]["dest_port"].to_s.to_i.positive?

        # puts finding["details"]["diligence_annotations"]["message"] if finding["details"].key?("diligence_annotations") && finding["details"]["diligence_annotations"].key?("message") && finding["details"]["diligence_annotations"].fetch("message").match?(/^Detected service: /im)
        detected_service = finding["details"]["diligence_annotations"].fetch("message").sub(/^Detected service: /im, "") if finding["details"].key?("diligence_annotations") && finding["details"]["diligence_annotations"].key?("message")
        scanner_identifier = if vuln_def_id == "open_ports" && !port_number.nil?
                               if %w[HTTP HTTPS].include?(detected_service) || [80, 443, 8080, 8443].include?(port_number)
                                 "http_open_port"
                               elsif [3306, 5432, 6379, 9200, 9300].include?(port_number)
                                 "database_server_detected"
                               elsif %w[Telnet SMTP].include?(detected_service) || [23, 25, 135, 136, 137, 138, 139, 445, 465, 587, 2323, 3389, 9002].include?(port_number)
                                 "trusted_open_port"
                               elsif [111].include?(port_number)
                                 "trusted_open_service"
                               elsif [1723].include?(port_number)
                                 "deprecated_protocol"
                               elsif [5800, 5900].include?(port_number)
                                 "infrastructure_exposure"
                               elsif %w[SIP].include?(detected_service) || [161, 1900, 5060, 5061, 5222, 5269, 5353].include?(port_number)
                                 "internal_network_exposure"
                               elsif %w[BGP DNS].include?(detected_service) || [22, 53, 110, 179].include?(port_number)
                                 "potential_trusted_protocol"
                               elsif [21].include?(port_number)
                                 "unecrypted_login"
                               elsif [1433, 1434].include?(port_number)
                                 "database_service_exposure"
                               elsif [112_11].include?(port_number)
                                 "sensitive_data_exposure"
                               elsif [22, 873].include?(port_number)
                                 "trusted_open_utility"
                               elsif [554].include?(port_number)
                                 "transmission_exposure"
                               elsif [179].include?(port_number)
                                 "network_misconfig"
                               elsif %w[XNPP NTP ISAKMP].include?(detected_service) || [123, 5222].include?(port_number)
                                 "non_sensitive_open_port"
                               elsif !detected_service.nil? && !detected_service.match?(/^HTTP/im)
                                 "#{detected_service}_open_port"
                               else
                                 "other_open_port"
                               end
                             else
                               vuln_def_id.to_s
                             end
        vd = {
          "scanner_identifier" => scanner_identifier
        }

        # get our mapped vuln
        fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper.new(@output_dir)
        cvd = fm.get_canonical_vuln_details("Bitsight", vd)

        # then create each vuln for this asset
        vuln_attributes = {
          "scanner_identifier" => scanner_id,
          "scanner_type" => "Bitsight",
          "details" => JSON.pretty_generate(finding),
          "created_at" => finding["first_seen"],
          "last_seen_at" => finding["last_seen"]
        }

        vuln_attributes["port"] = port_number unless port_number.nil?
        ###
        ### Set Scores based on what was available in the CVD
        ###
        vuln_attributes["vuln_def_name"] = cvd["name"] if cvd["name"]
        vuln_attributes["scanner_score"] = cvd["scanner_score"] if cvd["scanner_score"]
        vuln_attributes["override_score"] = cvd["override_score"] if cvd["override_score"]
        vuln_attributes.compact!
        create_kdi_asset_vuln(asset_attributes, vuln_attributes)

        ###
        ### Put them through our mapper
        ###
        cvd.tap { |hs| hs.delete("scanner_identifier") }
        create_kdi_vuln_def(cvd)
      end
    end
  end
end
