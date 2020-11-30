# frozen_string_literal: true

module Kenna
  module Toolkit
    module BitsightHelpers
      def get_bitsight_findings_and_create_kdi(bitsight_api_key, my_company_guid, max_findings = 1_000_000, options = {})
        # then get the assets for it
        # my_company = result["companies"].select{|x| x["guid"] == my_company_guid}
        more_findings = true
        offset = 0
        limit = 100

        while more_findings && (offset < max_findings)

          endpoint = "https://api.bitsighttech.com/ratings/v1/companies/#{my_company_guid}/findings?limit=#{limit}&offset=#{offset}"

          response = RestClient::Request.new(
            method: :get,
            url: endpoint,
            user: bitsight_api_key,
            password: "",
            headers: { accept: :json, content_type: :json }
          ).execute

          result = JSON.parse(response.body)

          # do the right thing with the findings here
          result["results"].each do |finding|
            _add_finding_to_working_kdi(finding, options)
          end

          # check for more
          endpoint = result["links"]["next"]
          more_findings = endpoint&.length&.positive?

          if more_findings && endpoint =~ /0.0.0.0/
            print_error "WARNING: endpoint is not well formed, doing a gsub on: #{endpoint}"
            endpoint.gsub!("https://0.0.0.0:8000/customer-api/", "https://api.bitsighttech.com/")
          end

          # bump the offset
          offset += limit

        end
      end

      def get_my_company(bitsight_api_key)
        # First get my company
        response = RestClient.get("https://#{bitsight_api_key}:@api.bitsighttech.com/portfolio")
        portfolio = JSON.parse(response.body)
        portfolio["my_company"]["guid"]
      end

      def valid_bitsight_api_key?(bitsight_api_key)
        endpoint = "https://api.bitsighttech.com/"
        begin
          response = RestClient::Request.new(
            method: :get,
            url: endpoint,
            user: bitsight_api_key,
            password: "",
            headers: { accept: :json, content_type: :json }
          ).execute
          result = JSON.parse(response.body)
          result.key? "disclaimer"
        rescue RestClient::Unauthorized => e
          false
        end
      end

      def get_bitsight_assets_for_company(bitsight_api_key, my_company_guid)
        # then get the assets for it
        # my_company = result["companies"].select{|x| x["guid"] == my_company_guid}
        endpoint = "https://api.bitsighttech.com/ratings/v1/companies/#{my_company_guid}/assets/statistics"
        response = RestClient::Request.new(
          method: :get,
          url: endpoint,
          user: bitsight_api_key,
          password: "",
          headers: { accept: :json, content_type: :json }
        ).execute
        result = JSON.parse(response.body)

        result["assets"].map { |x| x["asset"] }
      end

      private

      def _add_finding_to_working_kdi(finding, options)
        vuln_def_id = (finding["risk_vector_label"]).to_s.tr(" ", "_").tr("-", "_").downcase.strip
        print_debug "Working on finding of type: #{vuln_def_id}"

        # get the grades labled as benign... Default: GOOD
        benign_finding_grades = options[:benign_finding_grades]
        print_debug "Benign finding grades: #{benign_finding_grades}"

        finding["assets"].each do |a|
          asset_name = a["asset"]
          default_tags = ["Bitsight"]
          asset_category_tag = "bitsight_cat_#{a['category']}".downcase
          tags = default_tags.concat [asset_category_tag]

          asset_attributes = if a["is_ip"] # TODO: ... keep severity  ]
                               {
                                 "ip_address" => asset_name,
                                 "tags" => tags
                               }
                             else
                               {
                                 "hostname" => asset_name,
                                 "tags" => default_tags
                               }
                             end

          create_kdi_asset(asset_attributes)

          ####
          #### CVE CASE
          ####

          ###
          ### BUG BUG BUG
          ###

          ### CHECK OPEN PORTS AND LOOK OFOR VULNERABILITIEIS
          if vuln_def_id == "patching_cadence"

            # grab the CVE
            cve_id = finding["vulnerability_name"]

            if /^CVE-/i.match?(cve_id)
              create_cve_vuln(cve_id, finding, asset_attributes)
            else
              print_error "ERROR! Unknown vulnerability: #{cve_id}!"
              print_debug "#{finding}\n\n"
            end

          ####
          #### OPEN PORTS CAN HAVE BOTH!
          ####
          elsif vuln_def_id == "open_ports"

            # create the sensitive service first
            create_cwe_vuln(vuln_def_id, finding, asset_attributes)

            ###
            ### for each vuln on the service, create a cve
            ###
            finding["details"]["vulnerabilities"].each do |v|
              cve_id = v["name"]
              print_debug "Got CVE: #{cve_id}"
              print_error "ERROR! Unknown vulnerability!" unless /cve-/i.match?(cve_id)
              create_cve_vuln(cve_id, finding, asset_attributes)
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
              if options[:bitsight_create_benign_findings]
                # then create it
                create_cwe_vuln("benign_finding", finding, asset_attributes)
              else # otherwise skip!
                print "Skipping benign finding: #{vuln_def_id}"
              end

            else # we are probably a negative finding, just create it
              create_cwe_vuln(vuln_def_id, finding, asset_attributes)
            end

          else # no grade, so fall back to just creating
            create_cwe_vuln(vuln_def_id, finding, asset_attributes)

          end
        end
      end

      ###
      ### Helper to handle creating a cve vuln
      ###
      def create_cve_vuln(vuln_def_id, finding, asset_attributes)
        # then create each vuln for this asset
        vuln_attributes = {
          "scanner_identifier" => vuln_def_id,
          "scanner_type" => "Bitsight",
          "details" => JSON.pretty_generate(finding),
          "created_at" => finding["first_seen"],
          "last_seen_at" => finding["last_seen"],
          "status" => "open"
        }

        # set the port if it's available
        vuln_attributes["port"] = (finding["details"]["dest_port"]).to_s.to_i if finding["details"]

        # def create_kdi_asset_vuln(asset_id, asset_locator, args)
        create_kdi_asset_vuln(asset_attributes, vuln_attributes)

        vd = {
          "scanner_type" => "Bitsight",
          "scanner_identifier" => vuln_def_id.to_s,
          "cve_identifiers" => vuln_def_id.to_s
        }

        create_kdi_vuln_def(vd)
      end

      ###
      ### Helper to handle creating a cwe vuln
      ###
      def create_cwe_vuln(vuln_def_id, finding, asset_attributes)
        vd = {
          "scanner_identifier" => vuln_def_id.to_s
        }

        # get our mapped vuln
        fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper
        cvd = fm.get_canonical_vuln_details("Bitsight", vd)

        # then create each vuln for this asset
        vuln_attributes = {
          "scanner_identifier" => vuln_def_id.to_s,
          "scanner_type" => "Bitsight",
          "details" => JSON.pretty_generate(finding),
          "created_at" => finding["first_seen"],
          "last_seen_at" => finding["last_seen"],
          "status" => "open"
        }

        # set the port if it's available
        vuln_attributes["port"] = (finding["details"]["dest_port"]).to_s.to_i if finding["details"]

        ###
        ### Set Scores based on what was available in the CVD
        ###
        vuln_attributes["scanner_score"] = cvd["scanner_score"] if cvd["scanner_score"]

        vuln_attributes["override_score"] = cvd["override_score"] if cvd["override_score"]

        # def create_kdi_asset_vuln(asset_id, asset_locator, args)
        create_kdi_asset_vuln(asset_attributes, vuln_attributes)

        ###
        ### Put them through our mapper
        ###
        create_kdi_vuln_def(cvd)
      end
    end
  end
end
