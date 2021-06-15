# frozen_string_literal: true

require "httparty"
require_relative "../../../../lib/kdi/kdi_helpers"

module Kenna
  module Toolkit
    module VeracodeAV
      class Client
        include HTTParty
        include KdiHelpers

        APP_PATH = "/appsec/v1/applications"
        CAT_PATH = "/appsec/v1/categories"
        CWE_PATH = "/appsec/v1/cwes"
        FINDING_PATH = "/appsec/v2/applications"
        HOST = "api.veracode.com"
        REQUEST_VERSION = "vcode_request_version_1"

        def initialize(id, key, output_dir, filename, kenna_api_host, kenna_connector_id, kenna_api_key)
          @id = id
          @key = key
          @output_dir = output_dir
          @filename = filename
          @kenna_api_host = kenna_api_host
          @kenna_connector_id = kenna_connector_id
          @kenna_api_key = kenna_api_key
          @category_recommendations = []
          @cwe_recommendations = []
        end

        def applications(page_size)
          app_request = "#{APP_PATH}?size=#{page_size}"
          url = "https://#{HOST}#{app_request}"
          app_list = []
          until url.nil?
            uri = URI.parse(url)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(url, hmac_auth_options(auth_path))
            result = JSON.parse(response.body)
            applications = result["_embedded"]["applications"]

            applications.lazy.each do |application|
              # grab tags
              tag_list = []
              application["profile"]["tags"]&.split(",")&.each { |t| tag_list.push(t) } # if application["profile"]["tags"]
              tag_list.push("veracode_bu: #{application['profile']['business_unit']['name']}") if application["profile"]["business_unit"]["name"]
              tag_list.push("veracode_bc: #{application['profile']['business_criticality']}") if application["profile"]["business_criticality"]
              # tag_list = application["profile"]["tags"].split(",") if application["profile"]["tags"]
              app_list << { "guid" => application.fetch("guid"), "name" => application["profile"]["name"], "tags" => tag_list }
            end
            url = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
          app_list
        end

        def cwe_recommendations(page_size)
          cwe_request = "#{CWE_PATH}?size=#{page_size}"
          url = "https://#{HOST}#{cwe_request}"
          cwe_rec_list = []
          until url.nil?
            uri = URI.parse(url)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(url, hmac_auth_options(auth_path))
            result = JSON.parse(response.body)
            cwes = result["_embedded"]["cwes"]

            cwes.lazy.each do |cwe|
              # cwe_rec_list << { "id" => cwe.fetch("id"), "severity" => cwe.fetch("severity"), "remediation_effort" => cwe.fetch("remediation_effort"), "recommendation" => cwe.fetch("recommendation") }
              cwe_rec_list << { "id" => cwe.fetch("id"), "recommendation" => cwe.fetch("recommendation") }
            end
            url = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
          @cwe_recommendations = cwe_rec_list
        end

        def category_recommendations(page_size)
          cat_request = "#{CAT_PATH}?size=#{page_size}"
          url = "https://#{HOST}#{cat_request}"
          cat_rec_list = []
          until url.nil?
            uri = URI.parse(url)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(url, hmac_auth_options(auth_path))
            result = JSON.parse(response.body)
            categories = result["_embedded"]["categories"]

            categories.lazy.each do |category|
              cat_rec_list << { "id" => category.fetch("id"), "recommendation" => category.fetch("recommendation") }
            end
            url = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
          @category_recommendations = cat_rec_list
        end

        def get_findings(app_guid, app_name, tags, page_size, scan_type)
          print_debug "pulling #{scan_type} issues for #{app_name}"
          puts "pulling #{scan_type} issues for #{app_name}" # DBRO
          app_request = "#{FINDING_PATH}/#{app_guid}/findings?size=#{page_size}&scan_type=#{scan_type}"
          url = "https://#{HOST}#{app_request}"
          until url.nil?
            uri = URI.parse(url)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(url, hmac_auth_options(auth_path))

            if response.nil?
              puts "Unable to retrieve data for #{app_name}. Continuing..."
              print_error "Unable to retrieve data for #{app_name}. Continuing..."
              return
            end

            result = JSON.parse(response.body)
            findings = result["_embedded"]["findings"] if result.dig("_embedded", "findings")
            return if findings.nil?

            findings.lazy.each do |finding|
              # IF "STATIC" SCAN USE FILE, IF "DYNAMIC" USE URL
              file = nil
              url = nil
              ext_id = nil
              case finding["scan_type"]
              when "STATIC"
                file = finding["finding_details"]["file_name"]
                # file = "#{finding['finding_details']['file_path']}:#{finding['finding_details']['file_line_number']}"
                # file = finding["finding_details"]["file_path"]
                ext_id = "[#{app_name}] - #{file}"
              when "DYNAMIC"
                url = finding["finding_details"]["url"]
                ext_id = "[#{app_name}] - #{url}"
              end

              # Pull Status from finding["finding_status"]["status"]
              # Per docs this shoule be "OPEN" or "CLOSED"
              status = case finding["finding_status"]["status"]
                       when "CLOSED"
                         "closed"
                       else
                         "open"
                       end

              finding_tags = tags.dup
              finding_tags << "veracode_scan_type: #{finding['scan_type']}" unless finding_tags.include? "veracode_scan_type: #{finding['scan_type']}"
              finding_tags << "veracode_app: #{app_name}" unless finding_tags.include? "veracode_app: #{app_name}"

              # finding_cat = finding["finding_details"]["finding_category"].fetch("name")
              finding_rec = @category_recommendations.select { |r| r["id"] == finding["finding_details"]["finding_category"].fetch("id") }[0]["recommendation"]
              cwe_rec = @cwe_recommendations.select { |r| r["id"] == finding["finding_details"]["cwe"].fetch("id") }[0]["recommendation"]
              cwe_rec = "No CWE recommendation provided by Veracode. See category recommendation on Details tab." if cwe_rec == ""
              scanner_score = finding["finding_details"].fetch("severity")
              cwe = finding["finding_details"]["cwe"].fetch("id")
              cwe = "CWE-#{cwe}"
              cwe_name = finding["finding_details"]["cwe"].fetch("name")
              found_on = finding["finding_status"].fetch("first_found_date")
              last_seen = finding["finding_status"].fetch("last_seen_date")
              additional_information = {
                "issue_id" => finding.fetch("issue_id"),
                "description" => finding.fetch("description"),
                "violates_policy" => finding.fetch("violates_policy"),
                "severity" => scanner_score
              }
              additional_information.merge!(finding["finding_details"])
              additional_information.merge!(finding["finding_status"])

              # Formatting a couple fields
              additional_information["cwe"] = "#{cwe} - #{cwe_name} - #{additional_information['cwe']['href']}"
              additional_information["finding_category"] = "#{additional_information['finding_category']['id']} - #{additional_information['finding_category']['name']} - #{additional_information['finding_category']['href']}"

              asset = {

                "url" => url,
                "file" => file,
                "external_id" => ext_id,
                "application" => app_name,
                "tags" => finding_tags
              }

              asset.compact!

              # craft the vuln hash
              vuln_attributes = {
                "scanner_identifier" => cwe,
                "scanner_type" => "veracode",
                "scanner_score" => scanner_score * 2,
                "override_score" => scanner_score * 20,
                "details" => JSON.pretty_generate(additional_information),
                "created_at" => found_on,
                "last_seen_at" => last_seen,
                "status" => status
              }

              # Temp Fix awaiting Solution Fix for KDI Connector
              vuln_attributes["details"] = "Recommendation:\n\n#{finding_rec}\n\n===============\n\n#{vuln_attributes['details']}"

              vuln_attributes.compact!

              vuln_def = {
                "scanner_identifier" => cwe,
                "scanner_type" => "veracode",
                "cwe_identifiers" => cwe,
                "name" => cwe_name,
                "solution" => cwe_rec
              }

              vuln_def.compact!

              # Create the KDI entries
              create_kdi_asset_vuln(asset, vuln_attributes) # DBRO
              create_kdi_vuln_def(vuln_def)
            end
            url = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
        end

        def get_findings_sca(app_guid, app_name, tags, page_size)
          print_debug "pulling SCA issues for #{app_name}"
          puts "pulling SCA issues for #{app_name}" # DBRO
          app_request = "#{FINDING_PATH}/#{app_guid}/findings?size=#{page_size}&scan_type=SCA"
          url = "https://#{HOST}#{app_request}"
          until url.nil?
            uri = URI.parse(url)
            auth_path = "#{uri.path}?#{uri.query}"
            response = http_get(url, hmac_auth_options(auth_path))

            if response.nil?
              puts "Unable to retrieve data for #{app_name}. Continuing..."
              print_error "Unable to retrieve data for #{app_name}. Continuing..."
              return
            end

            result = JSON.parse(response.body)
            findings = result["_embedded"]["findings"] if result.dig("_embedded", "findings")
            return if findings.nil?

            findings.lazy.each do |finding|
              file = finding["finding_details"]["component_filename"]
              # file = finding["finding_details"]["component_path"].first.fetch("path")
              ext_id = "[#{app_name}] - #{file}"

              # Pull Status from finding["finding_status"]["status"]
              # Per docs this shoule be "OPEN" or "CLOSED"
              status = case finding["finding_status"]["status"]
                       when "CLOSED"
                         "closed"
                       else
                         "open"
                       end

              finding_tags = tags.dup
              finding_tags << "veracode_scan_type: #{finding['scan_type']}" unless finding_tags.include? "veracode_scan_type: #{finding['scan_type']}"
              finding_tags << "veracode_app: #{app_name}" unless finding_tags.include? "veracode_app: #{app_name}"
              # tags << "veracode_scan_type: #{finding['scan_type']}" unless tags.include? "veracode_scan_type: #{finding['scan_type']}"
              # tags << "veracode_app: #{app_name}" unless tags.include? "veracode_app: #{app_name}"

              # finding_cat = finding["finding_details"]["finding_category"].fetch("name")
              # finding_rec = @category_recommendations.select { |r| r["id"] == finding["finding_details"]["finding_category"].fetch("id") }[0]["recommendation"]
              scanner_score = finding["finding_details"].fetch("severity")
              cwe = finding["finding_details"]["cwe"].fetch("id") if finding["finding_details"]["cwe"]
              cwe = "CWE-#{cwe}" if finding["finding_details"]["cwe"]
              cve = finding["finding_details"]["cve"].fetch("name").strip if finding["finding_details"]["cve"]
              found_on = finding["finding_status"].fetch("first_found_date")
              last_seen = finding["finding_status"].fetch("last_seen_date")
              description = finding.fetch("description") if finding["description"]
              additional_information = {
                "scan_type" => finding.fetch("scan_type"),
                "description" => description,
                "violates_policy" => finding.fetch("violates_policy"),
                "severity" => scanner_score
              }
              additional_information.merge!(finding["finding_details"])
              additional_information.merge!(finding["finding_status"])

              # Formatting a couple fields
              additional_information["cwe"] = "#{cwe} - #{additional_information['cwe']['name']} - #{additional_information['cwe']['href']}" if finding["finding_details"]["cwe"]
              # additional_information["finding_category"] = "#{additional_information['finding_category']['id']} - #{additional_information['finding_category']['name']} - #{additional_information['finding_category']['href']}"

              asset = {

                "file" => file,
                "external_id" => ext_id,
                "application" => app_name,
                "tags" => finding_tags
              }

              asset.compact!

              # craft the vuln hash
              vuln_attributes = {
                "scanner_identifier" => cve,
                "scanner_type" => "veracode",
                "scanner_score" => scanner_score * 2,
                "override_score" => scanner_score * 20,
                "details" => JSON.pretty_generate(additional_information),
                "created_at" => found_on,
                "last_seen_at" => last_seen,
                "status" => status
              }

              # Temp Fix awaiting Solution Fix for KDI Connector
              # vuln_attributes["details"] = "Recommendation:\n\n#{finding_rec}\n\n===============\n\n#{vuln_attributes['details']}"

              vuln_attributes.compact!

              vuln_def = {
                "scanner_identifier" => cve,
                "scanner_type" => "veracode",
                "cwe_identifiers" => cwe,
                "cve_identifiers" => cve,
                "name" => cve,
                "description" => description
              }

              # Clear out SRCCLR numbers from CVE list
              vuln_def["cve_identifiers"] = nil unless cve.include? "CVE"
              # Clear CWE if CVE exists. CVE takes precedence
              vuln_def["cwe_identifiers"] = nil unless cve.nil?

              vuln_def.compact!

              # Create the KDI entries
              create_kdi_asset_vuln(asset, vuln_attributes) # DBRO
              create_kdi_vuln_def(vuln_def)
            end
            url = (result["_links"]["next"]["href"] unless result["_links"]["next"].nil?) || nil
          end
        end

        def issues(app_guid, app_name, tags, page_size, scan_types)
          scan_types_array = scan_types.split(",")
          # Get STATIC Findings
          get_findings(app_guid, app_name, tags, page_size, "STATIC") if scan_types_array.include? "STATIC"
          # Get DYNAMIC Findings
          get_findings(app_guid, app_name, tags, page_size, "DYNAMIC") if scan_types_array.include? "DYNAMIC"
          # Get SCA Findings
          get_findings_sca(app_guid, app_name, tags, page_size) if scan_types_array.include? "SCA"

          # Fix for slashes in the app_name. Won't work for filenames
          fname = if app_name.index("/")
                    app_name.tr("/", "_")
                  else
                    app_name
                  end

          fname = fname[0..175] # Limiting the size of the filename

          if @assets.nil? || @assets.empty?
            print_good "No data for #{app_name}. Skipping Upload."
          else
            kdi_upload(@output_dir, "veracode_#{fname}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key)
          end
        end

        def kdi_kickoff
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        end

        private

        def hmac_auth_options(api_path)
          { Authorization: veracode_signature(api_path) }
        end

        def veracode_signature(api_path)
          nonce = SecureRandom.hex
          timestamp = DateTime.now.strftime("%Q")
          request_data = "id=#{@id}&host=#{HOST}&url=#{api_path}&method=GET"

          encrypted_nonce = OpenSSL::HMAC.hexdigest(
            "SHA256", @key.scan(/../).map(&:hex).pack("c*"), nonce.scan(/../).map(&:hex).pack("c*")
          )
          encrypted_timestamp = OpenSSL::HMAC.hexdigest(
            "SHA256", encrypted_nonce.scan(/../).map(&:hex).pack("c*"), timestamp
          )
          signing_key = OpenSSL::HMAC.hexdigest(
            "SHA256", encrypted_timestamp.scan(/../).map(&:hex).pack("c*"), REQUEST_VERSION
          )
          signature = OpenSSL::HMAC.hexdigest(
            "SHA256", signing_key.scan(/../).map(&:hex).pack("c*"), request_data
          )

          "VERACODE-HMAC-SHA-256 id=#{@id},ts=#{timestamp},nonce=#{nonce},sig=#{signature}"
        end
      end
    end
  end
end
