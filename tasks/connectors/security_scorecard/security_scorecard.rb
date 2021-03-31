# frozen_string_literal: true

require_relative "lib/client"
module Kenna
  module Toolkit
    class SecurityScorecard < Kenna::Toolkit::BaseTask
      def self.metadata
        {
          id: "security_scorecard",
          name: "Security Scorecard",
          description: "This task connects to the Security Scorecard API and pulls results into the Kenna Platform.",
          options: [
            { name: "ssc_api_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the Security Scorecard key used to query the API." },
            { name: "ssc_domain",
              type: "string",
              required: false,
              default: nil,
              description: "If filled, this will pull a one-off report for the domain. [DEFAULT]" },
            { name: "ssc_portfolio_ids",
              type: "string",
              required: false,
              default: nil,
              description: "Comma separated list of portfolio ids. if nil will pull all portfolios." },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: "",
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
              default: "output/security_scorecard",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def ssc_issue_to_kdi_asset_hash(issue)
        # Create the assets
        asset_attributes = {
          "tags" => ["SecurityScorecard"]
        }

        ###
        ### Pull out the asset identfiiers here
        ###
        if issue["connection_attributes"]
          if issue["connection_attributes"].is_a? Hash
            # port = issue["connection_attributes"]["dst_port"]
            ip_address = issue["connection_attributes"]["dst_ip"] if issue["connection_attributes"]["dst_ip"]
            hostname = issue["connection_attributes"]["dst_host"] if issue["connection_attributes"]["dst_host"]
          else
            puts "UNKOWN FORMAT FOR ISSUE, SKIPPING: #{issue}"
            return nil
          end
        end

        hostname ||= issue["hostname"] if issue["hostname"]
        hostname ||= issue["subdomain"] if issue["subdomain"]
        hostname ||= issue["common_name"] if issue["common_name"]

        ip_address ||= issue["ip_address"] if issue["ip_address"]
        ip_address ||= issue["target"] if issue["target"]

        url = issue["initial_url"] if issue["initial_url"]
        url ||= issue["url"] if issue["url"]

        ip_address = issue["src_ip"] if issue["src_ip"]

        unless ip_address ||
               hostname ||
               url
          print_debug "UNMAPPED ASSET FOR FINDING: #{issue}"
          return nil
        end
        asset_attributes["ip_address"] = ip_address unless ip_address.nil? || ip_address.empty?
        asset_attributes["hostname"] = hostname unless hostname.nil? || hostname.empty?
        asset_attributes["url"] = url unless url.nil? || url.empty?

        asset_attributes
      end

      def ssc_issue_to_kdi_vuln_hash(issue)
        # hardcoded
        scanner_type = "SecurityScorecard"

        # create the asset baesd on
        first_seen = issue["first_seen_time"]
        last_seen = issue["last_seen_time"]

        if issue["connection_attributes"]
          port = issue["connection_attributes"]["dst_port"] if issue["connection_attributes"].is_a? Hash
        elsif issue["port"]
          port = issue["port"]
        end

        # puts JSON.pretty_generate(i)
        # puts

        issue_type = issue["type"]

        # handle patching cadence differently, these will have CVEs
        if issue_type =~ /patching_cadence/ || issue_type =~ /service_vuln/

          # puts "DEBUG CVE VULN: #{i["type"]} #{i['vulnerability_id']}"
          # puts "#{i}"

          vuln_attributes = {
            "scanner_identifier" => issue["vulnerability_id"] || issue["cve"],
            "vuln_def_name" => issue["vulnerability_id"] || issue["cve"],
            "scanner_type" => scanner_type,
            "details" => JSON.pretty_generate(issue),
            "created_at" => first_seen,
            "last_seen_at" => last_seen,
            "status" => "open"
          }
          vuln_attributes["port"] = port if port

          # create_kdi_asset_vuln(asset_attributes, vuln_attributes)

          vuln_def_attributes = {
            "name" => (issue["vulnerability_id"]).to_s,
            "cve_identifiers" => (issue["vulnerability_id"]).to_s,
            "scanner_type" => scanner_type
          }

        # OTHERWISE!!!
        else # run through mapper

          ###
          # if we got a positive finding, make it benign
          ###
          print_debug "Got: #{issue_type}: #{issue['issue_type_severity']}"

          if issue["issue_type_severity"] == "POSITIVE"
            issue_type = "benign_finding"
            # elsif i["issue_type_severity"] == "INFO"
            #  issue_type = "benign_finding"
          end

          # puts "DEBUG NON CVE VULN: #{issue_type}"

          temp_vuln_def_attributes = {
            "scanner_identifier" => issue_type
          }

          ###
          ### Put them through our mapper
          ###
          fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper
          vuln_def_attributes = fm.get_canonical_vuln_details("SecurityScorecard", temp_vuln_def_attributes)

          ###
          ### Vuln
          ###
          vuln_attributes = {
            "scanner_identifier" => issue_type,
            "scanner_type" => scanner_type,
            "details" => JSON.pretty_generate(issue),
            "created_at" => first_seen,
            "last_seen_at" => last_seen,
            "status" => "open"
          }
          vuln_attributes["port"] = port if port&.positive?

          ###
          ### Set Scores based on what was available in the CVD
          ###
          vuln_attributes["scanner_score"] = vuln_def_attributes["scanner_score"] if vuln_def_attributes["scanner_score"]
          vuln_attributes["vuln_def_name"] = vuln_def_attributes["name"] if vuln_def_attributes.key?("name")
          vuln_attributes["override_score"] = vuln_def_attributes["override_score"] if vuln_def_attributes["override_score"]
          vuln_def_attributes.tap { |hs| hs.delete("scanner_identifier") }
        end

        [vuln_attributes, vuln_def_attributes]
      end

      def ssc_csv_issue_to_hash(line)
        {
          "issue_id" => (line[0]).to_s, # issue id
          "factor_name" => (line[1]).to_s, # factor name
          "issue_type_title" => (line[2]).to_s, # issue type title
          "type" => (line[3]).to_s, # issue type code
          "issue_type_code" => (line[3]).to_s, # issue type code
          "issue_type_severity" => (line[4]).to_s, # issue type severity
          "issue_recommendation" => (line[5]).to_s, # issue type recommendation
          "first_seen_time" => Time.strptime((line[6]).to_s, "%m/%d/%Y"), # first seen
          "last_seen_time" => Time.strptime((line[7]).to_s, "%m/%d/%Y"), # last seen
          "ip_address" => (line[8]).to_s.split(",").first, # to fit existing kdi generation / ip addresses
          "ip_addresses" => (line[8]).to_s, # ip addresses
          "hostname" => (line[9]).to_s, # Hostname
          "subdomain" => (line[10]).to_s, # subdomain
          "target" => (line[11]).to_s, # target
          "port" => (line[12]).to_s.split(",").first, # to fit existing kdi generation / ports
          "ports" => (line[12]).to_s, # ports
          "status" => (line[13]).to_s, # status
          "cve" => (line[14]).to_s, # cve
          "vulnerability_id" => (line[14]).to_s, # to fit existing kdi generation / cve
          "description" => (line[15]).to_s, # description
          "time_since_published" => (line[16]).to_s, # time since published
          "time_open_since_published" => (line[17]).to_s, # time open since published
          "cookie_name" => (line[18]).to_s, # cookie name
          "data" => (line[19]).to_s, # data
          "common_name" => (line[20]).to_s, # common name
          "key_length" => (line[21]).to_s, # key length
          "using_rc4?" => (line[22]).to_s, # using rc4
          "issuer_organization_name" => (line[23]).to_s,
          "provider" => (line[24]).to_s,
          "detected_service" => (line[25]).to_s,
          "product" => (line[26]).to_s,
          "version" => (line[27]).to_s,
          "platform" => (line[28]).to_s,
          "browser" => (line[29]).to_s,
          "destination_ips" => (line[30]).to_s,
          "malware_family" => (line[31]).to_s,
          "malware_type" => (line[32]).to_s,
          "detection_method" => (line[33]).to_s,
          "label" => (line[34]).to_s,
          "initial_url" => (line[35]).to_s,
          "final_url" => (line[36]).to_s,
          "request_chain" => (line[37]).to_s,
          "headers" => (line[38]).to_s,
          "analysis" => (line[39]).to_s
        }
      end

      def run(options)
        super

        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]
        ssc_api_key = @options[:ssc_api_key]
        ssc_domain = @options[:ssc_domain]
        ssc_portfolio_ids = @options[:ssc_portfolio_id]
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        issue_types = nil # all

        client = Kenna::Toolkit::Ssc::Client.new(ssc_api_key)

        ### Basic Sanity checking
        if client.successfully_authenticated?
          print_good "Successfully authenticated!"
        else
          print_error "Unable to proceed, invalid key for Security Scorecard?"
          return
        end

        unless ssc_portfolio_ids
          ssc_portfolio_ids = []
          client.portfolios["entries"].each do |portfolio|
            ssc_portfolio_ids << portfolio.fetch("id")
          end
        end

        if ssc_domain

          # grab
          print_good "Pulling data for domain: #{ssc_domain}"
          if @options[:debug]
            issue_types = %w[
              patching_cadence_high
              patching_cadence_medium
              patching_cadence_low
              service_imap
              csp_no_policy
            ] # nil
            print_debug "Only getting #{issue_types}... "
          end

          company_issues = []
          issue_types ||= client.issue_types_list

          issue_types.each do |type|
            issues = client.issues_by_type_for_company(ssc_domain, type)

            if issues
              issues = issues["entries"]
              puts "#{issues.count} issues of type #{type}"
              company_issues.concat(issues.map { |i| i.merge({ "type" => type }) })
            else
              puts "Missing (or error) on #{type} issues"
            end
          end

          company_issues&.flatten
          company_issues.each do |issue|
            ###
            ### Get things in an acceptable format
            ###
            asset_attributes = ssc_issue_to_kdi_asset_hash(issue)
            next if asset_attributes.nil?

            vuln_attributes, vuln_def_attributes = ssc_issue_to_kdi_vuln_hash(issue)

            create_kdi_asset_vuln(asset_attributes, vuln_attributes)
            # vuln def entry
            create_kdi_vuln_def(vuln_def_attributes)
          end

          filename = "ssc_kdi_#{ssc_domain}.json"
          kdi_upload output_dir, filename, kenna_connector_id, kenna_api_host, kenna_api_key, false, 3, 2 unless @assets.empty?

        elsif ssc_portfolio_ids
          ssc_portfolio_ids.each do |portfolio|
            if @options[:debug]
              issue_types = %w[
                patching_cadence_high
                patching_cadence_medium
                patching_cadence_low
                service_imap
                csp_no_policy
              ] # nil
              print_debug "Only getting #{issue_types}... "
            end

            print_good "Pulling data for portfolio: #{portfolio}"
            companies = client.companies_by_portfolio(portfolio)
            companies["entries"].each do |company|
              company_issues = []
              issue_types ||= client.issue_types_list

              issue_types.each do |type|
                issues_by_type = client.issues_by_type_for_company(company["domain"], type)

                issues = issues_by_type["entries"] unless issues_by_type.nil?

                if issues
                  puts "#{issues.count} issues of type #{type}"
                  company_issues.concat(issues.map { |i| i.merge({ "type" => type }) })
                else
                  puts "Missing (or error) on #{type} issues"
                end
              end

              company_issues&.flatten
              company_issues.each do |issue|
                ###
                ### Get things in an acceptable format
                ###
                asset_attributes = ssc_issue_to_kdi_asset_hash(issue)
                next if asset_attributes.nil?

                vuln_attributes, vuln_def_attributes = ssc_issue_to_kdi_vuln_hash(issue)

                create_kdi_asset_vuln(asset_attributes, vuln_attributes)
                # vuln def entry
                create_kdi_vuln_def(vuln_def_attributes)
              end
              filename = "ssc_kdi_#{company['domain']}.json"
            end
            kdi_upload output_dir, filename, kenna_connector_id, kenna_api_host, kenna_api_key, false, 3, 2 unless @assets.nil? || @assets.empty?
          end
        end

        return unless kenna_connector_id && kenna_api_host && kenna_api_key

        kdi_connector_kickoff(kenna_connector_id, kenna_api_host, kenna_api_key)
      end
    end
  end
end
