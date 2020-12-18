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
            { name: "ssc_portfolio_id",
              type: "string",
              required: false,
              default: nil,
              description: "If filled, this will pull a portfolio's issues." },
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
            asset_attributes["ip_address"] = issue["connection_attributes"]["dst_ip"] if issue["connection_attributes"]["dst_ip"]
            asset_attributes["hostname"] = issue["connection_attributes"]["dst_host"] if issue["connection_attributes"]["dst_host"]
          else
            puts "UNKOWN FORMAT FOR ISSUE, SKIPPING: #{issue}"
            return nil
          end
        end

        # Converted Csv only
        asset_attributes["hostname"] = issue["hostname"] if issue["hostname"]

        asset_attributes["hostname"] = issue["subdomain"] if issue["subdomain"] && !issue["hostname"]

        asset_attributes["hostname"] = issue["common_name"] if issue["common_name"] && !issue["hostname"]

        ### End converted csv-only stuff

        asset_attributes["ip_address"] = issue["ip_address"] if issue["ip_address"]

        asset_attributes["url"] = issue["initial_url"] if issue["initial_url"]

        asset_attributes["url"] = issue["url"] if issue["url"]

        asset_attributes["fqdn"] = issue["domain"] if issue["domain"]

        asset_attributes["ip_address"] = issue["src_ip"] if issue["src_ip"]

        unless asset_attributes["ip_address"] ||
               asset_attributes["hostname"] ||
               asset_attributes["url"] ||
               asset_attributes["domain"]
          print_debug "UNMAPPED ASSET FOR FINDING: #{issue}"
        end

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
            "scanner_type" => scanner_type,
            "details" => JSON.pretty_generate(issue),
            "created_at" => first_seen,
            "last_seen_at" => last_seen,
            "status" => "open"
          }
          vuln_attributes["port"] = port if port

          # create_kdi_asset_vuln(asset_attributes, vuln_attributes)

          vuln_def_attributes = {
            "scanner_identifier" => (issue["vulnerability_id"]).to_s,
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
          vuln_attributes["port"] = port if port

          ###
          ### Set Scores based on what was available in the CVD
          ###
          vuln_attributes["scanner_score"] = vuln_def_attributes["scanner_score"] if vuln_def_attributes["scanner_score"]

          vuln_attributes["override_score"] = vuln_def_attributes["override_score"] if vuln_def_attributes["override_score"]

        end

        [vuln_attributes, vuln_def_attributes]
      end

      def ssc_csv_issue_to_hash(line)
        {
          "issue_id" => (line[0]).to_s,
          "factor_name" => (line[1]).to_s,
          "issue_type_title" => (line[2]).to_s,
          "type" => (line[3]).to_s, # to fit existing kdi generation
          "issue_type_code" => (line[3]).to_s,
          "issue_type_severity" => (line[4]).to_s,
          "issue_recommendation" => (line[5]).to_s,
          "first_seen_time" => Time.strptime((line[6]).to_s, "%m/%d/%Y"),
          "last_seen_time" => Time.strptime((line[7]).to_s, "%m/%d/%Y"),
          "ip_address" => (line[8]).to_s.split(",").first, # to fit existing kdi generation
          "ip_addresses" => (line[8]).to_s,
          "hostname" => (line[9]).to_s,
          "subdomain" => (line[10]).to_s,
          "port" => (line[11]).to_s.split(",").first, # to fit existing kdi generation
          "ports" => (line[11]).to_s,
          "status" => (line[12]).to_s,
          "cve" => (line[13]).to_s,
          "vulnerability_id" => (line[13]).to_s, # to fit existing kdi generation
          "description" => (line[14]).to_s,
          "time_since_published" => (line[15]).to_s,
          "time_open_since_published" => (line[16]).to_s,
          "cookie_name" => (line[17]).to_s,
          "data" => (line[18]).to_s,
          "common_name" => (line[19]).to_s,
          "key_length" => (line[20]).to_s,
          "using_rc4?" => (line[21]).to_s,
          "issuer_organization_name" => (line[22]).to_s,
          "provider" => (line[23]).to_s,
          "detected_service" => (line[24]).to_s,
          "product" => (line[25]).to_s,
          "version" => (line[26]).to_s,
          "platform" => (line[27]).to_s,
          "browser" => (line[28]).to_s,
          "destination_ips" => (line[29]).to_s,
          "malware_family" => (line[30]).to_s,
          "malware_type" => (line[31]).to_s,
          "detection_method" => (line[32]).to_s,
          "label" => (line[33]).to_s,
          "initial_url" => (line[34]).to_s,
          "final_url" => (line[35]).to_s,
          "request_chain" => (line[36]).to_s,
          "headers" => (line[37]).to_s,
          "analysis" => (line[38]).to_s
        }
      end

      def run(options)
        super

        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]
        ssc_api_key = @options[:ssc_api_key]
        ssc_domain = @options[:ssc_domain]
        ssc_portfolio_id = @options[:ssc_portfolio_id]
        issue_types = nil # all

        client = Kenna::Toolkit::Ssc::Client.new(ssc_api_key)

        ### Basic Sanity checking
        if client.successfully_authenticated?
          print_good "Successfully authenticated!"
        else
          print_error "Unable to proceed, invalid key for Security Scorecard?"
          return
        end

        # use the first one !!!
        unless ssc_portfolio_id
          ssc_portfolio_id = client.get_portfolio["entries"].first["id"]
          print_good "Using first portfolio since none was specified: #{ssc_portfolio_id}"
        end

        if ssc_domain

          # grab
          print_good "Pulling data for domain: #{ssc_domain}"
          # process
          issues = client.get_issues_report_for_domain(ssc_domain)

          print_good "Processing data for: #{ssc_domain}"

          if @options[:debug]
            icount = 5000
            print_debug "Only processing first #{icount} #{issue_types}... "
            issues = issues.first(icount)
          end

          issues_count = issues.count
          issues.each_with_index do |issue, index|
            if index.zero?
              # puts "HEADERS: #{issue}"
              next
            end

            # print_debug "Processing issue: #{issue}"
            print_good "Processing issue: #{index}/#{issues_count}: #{issue[0]}"
            i = ssc_csv_issue_to_hash(issue)

            ###
            ### Get things in an acceptable format
            ###
            asset_attributes = ssc_issue_to_kdi_asset_hash(i)
            # print asset_attributes
            vuln_attributes, vuln_def_attributes = ssc_issue_to_kdi_vuln_hash(i)
            # print vuln_attributes
            # print vuln_def_attributes

            # THEN create it
            create_kdi_asset(asset_attributes)
            # vuln
            create_kdi_asset_vuln(asset_attributes, vuln_attributes)
            # vuln def entry
            create_kdi_vuln_def(vuln_def_attributes)
          end

        elsif ssc_portfolio_id

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

          print_good "Pulling data for portfolio: #{ssc_portfolio_id}"
          issues = client.get_issues_for_portfolio(ssc_portfolio_id, issue_types)

          issues.each do |issue|
            ###
            ### Get things in an acceptable format
            ###
            asset_attributes = ssc_issue_to_kdi_asset_hash(issue)
            next if asset_attributes.nil?

            vuln_attributes, vuln_def_attributes = ssc_issue_to_kdi_vuln_hash(issue)

            # THEN create it
            create_kdi_asset(asset_attributes)
            # vuln
            create_kdi_asset_vuln(asset_attributes, vuln_attributes)
            # vuln def entry
            create_kdi_vuln_def(vuln_def_attributes)
          end
        else
          print_error "No Domain or Portfolio ID specified, unable to proceed!"
          return
        end

        ### Write KDI format
        kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "security_scorecard.kdi.json"
        write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        print_good "Output is available at: #{output_dir}/#{filename}"

        ### Finish by uploading if we're all configured
        return unless kenna_connector_id && kenna_api_host && kenna_api_key

        print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
        upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
      end
    end
  end
end
