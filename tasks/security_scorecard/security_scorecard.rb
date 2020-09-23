
require_relative 'lib/client'
module Kenna 
module Toolkit
class SecurityScorecard < Kenna::Toolkit::BaseTask

  def self.metadata 
    {
      id: "security_scorecard",
      name: "Security Scorecard",
      maintainers: ["jcran"],
      description: "This task connects to the Security Scorecard API and pulls results into the Kenna Platform.",
      options: [
        { :name => "ssc_api_key", 
          :type => "string", 
          :required => true, 
          :default => "", 
          :description => "This is the Security Scorecard key used to query the API." },
        { :name => "ssc_domain", 
          :type => "string", 
          :required => false, 
          :default => nil,
          :description => "If filled, this will pull a one-off report for the domain. [DEFAULT]" },
        { :name => "ssc_portfolio_id", 
          :type => "string", 
          :required => false, 
          :default => nil,
          :description => "If filled, this will pull a portfolio's issues." },
        { :name => "kenna_api_key", 
          :type => "api_key",
          :required => false, 
          :default => "", 
          :description => "Kenna API Key" },
        { :name => "kenna_api_host", 
          :type => "hostname", 
          :required => false, 
          :default => "api.kennasecurity.com", 
          :description => "Kenna API Hostname" },
        { :name => "kenna_connector_id", 
          :type => "integer", 
          :required => false, 
          :default => nil, 
          :description => "If set, we'll try to upload to this connector"  },    
        { :name => "output_directory", 
          :type => "filename", 
          :required => false, 
          :default => "output/security_scorecard", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
      ]
    }
  end


  def ssc_issue_to_kdi_asset_hash(i)

    # Create the assets
    asset_attributes = {
      "tags" => ["SecurityScorecard"]
    }

    ### 
    ### Pull out the asset identfiiers here 
    ###
    if i["connection_attributes"]
      if i["connection_attributes"].kind_of? Hash
        port = i["connection_attributes"]["dst_port"]
        asset_attributes["ip_address"] = i["connection_attributes"]["dst_ip"]  if i["connection_attributes"]["dst_ip"]
        asset_attributes["hostname"] = i["connection_attributes"]["dst_host"] if i["connection_attributes"]["dst_host"]
      else
        puts "UNKOWN FORMAT FOR ISSUE, SKIPPING: #{i}"
        return nil
      end
    end

    # Converted Csv only
    if i["hostname"]
      asset_attributes["hostname"] = i["hostname"]
    end
    
    if i["subdomain"] && !i["hostname"] 
      asset_attributes["hostname"] = i["subdomain"]
    end

    if i["common_name"] && !i["hostname"]
      asset_attributes["hostname"] = i["common_name"]
    end
  
    ### End converted csv-only stuff

    if i["ip_address"]
      asset_attributes["ip_address"] = i["ip_address"]
    end

    if i["initial_url"]
      asset_attributes["url"] = i["initial_url"]
    end

    if i["url"]
      asset_attributes["url"] = i["url"]
    end

    if i["domain"]
      asset_attributes["fqdn"] = i["domain"]
    end

    if i["src_ip"]
      asset_attributes["ip_address"] = i["src_ip"]
    end

    unless (asset_attributes["ip_address"] ||
      asset_attributes["hostname"] || 
      asset_attributes["url"] ||  
      asset_attributes["domain"])
      print_debug "UNMAPPED ASSET FOR FINDING: #{i}"
    end
  
  asset_attributes
  end
    
  def ssc_issue_to_kdi_vuln_hash(i)
    
    # hardcoded     
    scanner_type = "SecurityScorecard"

    # create the asset baesd on 
    first_seen = i["first_seen_time"]
    last_seen = i["last_seen_time"]
    
    if i["connection_attributes"]
      if i["connection_attributes"].kind_of? Hash
        port = i["connection_attributes"]["dst_port"]
      end
    elsif i["port"]
      port = i["port"]
    end

    #puts JSON.pretty_generate(i) 
    #puts 

    issue_type = i["type"]

    # handle patching cadence differently, these will have CVEs
    if issue_type =~ /patching_cadence/ || issue_type =~ /service_vuln/ 

      #puts "DEBUG CVE VULN: #{i["type"]} #{i['vulnerability_id']}"
      #puts "#{i}"

      vuln_attributes = {
        "scanner_identifier" => i["vulnerability_id"] || i["cve"] ,
        "scanner_type" => scanner_type,
        "details" => JSON.pretty_generate(i), 
        "created_at" => first_seen,
        "last_seen_at" => last_seen,
        "status" => "open"
      }
      vuln_attributes["port"] = port if port 

      #create_kdi_asset_vuln(asset_attributes, vuln_attributes)

      vuln_def_attributes = {
        "scanner_identifier" => "#{i["vulnerability_id"]}",
        "cve_identifiers" => "#{i["vulnerability_id"]}",
        "scanner_type" => scanner_type
      }

    # OTHERWISE!!!
    else # run through mapper 

      ###
      # if we got a positive finding, make it benign
      ###
      if i["issue_type_severity"] == "POSITIVE"
        issue_type = "benign_finding"
      end

      #puts "DEBUG NON CVE VULN: #{issue_type}"
      
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
        "details" => JSON.pretty_generate(i), 
        "created_at" => first_seen,
        "last_seen_at" => last_seen,
        "status" => "open"
      }
      vuln_attributes["port"] = port if port 

      ###
      ### Set Scores based on what was available in the CVD
      ###
      if vuln_def_attributes["scanner_score"]
        vuln_attributes["scanner_score"] = vuln_def_attributes["scanner_score"]
      end

      if vuln_def_attributes["override_score"]
        vuln_attributes["override_score"] = vuln_def_attributes["override_score"]
      end



    end

  [vuln_attributes, vuln_def_attributes]
  end

  def ssc_csv_issue_to_hash(line)
    {
      "issue_id" => "#{line[0]}",
      "factor_name"=> "#{line[1]}",
      "issue_type_title"=> "#{line[2]}",
      "type"=> "#{line[3]}",              # to fit existing kdi generation
      "issue_type_code"=> "#{line[3]}",
      "issue_type_severity"=> "#{line[4]}",
      "issue_recommendation"=> "#{line[5]}",
      "first_seen_time"=> Time.strptime("#{line[6]}", "%m/%d/%Y"),
      "last_seen_time"=> Time.strptime("#{line[7]}", "%m/%d/%Y"),
      "ip_address"=> "#{line[8]}".split(",").first, # to fit existing kdi generation
      "ip_addresses"=> "#{line[8]}",
      "hostname"=> "#{line[9]}",
      "subdomain"=> "#{line[10]}",
      "port" => "#{line[11]}".split(",").first, # to fit existing kdi generation
      "ports"=> "#{line[11]}",
      "status"=> "#{line[12]}",
      "cve"=> "#{line[13]}", 
      "vulnerability_id" => "#{line[13]}", # to fit existing kdi generation
      "description"=> "#{line[14]}",
      "time_since_published"=> "#{line[15]}",
      "time_open_since_published"=> "#{line[16]}",
      "cookie_name"=> "#{line[17]}",
      "data"=> "#{line[18]}",
      "common_name"=> "#{line[19]}",
      "key_length"=> "#{line[20]}",
      "using_rc4?"=> "#{line[21]}",
      "issuer_organization_name"=> "#{line[22]}",
      "provider"=> "#{line[23]}",
      "detected_service"=> "#{line[24]}",
      "product" => "#{line[25]}",
      "version" => "#{line[26]}",
      "platform" => "#{line[27]}",
      "browser" => "#{line[28]}",
      "destination_ips"=> "#{line[29]}",
      "malware_family"=> "#{line[30]}",
      "malware_type"=> "#{line[31]}",
      "detection_method"=> "#{line[32]}",
      "label"=> "#{line[33]}",
      "initial_url"=> "#{line[34]}",
      "final_url"=> "#{line[35]}",
      "request_chain"=> "#{line[36]}",
      "headers"=> "#{line[37]}",
      "analysis"=> "#{line[38]}"
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
    unless client.successfully_authenticated?
      print_error "Unable to proceed, invalid key for Security Scorecard?"
      return
    else 
      print_good "Successfully authenticated!"
    end

    # use the first one !!!
    #unless ssc_portfolio_id
    #  ssc_portfolio_id = client.get_portfolio["entries"].first["id"]
    #  print_good "Using first portfolio since none was specified: #{ssc_portfolio_id}"
    #end

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
        
        if index == 0 
          #puts "HEADERS: #{issue}"
          next
        end

        #print_debug "Processing issue: #{issue}"
        print_good "Processing issue: #{index}/#{issues_count}: #{issue[0]}"
        i = ssc_csv_issue_to_hash(issue)

        ### 
        ### Get things in an acceptable format 
        ###
        asset_attributes = ssc_issue_to_kdi_asset_hash(i)
        #print asset_attributes 
        vuln_attributes, vuln_def_attributes = ssc_issue_to_kdi_vuln_hash(i)
        #print vuln_attributes 
        #print vuln_def_attributes
        
        

        # THEN create it 
        create_kdi_asset(asset_attributes) 
        # vuln 
        create_kdi_asset_vuln(asset_attributes, vuln_attributes)
        # vuln def entry 
        create_kdi_vuln_def(vuln_def_attributes)
  
      end

    elsif ssc_portfolio_id

      if @options[:debug]
        issue_types = [
          "patching_cadence_high", 
          "patching_cadence_medium", 
          "patching_cadence_low", 
          "service_imap", 
          "csp_no_policy"
        ]# nil 
        print_debug "Only getting #{issue_types}... "
      end

      print_good "Pulling data for portfolio: #{ssc_portfolio_id}"
      issues = client.get_issues_for_portfolio(ssc_portfolio_id, issue_types)

      issues.each do |i|
      
        ### 
        ### Get things in an acceptable format 
        ###
        asset_attributes = ssc_issue_to_kdi_asset_hash(i)

        vuln_attributes, vuln_def_attributes = ssc_issue_to_kdi_vuln_hash(i)
      
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
    if kenna_connector_id && kenna_api_host && kenna_api_key
      print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
      upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
    end

  end    
end
end
end