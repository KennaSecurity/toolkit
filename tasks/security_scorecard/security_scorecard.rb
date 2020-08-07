
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
        { :name => "ssc_portfolio_id", 
          :type => "string", 
          :required => true, 
          :default => "", 
          :description => "This is the Security Scorecard portfolio used to pull the data." },
        { :name => "kenna_api_key", 
          :type => "api_key", 
          :required => false, 
          :default => nil, 
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

  def run(options)
    super
  
    kenna_api_host = @options[:kenna_api_host]
    kenna_api_key = @options[:kenna_api_key]
    kenna_connector_id = @options[:kenna_connector_id]
    ssc_api_key = @options[:ssc_api_key]
    ssc_portfolio_id = @options[:ssc_portfolio_id]
    scanner_type = "SecurityScorecard"
    
    #issue_types = ["patching_cadence_high", "patching_cadence_low", "service_imap", "csp_no_policy"]# nil 
    issue_types = nil # all 

    client = Kenna::Toolkit::Ssc::Client.new(ssc_api_key)

    ### Basic Sanity checking
    unless client.successfully_authenticated?
      print_error "Unable to proceed, invalid key for Security Scorecard?"
      return
    else 
      print_good "Successfully authenticated!"
    end

    issues = client.get_issues_for_portfolio(ssc_portfolio_id, issue_types)

    issues.each do |i|

      # create the asset baesd on 
      first_seen = i["first_seen_time"]
      last_seen = i["last_seen_time"]

      # Create the assets
      asset_attributes = {}

      if i["connection_attributes"]
        port = i["connection_attributes"]["dst_port"]
        asset_attributes["ip_address"] = i["connection_attributes"]["dst_ip"] 
      end

      if i["initial_url"]
        asset_attributes["url"] = i["initial_url"]
      end

      create_kdi_asset(asset_attributes) 

      ###
      ### Vuln
      ###
      issue_type = i["type"]
      vuln_attributes = {
        "scanner_identifier" => issue_type,
        "scanner_type" => scanner_type,
        "details" => i, 
        "created_at" => first_seen,
        "last_seen_at" => last_seen,
        "status" => "open"
      }
      vuln_attributes["port"] = port if port 

      create_kdi_asset_vuln(asset_attributes, vuln_attributes)
      
      # handle patching cadence differently, these will have CVEs
      if i["vulnerability_id"] 

        vuln_def_attributes = {
          "scanner_identifier" => "#{i["vulnerability_id"]}",
          "cve_identifiers" => "#{i["vulnerability_id"]}",
          "scanner_type" => scanner_type
        }

        cvd = create_kdi_vuln_def(vuln_def_attributes)

      # OTHERWISE!!!
      else # run through mapper 

        vuln_def_attributes = {
          "scanner_identifier" => issue_type,
          "scanner_type" => scanner_type
        }
      
        ###
        ### Put them through our mapper 
        ###
        fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper 
        vd = fm.get_canonical_vuln_details("SecurityScorecard", vuln_def_attributes)
        cvd = create_kdi_vuln_def(vd)
  
      end

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