require_relative 'lib/client'

module Kenna 
module Toolkit
class ExpanseTask < Kenna::Toolkit::BaseTask

  def self.metadata 
    {
      id: "expanse",
      name: "Expanse",
      description: "This task connects to the Expanse API and pulls results into the Kenna Platform.",
      options: [
        { :name => "expanse_api_key", 
          :type => "string", 
          :required => true, 
          :default => "", 
          :description => "This is the Expanse key used to query the API." },
        { :name => "expanse_api_key", 
          :type => "string", 
          :required => false, 
          :default => "", 
          :description => "Comma-separated list of exposure types. If not set, all exposures will be included" },
        { :name => "kenna_api_token", 
          :type => "api_key", 
          :required => false, 
          :default => nil, 
          :description => "Kenna API Key" },
        { :name => "kenna_api_host", 
          :type => "hostname", 
          :required => false  , 
          :default => "api.kennasecurity.com", 
          :description => "Kenna API Hostname" },
        { :name => "output_directory", 
          :type => "filename", 
          :required => false, 
          :default => "output/expanse", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
      ]
    }
  end

  def map_scanner_severity(sev_word)
    out = 0
    case sev_word
    when "CRITICAL"
      out = 100
    when "WARNING"
      out = 50
    when "ROUTINE"
      out = 10
    when "UNCATEGORIZED"
      out = 1
    end
  out 
  end

  def default_field_mapping
    {
      'asset' => [  
        { action: "copy", source: "parentDomain", target: "domain" },
        { action: "copy", source: "domain", target: "hostname" },
        { action: "copy", source: "ip", target: "ip_address" }
      ],
      'vuln' => [
        { action: "proc", target: "scanner_identifier", proc: lambda{|x| "open_port_#{x["port"]}" }},
        { action: "copy", source: "port", target: "port" },
        { action: "proc", target: "scanner_score", proc: lambda{|x| map_scanner_severity(x["severity"]) } },
        { action: "data", target: "scanner_type", data: "Expanse" }
      ],
      'vuln_def' => [
        { action: "proc", target: "scanner_identifier", proc: lambda{|x| "open_port_#{x["port"]}" }},
        { action: "proc", target: "description", proc: lambda{|x| "Open Port: #{x["port"]}" } },
        { action: "data", target: "remediation", data: "Investigate this exposure" },
        { action: "proc", target: "extra_attribute", proc: lambda{|x| "some value" } }
      ]
    }
  end

  ###
  ### Each entry (type) should have a set of mappings for each KDI section:
  ###   Asset
  ###   Vuln
  ###   VulnDef
  ###
  ### Also, each mapping should be one of the following types: 
  ###   calc - just copies data from the source 
  ###   copy - just copies data from the source 
  ###   data - static data, use directly without worrying about source data
  ###
  def field_mapping_by_type
    {
      'application-server-software' => {
        'asset' => [ ],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| "app_server_software_#{x["firstObservation"]["configuration"]["applicationServerSoftware"]}".to_string_identifier }
          },
         ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| "Exposed App Server Software: #{x["firstObservation"]["configuration"]["applicationServerSoftware"]}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| "app_server_software_#{x["firstObservation"]["configuration"]["applicationServerSoftware"]}".to_string_identifier }
          }
        ]
      },
      'bacnet-servers' => {}, 
      'dns-servers' => {}, 
      'ethernet-ip-servers' => {}, 
      'ftp-servers' => {}, 
      'ftps-servers' => {}, 
      'memcached-servers' => {}, 
      'modbus-servers' => {}, 
      'ms-sql-servers' => {}, 
      'my-sql-servers' => {}, 
      'pop3-servers' => {}, 
      'rdp-servers' => {},
      'smb-servers' => {},
      'snmp-servers' => {},
      'ssh-servers' => {},
      'upnp-servers' => {},
      'web-servers' => {},
      'vnc-servers' => {},
      'vx-works-servers' => {}
    }
  end

  # this method does the actual mapping, as specified
  # in the field_mapping_by_type method
  def map_fields(exposure_type, exposure)
    
    # grab the relevant mapping
    mapping_areas = default_field_mapping.deep_merge(field_mapping_by_type[exposure_type]) # asset, vuln, vuln_def

    # then execute the mapping 
    out = {}

    ## For each area (asset,vuln,vuln_def) in the mapping
    mapping_areas.each do |area,mapping|
      out[area] = {}

      ## For each item in the mapping
      mapping.each do |map_item|
        target = map_item[:target]
        map_action = map_item[:action]
        
        ## Perform the requested mapping action

        if map_action == "proc" # call a lambda, passing in the whole exposure
          out[area][target] = map_item[:proc].call(exposure)
        elsif map_action == "copy" # copy from source data
          out[area][target] = exposure[map_item[:source]]
        elsif map_action == "data" # static data 
          out[area][target] = map_item[:data]
        end

      end
    end

  out 
  end


  def run(options)
    super
  
    api_host = @options[:kenna_api_host]
    api_token = @options[:kenna_api_token]
    expanse_api_key = @options[:expanse_api_key]

    # create an api client
    @client = Kenna::Toolkit::Expanse::Client.new(expanse_api_key)
  
    @assets = []
    @vuln_defs = []

    unless @client.successfully_authenticated?
      print_bad "Unable to proceed, invalid key for Expanse?"
      return 
    end
    print_good "Valid key, proceeding!"

    ### 
    ### Get the list of exposure types
    ###
    if @options[:exposure_types]
      exposure_types = @options[:exposure_types]
      #print_debug "DEBUG Getting results for exposure_types:\n#{JSON.pretty_generate(exposure_types)}"      
    else
      exposure_counts = @client.cloud_exposure_counts
      exposure_types = exposure_counts.map{|x| x["type"] }
      #print_debug "Getting results for exposures:\n#{JSON.pretty_generate(exposure_counts)}"      
    end
  

    ###
    ### For exach exposure type
    ###
    exposure_types.sort.each do |et|

      unless field_mapping_by_type[et]
        print_error "WARNING! Unmapped exposure type: #{et}, skipping"
        next
      end
     
      # get all exposures of this type
      exposures = @client.cloud_exposures(1, 1, [et]) # TODO DEBUG ETC ETC ETC
      next unless exposures.count > 0  #skip empty

      # map fields for those expsures
      result = exposures.map do |e| 
        #puts "Got Exposure:\n#{JSON.pretty_generate(e)}"
        map_fields(et, e) 
      end

      # convert to KDI 
      result.each do |r|
        create_kdi_asset(r["asset"], "ip_address", tags=[], priority=10)
        create_kdi_asset_vuln(r["asset"]["ip_address"], "ip_address", r["vuln"])      
        create_kdi_vuln_def(r["vuln_def"])
      end

    end 

    kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
   
    # create output dir
    if @options[:output_directory]
      output_dir = "#{$basedir}/#{@options[:output_directory]}"
      FileUtils.mkdir_p output_dir
      
      # create full output path
      output_path = "#{output_dir}/expanse.kdi.json"

      print_good "Output being written to: #{output_path}"
      File.open(output_path,"w") {|f| f.puts JSON.pretty_generate(kdi_output) } 
    end


    
=begin
    # iterate through the assets!
    
      # Create the assets!
      #  
      #  {
      #  file: string,  + (At least one of the fields with a + is required for each asset.)
      #  ip_address: string, + (See help center or support for locator order set for your instance)
      #  mac_address: string, +
      #  hostname: string, +
      #  ec2: string, +
      #  netbios: string, +
      #  url: string, +
      #  fqdn: string, +
      #  external_id: string, +
      #  database: string, +
      #  application: string, (This field should be used as a meta data field with url or file)
      # 
      #  tags: [ string (Multiple tags should be listed and separated by commas) ],
      #  owner: string,
      #  os: string, (although not required, it is strongly recommended to populate this field when available)
      #  os_version: string,
      #  priority: integer, (defaults to 10, between 0 and 10 but default is recommended unless you 
      #                      have a documented risk appetite for assets)
      #  vulns: * (If an asset contains no open vulns, this can be an empty array, 
      #            but to avoid vulnerabilities from being closed, use the skip-autoclose flag) ]
      #  }
    
      # Create the vuln!
      # 
      #  scanner_identifier: string, * ( each unique scanner identifier will need a 
      #                                  corresponding entry in the vuln-defs section below, this typically should 
      #                                  be the external identifier used by your scanner)
      #  scanner_type: string, * (required)
      #  scanner_score: integer (between 0 and 10),
      #  override_score: integer (between 0 and 100),
      #  created_at: string, (iso8601 timestamp - defaults to current date if not provided)
      #  last_seen_at: string, * (iso8601 timestamp)
      #  last_fixed_on: string, (iso8601 timestamp)
      #  closed_at: string, ** (required with closed status - This field used with status may be provided on remediated vulns to indicate they're closed, or vulns that are already present in Kenna but absent from this data load, for any specific asset, will be closed via our autoclose logic)
      #  status: string, * (required - valid values open, closed, false_positive, risk_accepted)
      #  port: integer
      
      # TODO
      #vuln_attributes = {
      #  scanner_identifier: f.id,
      #  scanner_type: f.service.service_name,
      #  scanner_score: f.severity, 
      #  created_at: f.created_at,
      #  last_seen_at: f.updated_at,
      #  status: "open"
      #}
      # def create_kdi_asset_vuln(asset_id, asset_locator, args)
      #create_kdi_asset_vuln(aws_account_id, :external_id, vuln_attributes)

      #print_good "Creating vuln def: #{f.title}"      
      # Create the vuln def! 
      # 
      # {
      #   scanner_identifier: * (entry for each scanner identifier that appears in the vulns section, 
      #                          this typically should be the external identifier used by your scanner)
      #   scanner_type: string, * (matches entry in vulns section)
      #   cve_identifiers: string, (note that this can be a comma-delimited list format CVE-000-0000)
      #   wasc_identifiers: string, (note that this can be a comma-delimited list - format WASC-00)
      #   cwe_identifiers: string, (note that this can be a comma-delimited list - format CWE-000)
      #   name: string, (title or short name of the vuln, will be auto-generated if not set)
      #   description:  string, (full description of the vuln)
      #   solution: string, (steps or links for remediation teams)
      # }
      #vuln_def_attributes = {
      #  scanner_identifier: f.id,
      #  scanner_type: f.service.service_name,
      #  name: f.title,
      #  description: f.description
      #}
      # def create_kdi_vuln_def(args)
      #create_kdi_vuln_def(vuln_def_attributes)
    end
=end

    #
    # TODO... upload 
    #
  end    

end
end
end