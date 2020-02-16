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

=begin
  def get_value_by_header(row, headers, field_name)

    # in case we get a string
    headers = headers.split(",") if headers.kind_of? String

    #puts "Getting value for field name: #{field_name} from: #{headers}"

    i = headers.find_index(field_name)
    return nil unless i 
    raise "Invalid index: #{i} for field_name: #{field_name}. All headers: #{headers}" unless i 

  "#{row[i]}"
  end

  def exposures_by_type_csv(exposure_type)
    exposures = []
    csv = @client.cloud_exposure_csv("ftp-servers")
    # Go through the CSV, pulling out the appropriate values
    csv.each_with_index do |row, index|
      next if index == 0 #skip the first 

      exposure_details = {}
      exposure_details[:ip] = get_value_by_header(row, csv.first, "ip")
      exposure_details[:hostname] = get_value_by_header(row, csv.first, "lastObservation.hostname")
      exposure_details[:domain] = get_value_by_header(row, csv.first, "domain")
      exposure_details[:port] =  get_value_by_header(row, csv.first, "port")
      exposure_details[:severity] = get_value_by_header(row, csv.first, "severity")
      exposure_details[:type] =  get_value_by_header(row, csv.first, "type") 
      exposures << exposure_details
    end
  
  exposures 
  end
=end

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
      'dns-servers' => {
        'asset' => [  
          { action: "copy", source: "domain", target: "domain" },
          { action: "copy", source: "hostname", target: "hostname" },
          { action: "copy", source: "ip", target: "ip_address" }
        ],
        'vuln' => [
          { action: "copy", source: "port", target: "port" },
          { action: "copy", source: "severity", target: "severity" },
          { action: "data", target: "scanner_type", data: "Expanse" }
        ],
        'vuln_def' => [
          { action: "data", target: "description",  data: "Open Port" },
          { action: "data", target: "remediation", data: "Investigate" },
          { action: "calc", target: "extra_attribute", lambda: lambda{|x| "some value" } }
        ]
      }, 
      'ftp-servers' => {
        'asset' => [  
          { action: "copy", source: "domain", target: "domain" },
          { action: "copy", source: "hostname", target: "hostname" },
          { action: "copy", source: "ip", target: "ip_address" }
        ],
        'vuln' => [
          { action: "copy", source: "port", target: "port" },
          { action: "copy", source: "severity", target: "severity" },
          { action: "data", target: "scanner_type", data: "Expanse" }
        ],
        'vuln_def' => [
          { action: "data", target: "decription", data: "Open Port" },
          { action: "data", target: "remediation", data: "Investigate" }
        ]
      }, 
      'ftps-servers' => {
        'asset' => [  
          { action: "copy", source: "domain", target: "domain" },
          { action: "copy", source: "hostname", target: "hostname" },
          { action: "copy", source: "ip", target: "ip_address" }
        ],
        'vuln' => [
          { action: "copy", source: "port", target: "port" },
          { action: "copy", source: "severity", target: "severity" },
          { action: "data", target: "scanner_type", data: "Expanse" }
        ],
        'vuln_def' => [
          { action: "data", target: "description",  data: "Open Port" },
          { action: "data", target: "remediation", data: "Investigate" }
        ]
      }
    }
  end

  # this method does the actual mapping, as specified
  # in the field_mapping_by_type method
  def map_fields(exposure_type, exposure)
    
    # grab the relevant mapping
    mapping_areas = field_mapping_by_type[exposure_type] # asset, vuln, vuln_def

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

        if map_action == "calc" # call a lambda, passing in the whole exposure
          out[area][target] = map_item[:lambda].call(exposure)
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

    
    exposure_types = @client.cloud_exposure_types.map{|x| x["type"]}
    print_good "Getting results for exposure types: #{exposure_types}"

    exposure_types.sort.each do |et|

      unless field_mapping_by_type[et]
        print_error "ERROR! Unmapped exposure type: #{et}, skipping"
        next
      end
     
      # get all exposures of this type
      exposures = @client.cloud_exposures([et])
      next unless exposures.count > 0  #skip empty

      # map fields for those expsures
      result = exposures.map{|e| map_fields(et, e)}

      # convert to KDI 
      result.each do |r|
        create_kdi_asset(r["asset"], "ip_address", tags=[], priority=10)
        create_kdi_asset_vuln(r["asset"]["ip_address"], "ip_address", r["vuln"])      
        create_kdi_vuln_def(r["vuln_def"])
      end

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

    #
    # TODO... upload 
    #
  end    

end
end
end