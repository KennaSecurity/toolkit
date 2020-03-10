# expanse client 
require_relative 'lib/client'

# cloud exposure field mapping
require_relative 'lib/cloud_exposure_mapping'

module Kenna 
module Toolkit
class ExpanseTask < Kenna::Toolkit::BaseTask

  include Kenna::Toolkit::Expanse::CloudExposureMapping

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
        { :name => "cloud_exposure_types", 
          :type => "string", 
          :required => false, 
          :default => "", 
          :description => "Comma-separated list of cloud exposure types. If not set, all exposures will be included" },
        { :name => "kenna_api_token", 
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
          :default => "output/expanse", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
        ]
    }
  end

  def run(options)
    super
  
    kenna_api_host = @options[:kenna_api_host]
    kenna_api_token = @options[:kenna_api_token]
    kenna_connector_id = @options[:kenna_connector_id]

    expanse_api_key = @options[:expanse_api_key]

    # create an api client
    @expanse = Kenna::Toolkit::Expanse::Client.new(expanse_api_key)
    @kenna = Kenna::Api.new(kenna_api_token, kenna_api_host)
  
    @assets = []
    @vuln_defs = []

    # verify we have a good key before proceeding
    unless @expanse.successfully_authenticated?
      print_bad "Unable to proceed, invalid key for Expanse?"
      return 
    end
    print_good "Valid key, proceeding!"

    # handle normal exposurs
    #create_kdi_from_exposures

    # handle cloud exposures
    create_kdi_from_cloud_exposures

    # write KDI format
    kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
   
    ###
    ### Write the file 
    ### 

    output_dir = "#{$basedir}/#{@options[:output_directory]}"
    FileUtils.mkdir_p output_dir
    
    # create full output path
    output_path = "#{output_dir}/expanse.kdi.json"

    # write it
    File.open(output_path,"w") {|f| f.puts JSON.pretty_generate(kdi_output) } 

    ###
    ### Finish by uploading, or just tell the user 
    ###

    # optionally upload the file if a connector ID has been specified 
    #if kenna_connector_id && kenna_api_host && kenna_api_token
  
      print_good "Attempting to upload to Kenna api"
      print_good "Kenna API host: #{kenna_api_host}"

      # upload it 
      @kenna.upload_to_connector(kenna_connector_id, output_path)

      # delete the temp file 
      File.delete(output_path)

    #else # just tell the user where the output is 
      print_good "Output is available at: #{output_path}"
    #end

  end    

  def create_kdi_from_exposures
    exposures = @expanse.exposures(1, 1)
    # parse and create kdi 
    exposures.each do |e|
      #puts "Exposure: #{e}"
    end
  end

  def create_kdi_from_cloud_exposures
   
    ### 
    ### Get the list of exposure types
    ###
    if @options[:cloud_exposure_types]
      exposure_types = @options[:cloud_exposure_types]
    else
      exposure_counts = @expanse.cloud_exposure_counts
      exposure_types = exposure_counts.map{|x| x["type"] }
    end
  
    ###
    ### For exach exposure type
    ###
    exposure_types.sort.each do |et|

      unmapped = false
      unless field_mapping_for_cloud_exposures[et]
        print_error "WARNING! Unmapped exposure type: #{et}!"
        unmapped = true 
      end
    
      # get all exposures of this type
      cloud_exposures = @expanse.cloud_exposures(1, 1, [et])
    
      # skip if we don't have any 
      unless cloud_exposures.count > 0 #skip empty
        print_good "No exposures of type #{et} found!"
        next
      end

      # map fields for those expsures
      result = cloud_exposures.map do |e| 
        #print_debug "Got UNMAPPED Exposure #{et}:\n#{JSON.pretty_generate(e)}" if unmapped 
        map_cloud_exposure_fields(et, e) 
      end

      # convert to KDI 
      result.each do |r|

        create_kdi_asset(r["asset"])
        create_kdi_asset_vuln(r["asset"], r["vuln"])      

        # Normalize
        fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper 
        vd = fm.get_canonical_vuln_details("Expanse", r["vuln_def"])
        
        # Create the vuln def 
        create_kdi_vuln_def(vd)
      end

    end 
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
    when "UNCATEGORIZED" # default a little higher so it's looked at.
      out = 25
    end
  out 
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


end
end
end


