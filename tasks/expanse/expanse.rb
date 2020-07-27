# expanse client 
require_relative 'lib/client'

# cloud exposure field mapping
require_relative 'lib/mapper'
require_relative 'lib/cloud_exposure_mapping'
require_relative 'lib/standard_exposure_mapping'

module Kenna 
module Toolkit
class ExpanseTask < Kenna::Toolkit::BaseTask

  include Kenna::Toolkit::Expanse::Mapper
  include Kenna::Toolkit::Expanse::CloudExposureMapping
  include Kenna::Toolkit::Expanse::StandardExposureMapping

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
        { :name => "include_exposures", 
          :type => "boolean", 
          :required => false, 
          :default => true, 
          :description => "Pull and parse normal exposure types" },
        { :name => "include_cloud_exposures", 
          :type => "boolean", 
          :required => false, 
          :default => true, 
          :description => "Pull and parse cloud exposure types" },
        { :name => "cloud_exposure_types", 
          :type => "string", 
          :required => false, 
          :default => "", 
          :description => "Comma-separated list of cloud exposure types. If not set, all exposures will be included" },
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
          :default => "output/expanse", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
        ]
    }
  end

  def run(options)
    super

    # Get options
    kenna_api_host = @options[:kenna_api_host]
    kenna_api_key = @options[:kenna_api_key]
    kenna_connector_id = @options[:kenna_connector_id]
    expanse_api_key = @options[:expanse_api_key]

    # create an api client
    @expanse = Kenna::Toolkit::Expanse::Client.new(expanse_api_key)
      
    @assets = []
    @vuln_defs = []

    # verify we have a good key before proceeding
    unless @expanse.successfully_authenticated?
      print_error "Unable to proceed, invalid key for Expanse?"
      return 
    end
    print_good "Valid key, proceeding!"

    ######
    # Handle normal exposures
    ######
    if @options[:include_exposures]
      print_good "Working on normal exposures"
      create_kdi_from_exposures
    end

    ####
    # Handle cloud exposures
    ####
    if @options[:include_cloud_exposures]
      print_good "Working on cloud exposures"
      create_kdi_from_cloud_exposures
    end
   
    ####
    # Write KDI format
    ####
    kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
    output_dir = "#{$basedir}/#{@options[:output_directory]}"
    filename = "expanse.kdi.json"
    
    # actually write it 
    write_file output_dir, filename, JSON.pretty_generate(kdi_output)
    print_good "Output is available at: #{output_dir}/#{filename}"

    ####
    ### Finish by uploading if we're all configured
    ####
    if kenna_connector_id && kenna_api_host && kenna_api_key
      print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
      upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
    end

  end    

  def create_kdi_from_exposures
    print "Getting exposures from Expanse"
    
    if @options[:debug]
      max_pages = 1 
      max_per_page = 1
      print_debug "Debug mode, override max to: #{max_pages * max_per_page}"
    else 
      max_pages = 100
      max_per_page = 10000
    end

    exposures = @expanse.exposures(max_pages,max_per_page)

    # skip if we don't have any 
    unless exposures.count > 0 #skip empty
      print  "No exposures found!"
      return 
    end

    # parse and create kdi 
    print "Mapping #{exposures.count} exposures"
    result = exposures.map do |e|
      print "Mapping #{e}"
      # map fields for those expsures
      map_exposure_fields(false, e["exposureType"], e) 
    end

    # convert to KDI 
    fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper 
    result.each do |r|

      create_kdi_asset(r["asset"])
      create_kdi_asset_vuln(r["asset"], r["vuln"])      

      # Normalize
      vd = fm.get_canonical_vuln_details("Expanse", r["vuln_def"].compact)
      
      # set scanner type
      vd["scanner_type"] = "Expanse"
      
      # Create the vuln def 
      create_kdi_vuln_def(vd)
    end
    
  end

  def create_kdi_from_cloud_exposures
   
    ### 
    ### Get the list of exposure types
    ###
    if @options[:cloud_exposure_types]
      cloud_exposure_types = @options[:cloud_exposure_types]
    else
      cloud_exposure_counts = @expanse.cloud_exposure_counts
      cloud_exposure_types = cloud_exposure_counts.map{|x| x["type"] }
    end
  
    ###
    ### For each exposure type
    ###
    cloud_exposure_types.sort.each do |et|

      unmapped = false
      unless field_mapping_for_cloud_exposures[et]
        print_error "Skipping unmapped exposure type: #{et}!"
        unmapped = true 
        next
      end
    
      # get all exposures of this type
      max_pages = 100
      max_per_page = 10000

      if @options[:debug]
        max_pages = 1 
        max_per_page = 1
        print_debug "Debug mode, override max to: #{max_pages * max_per_page} for #{et}"
      end

      print_good "Working on cloud exposure: #{et}!"
      cloud_exposures = @expanse.cloud_exposures(max_pages,max_per_page,[et])
      print_good "Got #{cloud_exposures.count} cloud exposures of type #{et}"

      # skip if we don't have any 
      unless cloud_exposures.count > 0 #skip empty
        print_debug "No cloud exposures of type #{et} found!"
        next
      end

      # map fields for those expsures
      print "Mapping #{cloud_exposures.count} cloud exposures"
      result = cloud_exposures.map do |e| 
        print "Mapping #{e}"
        #print_debug "Got UNMAPPED Exposure #{et}:\n#{JSON.pretty_generate(e)}" if unmapped 
        map_exposure_fields(true, et, e) 
      end
      print_good "Mapped #{result.count} cloud exposures"

      # convert to KDI 
      result.each do |r|
        print_good "Getting #{r["asset"]}"

        create_kdi_asset(r["asset"])
        create_kdi_asset_vuln(r["asset"], r["vuln"])      

        # Normalize
        fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper 
        vd = fm.get_canonical_vuln_details("Expanse", r["vuln_def"].compact)
        
        # set scanner type
        vd["scanner_type"] = "Expanse"
        
        # Create the vuln def 
        create_kdi_vuln_def(vd)
      end

    end 
  end

end
end
end


