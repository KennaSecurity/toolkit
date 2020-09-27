require_relative 'cloud_exposure_mapping'
require_relative 'standard_exposure_mapping'

module Kenna
module Toolkit
module Expanse
module Mapper

  include Kenna::Toolkit::KdiHelpers
  include Kenna::Toolkit::Expanse::CloudExposureMapping
  include Kenna::Toolkit::Expanse::StandardExposureMapping

  #
  # this method does the actual mapping, as specified
  # in the field_mapping_by_type method
  def map_exposure_fields(cloud, exposure_type, exposure)
    
    if cloud 
      # grab the relevant mapping
      mapping_areas = default_exposure_field_mapping(exposure_type).deep_merge(
        field_mapping_for_cloud_exposures[exposure_type]) # asset, vuln, vuln_def
    else
      # grab the relevant mapping
      mapping_areas = default_exposure_field_mapping(exposure_type).deep_merge(
        field_mapping_for_standard_exposures[exposure_type]) # asset, vuln, vuln_def
    end
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

    # always set our exposure type... this should save some typing in the mapping file... 
    out["vuln"]["scanner_identifier"] = exposure_type
    out["vuln_def"]["scanner_identifier"] = exposure_type

  out 
  end

  def create_kdi_from_exposures(max_pages = 100, max_per_page = 10000)
    print "Getting exposures from Expanse"

    exposures = @client.exposures(max_pages,max_per_page)

    # skip if we don't have any 
    unless exposures.count > 0 #skip empty
      print  "No exposures found!"
      return 
    end

    # parse and create kdi 
    #print "Mapping #{exposures.count} exposures"
    result = exposures.map do |e|
      #print "Mapping #{e}"
      # map fields for those expsures
      map_exposure_fields(false, e["exposureType"], e) 
    end

    
    fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper 

    # Create KDI
    result.each do |r|

      vuln_def_id = "#{r["vuln_def"]["scanner_identifier"]}".downcase.gsub("-","_").gsub(" ","_")
    
      # Get the normalized info
      vd = { "scanner_identifier" => vuln_def_id}
      cvd = fm.get_canonical_vuln_details("Expanse", vd )

      # create the asset 
      create_kdi_asset(r["asset"])
      
      ### Setup basic vuln attributes
      vuln_attributes =  {
        "scanner_identifier" => "#{vuln_def_id}",
        "created_at" => r["vuln"]["created_at"],
        "last_seen_at" => r["vuln"]["last_seen_at"],
        "scanner_type" => "Expanse",
        "port" => r["vuln"]["port"],
        "details" => r["vuln"]["details"],
        "status" => "open"
      }

      ### Set Scores based on what was available in the CVD
      if cvd["scanner_score"]
        vuln_attributes["scanner_score"] = cvd["scanner_score"]
      end

      if cvd["override_score"]
        vuln_attributes["override_score"] = cvd["override_score"]
      end

      # Create the vuln
      create_kdi_asset_vuln(r["asset"], vuln_attributes)      

      # Create the vuln def 
      print_debug "Creating vuln def from #{cvd}"
      create_kdi_vuln_def(cvd)
    end

  end

  def create_kdi_from_cloud_exposures(max_pages = 100, max_per_page = 10000)
   
    ### 
    ### Get the list of exposure types
    ###
    if @options && @options[:cloud_exposure_types]
      cloud_exposure_types = "#{@options[:cloud_exposure_types]}".downcase.gsub("-","_")
    else
      cloud_exposure_counts = @client.cloud_exposure_counts
      cloud_exposure_types = cloud_exposure_counts.map{|x| "#{x["type"]}".downcase.gsub("-","_") }
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

      print_good "Working on cloud exposure: #{et}!"
      cloud_exposures = @client.cloud_exposures(max_pages,max_per_page,[et])
      print_good "Got #{cloud_exposures.count} cloud exposures of type #{et}"

      # skip if we don't have any 
      unless cloud_exposures.count > 0 #skip empty
        print_debug "No cloud exposures of type #{et} found!"
        next
      end

      # map fields for those expsures
      print "Mapping #{cloud_exposures.count} cloud exposures"
      result = cloud_exposures.map do |e| 
        #print "Mapping #{e}"
        #print_debug "Got UNMAPPED Exposure #{et}:\n#{JSON.pretty_generate(e)}" if unmapped 
        map_exposure_fields(true, et, e) 
      end
      print_good "Mapped #{result.count} cloud exposures"

      # convert to KDI 
      fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper 
      result.each do |r|

        # NORMALIZE 
        vuln_def_id = "#{r["vuln_def"]}".downcase.gsub("-","_").gsub(" ","_")
        cvd = fm.get_canonical_vuln_details("Expanse", {"scanner_identifier" => vuln_def_id} )

        create_kdi_asset(r["asset"])

        ### Setup basic vuln attributes
        vuln_attributes =  r["vuln"]

        ### Set Scores based on what was available in the CVD
        if cvd["scanner_score"]
          vuln_attributes["scanner_score"] = cvd["scanner_score"]
        end

        if cvd["override_score"]
          vuln_attributes["override_score"] = cvd["override_score"]
        end

        # Create the vuln
        create_kdi_asset_vuln(r["asset"], vuln_attributes)

        # Create the vuln def 
        #print_debug "Creating vuln def from #{cvd}"
        create_kdi_vuln_def(cvd)
      end

    end 
  end


  def map_exposure_severity(sev_word)
    out = 0
    case sev_word
    when "CRITICAL"
      out = 10
    when "WARNING"
      out = 6
    when "ROUTINE"
      out = 1
    when "UNCATEGORIZED" # unknown
      out = 0
    end
  out 
  end

  def default_exposure_field_mapping(exposure_type)
    {
      'asset' => [  
        { action: "copy", source: "parentDomain", target: "domain" },
        { action: "copy", source: "domain", target: "hostname" },
        { action: "copy", source: "ip", target: "ip_address" },
        { action: "data", target: "tags", data: ["Expanse"] } # TODO... needs more thought 
      ], 
      'vuln' => [
        { action: "proc", target: "scanner_identifier", proc: lambda{|x| "#{exposure_type.downcase}" }},
        { action: "proc", target: "created_at", proc: lambda{|x| x["firstObservation"]["scanned"] }},
        { action: "proc", target: "last_seen_at", proc: lambda{|x| x["lastObservation"]["scanned"] }},
        { action: "copy", target: "port", source: "portNumber" },
        { action: "proc", target: "details", proc: lambda{|x| JSON.pretty_generate(x)  } },
        #{ action: "proc", target: "scanner_score", proc: lambda{|x| map_exposure_severity(x["severity"]) } },
        { action: "data", target: "scanner_type", data: "Expanse" }
      ],
      'vuln_def' => [
        { action: "data", target: "scanner_type", data: "Expanse" },
        { action: "proc", target: "scanner_identifier", proc: lambda{|x| "#{exposure_type.downcase}" }},
        { action: "data", target: "remediation", data: "Investigate this Exposure!" }
      ]
    }
  end



end 
end
end
end