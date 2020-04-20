module Kenna
module Toolkit
module Expanse
module ExposureMapping

def map_exposure_severity(sev_word)
  out = 0
  case sev_word
  when "CRITICAL"
    out = 10
  when "WARNING"
    out = 6
  when "ROUTINE"
    out = 1
  when "UNCATEGORIZED" # default a little higher so it's looked at.
    out = 3
  end
out 
end

def default_exposure_field_mapping(exposure_type)
  {
    'asset' => [  
      { action: "copy", source: "parentDomain", target: "domain" },
      { action: "copy", source: "domain", target: "hostname" },
      { action: "copy", source: "ip", target: "ip_address" },
      #{ action: "proc", target: "tags", proc: lambda{|x| x["tags"] } } # TODO... needs more thought 
    ],
    'vuln' => [
      { action: "proc", target: "scanner_identifier", proc: lambda{|x| "#{exposure_type.downcase}_#{x["id"]}" }},
      { action: "copy", source: "port", target: "port" },
      { action: "proc", target: "scanner_score", proc: lambda{|x| map_exposure_severity(x["severity"]) } },
      { action: "data", target: "scanner_type", data: "Expanse" }
    ],
    'vuln_def' => [
      { action: "proc", target: "scanner_identifier", proc: lambda{|x| "#{exposure_type.downcase}_#{x["id"]}" }},
      { action: "proc", target: "description", proc: lambda{|x| 
        "#{exposure_type.downcase} on port: #{x["port"]}\nFull Details:\n#{JSON.pretty_generate(x)}" } },
      { action: "data", target: "remediation", data: "Investigate this Exposure!" }
    ]
  }
end


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

out 
end


end 
end
end
end