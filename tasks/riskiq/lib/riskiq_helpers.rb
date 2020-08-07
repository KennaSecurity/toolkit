module Kenna
module Toolkit
module RiskIq

  module Helpers

    def convert_riq_output_to_kdi(data_items)
      output = []
      
      # just return empty array if we weren't handed anything
      return output unless data_items
  
      fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper 
  
      print_debug "Working on on #{data_items.count} items"
      data_items.each do |item| 
        ###
        ### Handle Asset, note, host was used in the past, but now 
        ### page is the way to go 
        ###
        if item["type"] == "HOST" || item["type"] == "PAGE"
  
          id = item["id"]
          hostname = URI.parse(item["name"]).hostname
  
          # Note that the docs appear wrong here: 
          # https://api.riskiq.net/api/concepts.html
  
          ## 
          ## Setting firstSeen/lastSeen to now
          ##
          first_seen = Time.now.utc
          last_seen = Time.now.utc
  
          # if item["lastSeen"]
          #   last_seen = Date.iso8601("#{item["lastSeen"]}")
          # else 
          #   last_seen = Date.iso8601("#{item["createdAt"]}","%s").to_s
          # end
  
          #if item["firstSeen"]
          #   first_seen = Date.iso8601("#{item["firstSeen"]}","%s").to_s
          # else 
          #   first_seen = Date.iso8601("#{item["createdAt"]}","%s").to_s
          # end
  
          tags = []
          tags = item["tags"].map{|x| x["name"]} if item["tags"]
  
          organizations = []
          organizations = item["organizations"].map{|x| x["name"]} if item["organizations"]
        
          if item["asset"] && item["asset"]["ipAddresses"] && item["asset"]["ipAddresses"].first
            # TODO - we should pull all ip addresses when we can support it in KDI 
            ip_address = item["asset"]["ipAddresses"].first["value"] 
          end
          
        else
          raise "Unknown / unmapped type: #{item["type"]} #{item}"
        end
        
        asset = { 
          "hostname" => "#{hostname}",
          "ip_address" => "#{ip_address}",
          "external_id" => "#{id}",
          #"first_seen" => "#{first_seen}",
          #"last_seen" => "#{last_seen}",
          "tags" => ["RiskIQ"]
        }
        create_kdi_asset(asset)
        
        ###
        ### Handle Vuln / Vuln DEF
        ###
  
        ###
        ### Get the CVES out of web components
        ###
        if item["asset"]["webComponents"]
          (item["asset"]["webComponents"] || []).each do |wc|
  
            # if you want to create open ports
            #wc["ports"].each do |port|
            #  puts port["port"]
            #end
  
            # if you want to create open ports
            (wc["cves"] || []).each do |cve| 
              
              vuln = {
                "scanner_identifier" => "#{cve["name"]}",
                "scanner_type" => "RiskIQ",
                "details" => JSON.pretty_generate(wc),
                "first_seen" => first_seen,
                "last_seen" => last_seen,
                "status" => "open"
              }
  
              vuln_def= {
                "scanner_identifier" => "#{cve["name"]}",
                "scanner_type" => "RiskIQ",
                "cve_identifiers" => "#{cve["name"]}"
              }
              
              create_kdi_asset_vuln(asset, vuln)
              
              #vd = fm.get_canonical_vuln_details("RiskIQ", vuln_def)
              create_kdi_vuln_def(vuln_def)
            end
  
          end
        end
      end
    end
  end


end
end
end
