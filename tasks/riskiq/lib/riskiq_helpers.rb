module Kenna
module Toolkit
module RiskIq

  module Helpers

    def create_self_signed_cert_vuln(asset, cert, first_seen, last_seen)
      
      vuln = {
        "scanner_identifier" => "self_signed_certificate",
        "scanner_type" => "RiskIQ",
        "details" => JSON.pretty_generate(cert),
        #"first_seen" => first_seen,
        #"last_seen" => last_seen,
        "status" => "open"
      }

      vd = {
        "scanner_identifier" => "self_signed_certificate",
        "scanner_type" => "RiskIQ"
      }
      
      create_kdi_asset_vuln(asset, vuln)
      
      vuln_def = @fm.get_canonical_vuln_details("RiskIQ", vd)
      create_kdi_vuln_def(vuln_def)
    end

    def create_open_port_vuln(asset, s, first_seen, last_seen)
      
      port_number = s["port"] if s.kind_of? Hash
      port_number = port_number.to_i
      
      
      unless s["recent"]
        puts "DEBUG skipping unrecent #{s} port"
      end


      ### 
      ### handle http ports differently ... todo, standardize this
      ###
      if port_number == 80 || port_number == 443 || port_number == 8080
        scanner_identifier = "http_open_port"
      else
        scanner_identifier = "other_open_port"
      end

      vuln = {
        "scanner_identifier" => scanner_identifier,
        "scanner_type" => "RiskIQ",
        "details" => JSON.pretty_generate( s.except("banners", "webComponents", "scanMetadata")),
        "port" => port_number,
        #"first_seen" => first_seen,
        #"last_seen" => last_seen,
        "status" => "open"
      }

      puts "Creating assetn+vuln:\n#{asset}\n#{vuln}\n"
      create_kdi_asset_vuln(asset, vuln)


      vd = {
        "scanner_identifier" => scanner_identifier,
        "scanner_type" => "RiskIQ"
      }
      
      vuln_def = @fm.get_canonical_vuln_details("RiskIQ", vd)
      create_kdi_vuln_def(vuln_def)
    end

    def convert_riq_output_to_kdi(data_items)
      output = []
      
      # just return empty array if we weren't handed anything
      return output unless data_items
  
      kdi_initialize

      @fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper 
  
      print_debug "Working on on #{data_items.count} items"
      data_items.each do |item| 
        
        ###
        ### First handle dates (same across all assets)
        ###
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

        ###
        ### First handle tags (same across all assets)
        ###
        tags = ["RiskIQ"]
        if item["tags"]
          tags = tags.concat(item["tags"].map{|x| x["name"] })
        end

        ###
        ### Always set External ID
        ###
        id = item["id"]

        ###
        ### Handle Assets by type
        ###
        if item["type"] == "HOST" || item["type"] == "PAGE"

          # Hostname
          begin
            hostname = URI.parse(item["name"]).hostname
            hostname = item["hosts"].first if !hostname && item["hosts"] && !item["hosts"].empty?
            hostname = item["name"] unless hostname
          rescue URI::InvalidURIError => e
            hostname = nil
          end
        
          # get ip address
          if item["asset"] && (item["asset"]["ipAddress"] || (item["asset"]["ipAddresses"] && item["asset"]["ipAddresses"].first))
            # TODO - we should pull all ip addresses when we can support it in KDI 
            ip_address = item["asset"]["ipAddresses"].first["value"] 
            ip_address = item["asset"]["ipAddress"] unless ip_address
          end

          # create base asset, then optional identifiers
          asset = { 
            #"first_seen" => "#{first_seen}",
            #"last_seen" => "#{last_seen}",
            "tags" => tags
          }
          asset["external_id"] = "#{id}" if id
          asset["hostname"] = "#{hostname}" if hostname
          asset["ip_address"] = "#{ip_address}" if ip_address

          create_kdi_asset(asset)
        
          if "#{hostname}".empty? && "#{ip_address}".empty? && "#{id}".empty? 
            print_error "UKNOWN item: #{item}"
          end

        elsif item["type"] == "IP_ADDRESS"

          asset = { 
            "ip_address" => "#{item["name"]}",
            #"first_seen" => "#{first_seen}",
            #"last_seen" => "#{last_seen}",
            "tags" => tags
          }
          asset["external_id"] = "#{id}" if id

          # Only create the asset if we have open services on it (otherwise it'll just be an empty asset)
          create_kdi_asset(asset) if item["asset"]["services"] && item["asset"]["services"].count > 0

        elsif item["type"] == "SSL_CERT"

          # grab the sha
          sha_name = item["name"]

          # grab a hostname
          hostname = item["asset"]["subjectAlternativeNames"].first if item["asset"] && item["asset"]["subjectAlternativeNames"]
          hostname = item["asset"]["subject"]["common_name"] if item["asset"] && item["asset"]["subject"] && !hostname
          hostname = item["asset"]["issuer"]["common_name"] if item["asset"] && item["asset"]["issuer"] && !hostname
          hostname = "unknown host, unable to get from the certificate" unless hostname

          asset = { 
            "hostname" => "#{hostname}",
            "external_id" => "#{sha_name}",
            #"first_seen" => "#{first_seen}",
            #"last_seen" => "#{last_seen}",
            "tags" => tags
          }
          asset["external_id"] = "#{id}" if id
          
          #  ... only create the asset if we have a self-signed cert
          if item["asset"]["selfSigned"]
            create_kdi_asset(asset)
            create_self_signed_cert_vuln(asset, item, first_seen, last_seen)
          end
          
        else
          raise "Unknown / unmapped type: #{item["type"]} #{item}"
        end

        ###
        ### Handle Vuln / Vuln DEF
        ###

        ###
        ### Get the open port out of services
        ###
        if @riq_create_open_ports
          if item["asset"]["services"]
            if (item["asset"]["services"].count > 1200) && @riskiq_limit_spurious_ports
              puts "TOO MANY OPEN PORTS on #{item["name"]}, SKIPPING!"
              next
            else
              (item["asset"]["services"] || []).uniq.each do |serv|
                create_open_port_vuln(asset, serv, first_seen, last_seen)
              end
            end
          end
        end
  
        ###
        ### Get the CVES out of web components
        ###
        if @riq_create_cves
          if item["asset"]["webComponents"]
            (item["asset"]["webComponents"] || []).each do |wc|
    
              # default to derived if no port specified
              derived_port = "#{item["asset"]["service"]}".split(":").last

              # if you want to create open ports, we need to infer the port from the service
              # in addition to whatever else we've gotten
              (wc["ports"] << derived_port).uniq.compact.each do |port|
      
                if port.kind_of? Hash
                  port = port["port"]
                end

                # if you want to create open ports
                (wc["cves"] || []).uniq.each do |cve| 

                  vuln = {
                    "scanner_identifier" => "#{cve["name"]}",
                    "scanner_type" => "RiskIQ",
                    "port" => port.to_i,
                    #"first_seen" => first_seen,
                    #"last_seen" => last_seen,
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
end
end
