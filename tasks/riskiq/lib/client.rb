require 'date'
require 'base64'

module Kenna
module Toolkit
module RiskIq

class Client

  def initialize(api_key, api_secret)
    @api_url = "https://api.riskiq.net/v1/"

    raise "Bad key?" unless api_key && api_secret

    creds = "#{api_key}:#{api_secret}"
    token = Base64.strict_encode64(creds)
    @headers = {
      "Authorization" => "Basic #{token}", 
      "Content-Type" => "application/json"
    }
  end

  def successfully_authenticated?
    true # TODO ... let's sort 
  end
 
  ##
  def footprint_query 
    json_search_query = '{
      "filters": {
        "condition": "AND",
          "value": [
            {
                "name": "type",
                "operator": "EQ",
                "value": "PAGE"
            },
            {
                "name": "state",
                "operator": "EQ",
                "value": "CONFIRMED"
            },
            {
                "name": "cvssScore",
                "operator": "NOT_NULL",
                "value": true
            }
          ]
        }
    }'
  end

  def get_global_footprint(max_pages=-1)
    # start with sensible defaults
    current_page = 1
    out = []

    while current_page <= max_pages || max_pages == -1
      #puts "DEBUG Getting page: #{current_page} / #{max_pages}"

      endpoint = "#{@api_url}/globalinventory/search?page=#{current_page}&size=100"
  
      begin

        response = RestClient::Request.execute({
          method: :post,
          url: endpoint,
          payload: footprint_query,
          headers: @headers
        })

        ###
        ### uncomment to save pages of output
        ###
        #debug_out = "/tmp/riq_response_page_#{current_page}.json"
        # puts "DEBUG: Writing #{debug_out}"
        # File.open(debug_out, "w") do |f|
        #   f.puts "#{response.body}"
        # end
        result = JSON.parse(response.body)

      rescue RestClient::InternalServerError => e 
        puts "Error making request - server 500?!"
        return nil 
      rescue RestClient::ServerBrokeConnection => e 
        puts "Error making request - server dropped us?!"
        return nil 
      rescue RestClient::NotFound => e 
        puts "Error making request - bad endpoint?!"
        return nil 
      rescue RestClient::BadRequest => e 
        puts "Error making request - bad creds?!"
        return nil 
      rescue JSON::ParserError => e 
        puts "Error parsing json!"
        return nil 
      end

      # do stuff with the data 
      out.concat(result["content"])

      # prepare the next request
      if max_pages == -1
        puts "DEBUG Total Pages: #{result["totalPages"]}"
        max_pages = result["totalPages"].to_i
      end

      current_page +=1
    end

  out 
  end
end

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
        "tags" => tags.concat(organizations)
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
              "first_seen" => first_seen,
              "last_seen" => last_seen
            }

            vuln_def= {
              "scanner_identifier" => "#{cve["name"]}",
              "scanner_type" => "RiskIQ",
              "cve_identifiers" => "#{cve["name"]}"
              #"description" => "See CVE Description",
              #"solution" => "See CVE Remediation"
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
