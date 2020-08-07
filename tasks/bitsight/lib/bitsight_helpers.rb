module Kenna
module Toolkit
module BitsightHelpers

  def get_bitsight_findings_and_create_kdi(bitsight_api_key, my_company_guid, max_findings=1000000)
    findings = []
    # then get the assets for it 
    #my_company = result["companies"].select{|x| x["guid"] == my_company_guid}
    more_findings = true
    offset = 0 
    limit = 100
    
    while more_findings && (offset < max_findings)
    
      endpoint = "https://api.bitsighttech.com/ratings/v1/companies/#{my_company_guid}/findings?limit=#{limit}&offset=#{offset}"
    
      print_good "Requesting: #{endpoint}"

      response = RestClient::Request.new(
        :method => :get,
        :url => endpoint,
        :user => bitsight_api_key,
        :password => "",
        :headers => { :accept => :json, :content_type => :json }
      ).execute

      result = JSON.parse(response.body)

      # do the right thing with the findings here 
      result["results"].each do |finding|
        #puts "DEBUG finding: #{finding}\n"
        _add_finding_to_working_kdi(finding)
      end
      
      # check for more 
      endpoint = result["links"]["next"]
      more_findings = endpoint && endpoint.length > 0

      if more_findings && endpoint =~ /0.0.0.0/
        print_error "WARNING: endpoint is not well formed, doing a gsub on: #{endpoint}"
        endpoint.gsub!("https://0.0.0.0:8000/customer-api/", "https://api.bitsighttech.com/")
      end

      # bump the offset
      offset = offset + limit

    end
  end

  def get_my_company(bitsight_api_key)
    # First get my company
    response = RestClient.get("https://#{bitsight_api_key}:@api.bitsighttech.com/portfolio")
    portfolio = JSON.parse(response.body)
  my_company_guid = portfolio["my_company"]["guid"]
  end

  def valid_bitsight_api_key?(bitsight_api_key)
    
    endpoint = "https://api.bitsighttech.com/"
    begin 
      response = RestClient::Request.new(
        :method => :get,
        :url => endpoint,
        :user => bitsight_api_key,
        :password => "",
        :headers => { :accept => :json, :content_type => :json }
      ).execute
      result = JSON.parse(response.body)
      result.has_key? "disclaimer"
    rescue RestClient::Unauthorized => e 
      return false
    end
  end
  
  def get_bitsight_assets_for_company(bitsight_api_key, my_company_guid)
    
    # then get the assets for it 
    #my_company = result["companies"].select{|x| x["guid"] == my_company_guid}
    endpoint = "https://api.bitsighttech.com/ratings/v1/companies/#{my_company_guid}/assets/statistics"
    response = RestClient::Request.new(
      :method => :get,
      :url => endpoint,
      :user => bitsight_api_key,
      :password => "",
      :headers => { :accept => :json, :content_type => :json }
    ).execute
    result = JSON.parse(response.body)

  result["assets"].map{|x| x["asset"] }  
  end

  private 

  def _add_finding_to_working_kdi(finding)

    vuln_def_id = "#{finding["risk_vector_label"]}".gsub(" ", "_").gsub("-", "_").downcase
    
    finding["assets"].each do |a|

      asset_name = a["asset"]
      default_tags = ["Bitsight"]

      if a["is_ip"] # TODO ... keep severity  ]
        asset_attributes = {:ip_address => asset_name, :tags => default_tags }
      else 
        asset_attributes = {:hostname => asset_name, :tags => default_tags}
      end

      create_kdi_asset(asset_attributes) 

      # then create each vuln for this asset
      vuln_attributes = {
        "scanner_identifier" => "#{vuln_def_id}",
        "scanner_type" => "Bitsight",
        "scanner_score" => finding["severity"].to_i,  # TODO # severity, severity_category
        "details" => "#{finding["risk_vector_label"]}\n\nFull Details:\n#{JSON.pretty_generate(finding)}",
        "created_at" => finding["first_seen"],
        "last_seen_at" => finding["last_seen"]
      }
      
      # def create_kdi_asset_vuln(asset_id, asset_locator, args)
      create_kdi_asset_vuln(asset_attributes, vuln_attributes)
    end

    ## TODO.. parse out cve here

    vuln_def_attributes = {
      "scanner_identifier" => "#{vuln_def_id}",
      "scanner_type" => "Bitsight",
      "name" => "#{vuln_def_id}"
    }
    
    ###
    ### Put them through our mapper 
    ###
    fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper 
    vd = fm.get_canonical_vuln_details("Bitsight", vuln_def_attributes)
    cvd = create_kdi_vuln_def(vd)
  end

  

end
end
end