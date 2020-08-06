
module Kenna
module Toolkit
module MSDefenderAtpHelper

  @client_id = nil
  @tenant_id = nil
  @client_secret = nil
  @atp_query_api = nil
  @atp_oath_url = nil
  @token = nil

  def atp_get_machines(page_param=nil)
    print "Getting machines"
    atp_get_auth_token() if @token.nil?
    url = "#{@atp_query_api}/api/machines"
    url = "#{url}?#{page_param}" if !page_param.nil?
    print "url = #{url}"
    begin
      headers = {'Content-Type' => 'application/json', 'Accept' => 'application/json', 'Authorization' => "Bearer #{@token}", 'accept-encoding' => 'identity'}
      response = http_get(url, headers,1)
      if !response.code == 200 then
        response = nil
        raise "unauthorized"
      end
    rescue
      atp_get_auth_token()
      retry
    end
    return nil unless response 

    begin 
      json = JSON.parse(response.body)
    rescue JSON::ParserError => e 
      print_error "Unable to process response!"
    end

    json["value"]
  end
  
  def atp_get_vulns(page_param=nil)
    print "Getting vulns"
    #headers = {'content-type' => 'application/json', 'accept' => 'application/json', 'Authorization' => "Bearer #{@token}", 'accept-encoding' => 'identity'}
    url =  "#{@atp_query_api}/api/vulnerabilities/machinesVulnerabilities"
    url = "#{url}?#{page_param}" if !page_param.nil?
    print "url = #{url}"
    begin
      headers = {'content-type' => 'application/json', 'accept' => 'application/json', 'Authorization' => "Bearer #{@token}", 'accept-encoding' => 'identity'}
      response = http_get(url, headers,1)
      if !response.code == 200 then
        response = nil
        raise "unauthorized"
      end
    rescue
      atp_get_auth_token()
      retry
    end
    return nil unless response 
    
    begin 
      json = JSON.parse(response.body)
    rescue JSON::ParserError => e 
      print_error "Unable to process response!"
    end

    json["value"]
  end
 
  def atp_get_auth_token()
    print "Getting token"
    oauth_url = "#{@atp_oath_url}/#{@tenant_id}/oauth2/token"
    headers = {'content-type' =>  'application/x-www-form-urlencoded'}
    mypayload = {
      "resource" => @atp_query_api, 
      "client_id" => "#{@client_id}", 
      "client_secret" => "#{@client_secret}", 
      "grant_type" => "client_credentials"
    }

    response = http_post(oauth_url, headers, mypayload)
    return nil unless response 

    begin 
      json = JSON.parse(response.body)
    rescue JSON::ParserError => e 
      print_error "Unable to process response!"
    end

    @token = json.fetch("access_token")
  end

  def set_client_data(tenant_id, client_id,secret,atp_query_api,atp_oath_url)
    print "Setting client data"
    @atp_oath_url = atp_oath_url
    @tenant_id = tenant_id
    @client_id = client_id
    @client_secret = secret 
    @atp_query_api = atp_query_api
  end

end
end
end