
module Kenna
module Toolkit
module MicrosoftAtpHelper

  def atp_get_machines(token)
    print "Getting machines"
    headers = {'Content-Type' => 'application/json', 'Accept' => 'application/json', 'Authorization' => "Bearer #{token}", 'accept-encoding' => 'identity'}
    url = "https://api.securitycenter.microsoft.com/api/machines"
    
    response = http_get(url, headers)
    return nil unless response 

    begin 
      json = JSON.parse(response.body)
    rescue JSON::ParserError => e 
      print_error "Unable to process response!"
    end

  json["value"]
  end
  
  def atp_get_vulns(token,machine_id)
    print "Getting vulns for machine #{machine_id}"
    atp_query_api = "https://api.securitycenter.microsoft.com/"
    headers = {'content-type' => 'application/json', 'accept' => 'application/json', 'Authorization' => "Bearer #{token}", 'accept-encoding' => 'identity'}
    url =  "#{atp_query_api}/api/machines/#{machine_id}/vulnerabilities"
    
    response = http_get(url, headers)
    return nil unless response 
    
    begin 
      json = JSON.parse(response.body)
    rescue JSON::ParserError => e 
      print_error "Unable to process response!"
    end

  json["value"]
  end
 
  def atp_get_auth_token(tenant_id, client_id,secret)
    print "Getting token"
    atp_query_api = "https://api.securitycenter.microsoft.com/"
    oauth_url = "https://login.windows.net/#{tenant_id}/oauth2/token"
    headers = {'content-type' =>  'application/x-www-form-urlencoded'}
    mypayload = {
      "resource" => atp_query_api, 
      "client_id" => "#{client_id}", 
      "client_secret" => "#{secret}", 
      "grant_type" => "client_credentials"
    }

    response = http_post(oauth_url, headers, mypayload)
    return nil unless response 

    begin 
      json = JSON.parse(response.body)
    rescue JSON::ParserError => e 
      print_error "Unable to process response!"
    end

  json.fetch("access_token")
  end

end
end
end