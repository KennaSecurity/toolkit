module Kenna 
module Toolkit
class InspectApiToken < Kenna::Toolkit::BaseTask

  def metadata 
      {
        id: "inspect_api_token",
        name: "Inspect API Token",
        description: "This task pulls results from AWS inspector and translates them into JSON",
        options: [
          {:name => "kenna_api_token", 
            :type => "api_key", 
            :required => true, 
            :default => nil, 
            :description => "Kenna API Key" },
          {:name => "kenna_api_host", 
            :type => "hostname", 
            :required => false  , 
            :default => "api.kennasecurity.com", 
            :description => "Kenna API Hostname" }
        ]
      }
  end

  def run(opts)
    super # opts -> @options
    
    api_host = @options[:kenna_api_host]
    api_token = @options[:kenna_api_token]

    # TODO. ... handled upstream?
    unless api_host && api_token
      print_error "Cannot proceed, missing required options"
      return
    end

    api_client = Kenna::Api.new(api_token, api_host)
    

    print_good
    print_good "Connectors: #{api_client.get_connectors["connectors"].count}"
    #print_good "Connector Runs: #{api_client.get_connector_runs["connector_runs"].count}"
    print_good "Users: #{api_client.get_users["users"].count}"
    print_good "Roles: #{api_client.get_roles["roles"].count}"
    print_good "Asset Groups: #{api_client.get_asset_groups["asset_groups"].count}"
    print_good "Vulns: #{api_client.get_vulns["vulnerabilities"].count}"
    print_good

  end


end
end
end
