module Kenna 
module Toolkit
class InspectApiToken < Kenna::Toolkit::BaseTask

  def self.metadata 
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
    #unless api_host && api_token
    #  print_error "Cannot proceed, missing required options"
    #  return
    #end

    api_client = Kenna::Api.new(api_token, api_host)

    # get connectors
    response = api_client.get_connectors
    if response[:status] == "success"
      print_good "Connectors: #{response[:results]["connectors"].count}"
    else 
      print_error "Connectors: #{response[:message]}"
    end

    # get users
    response = api_client.get_users
    if response[:status] == "success"
      print_good "Users: #{response[:results]["users"].count}"
    else 
      print_error "Users: #{response[:message]}"
    end
    
    # get roles
    response = api_client.get_roles
    if response[:status] == "success"
      print_good "Roles: #{response[:results]["roles"].count}"
    else 
      print_error "Roles: #{response[:message]}"
    end

    # get asset groups
    response = api_client.get_asset_groups
    if response[:status] == "success"
      print_good "Asset Groups: #{response[:results]["asset_groups"].count}"
    else 
      print_error "Asset_Groups: #{response[:message]}"
    end

    # get vulns
    response = api_client.get_vulns
    if response[:status] == "success"
      print_good "Vulns: #{response[:results]["vulnerabilities"].count}"
    else 
      print_error "Vulns: #{response[:message]}"
    end

  end


end
end
end
