module Kenna
   class Api

    def version
      0
    end

    def initialize(api_token, api_host)
      @token = api_token
      @base_url = "https://#{api_host}"
    end

    def get_connectors
      _kenna_api_request(:get, "connectors")
    end

    def get_connector_runs
      _kenna_api_request(:get, "connector_runs")
    end

    def get_asset_groups
      _kenna_api_request(:get, "asset_groups")
    end

    def get_users
      _kenna_api_request(:get, "users")
    end

    def get_roles
      _kenna_api_request(:get, "roles")
    end

    def get_vulns
      _kenna_api_request(:get, "vulnerabilities")
    end

    private

    def _kenna_api_request(method, resource, body=nil)

      headers = { 'X-Risk-Token': "#{@token}" }
      endpoint = "#{@base_url}/#{resource}"

      if method == :get
        
        begin 
          results = RestClient.get endpoint, headers
        rescue RestClient::Forbidden => e
          out = { message: "Access Denied" } 
          return
        end

      elsif method == :post

        begin 
          results = RestClient.post endpoint, body, headers
        rescue RestClient::Forbidden => e
          out = { message: "Access Denied" } 
          return
        end
  
      else 
        # uknown method
        out = { message: "Unknown API method" } 
      end

      begin 
        out = JSON.parse(results)
      rescue
        raise "Unable to parse JSON!"
      end

    out.merge({message: "Success"})
    end


  end
end
