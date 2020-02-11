module Kenna
module Toolkit
module Expanse
class Client

  def initialize(api_key)
    url = "https://expander.qadium.com/api/v1/idtoken"
    response = RestClient.get(url, {:Authorization => "Bearer #{api_key}"})
    @token = JSON.parse(response.body)["token"]
    @headers = {:Authorization => "JWT #{@token}"}
  end

  def successfully_authenticated?
    @token.length > 0
  end

  def exposures
    return nil unless successfully_authenticated?

    # start with sensible defaults
    offset = 0
    limit = 1000
    more_results = true 
    out = []

    while more_results
      url = "https://expander.qadium.com/api/v2/configurations/exposures?limit=#{limit}&offset=#{offset}"
      response_body = RestClient.get(url, @headers )
      result = JSON.parse response_body

      # do stuff with the data 
      print_good "Got #{result["data"].count} results"
      out.concat(result["data"])

      # prepare the next request
      offset += limit
      if result["pagination"]
        more_results = result["pagination"]["next"]
      else 
        more_results = false
      end
    end

  out 
  end

  def open_ports
    return nil unless successfully_authenticated?

    # start with sensible defaults
    offset = 0
    limit = 1000
    more_results = true 
    out = []

    while more_results
      url = "https://expander.qadium.com/api/v2/exposures/ip-ports?limit=#{limit}&offset=#{offset}"
      response_body = RestClient.get(url, @headers )
      result = JSON.parse response_body

      # do stuff with the data 
      print_good "Got #{result["data"].count} results"
      out.concat(result["data"])

      # prepare the next request
      offset += limit
      if result["pagination"]
        more_results = result["pagination"]["next"]
      else 
        more_results = false
      end
    end
  out 
  end

end
end
end
end