require 'base64'

module Kenna
module Toolkit
module RiskIq
class Client

  def initialize(url, api_key, api_secret)
    @api_url = url || 'https://ws.riskiq.net/v1'
    @token = Base64.encode64("#{api_key}:#{api_secret}")
    @headers = {
      "Authorization" => "Basic #{@token}", 
      "Content-Type" => "application/json"
    }
  end

  def successfully_authenticated?
    return true if @endpoint && @token # TODO - improve this 
  false 
  end

  def footprint
    json_search_query = '{
      "filters": {
        "condition": "AND",
        "value": [{
          "name": "type",
          "operator": "EQ",
          "value": "HOST"
        }, {
          "name": "state",
          "operator": "EQ",
          "value": "CONFIRMED"
        }, {
          "name": "cvssScore",
          "operator": "NOT_NULL",
          "value": true
        }]
      }
    }'
  

    # start with sensible defaults
    current_page = 1
    total_pages = 1
    out = []

    while current_page <= total_pages
      endpoint = "#{@api_url}/globalinventory/search?page=#{current_page}&size=1000"

      response = RestClient::Request.execute(
        method: :post,
        url: endpoint,
        payload: json_search_query,
        headers: @headers
       )

      result = JSON.parse(response.body)

      # do stuff with the data 
      out.concat(result["content"])

      # prepare the next request
      total_pages = result["totalPages"].to_i
      current_page +=1
    end

  out 
  end


end
end
end
end