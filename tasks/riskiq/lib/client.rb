require 'base64'

module Kenna
module Toolkit
module RiskIq
class Client

  def initialize(url, api_key, api_secret)
    @api_url = url || 'https://ws.riskiq.net/v1'
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
  ##{
  ##  "name": "cvssScore",
  ##  "operator": "NOT_NULL",
  ##  "value": true
  ##}
  ##
  def footprint_query 
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
        }]
      }
    }'
  end

  def get_global_footprint(max_pages=-1)
    # start with sensible defaults
    current_page = 1
    out = []

    while current_page <= max_pages || max_pages == -1
      puts "DEBUG Getting page: #{current_page} / #{max_pages}"

      endpoint = "#{@api_url}/globalinventory/search?page=#{current_page}&size=1000"
  
      begin 
        response = RestClient::Request.execute({
          method: :post,
          url: endpoint,
          payload: footprint_query,
          headers: @headers
        })

        result = JSON.parse(response.body)

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
end
end
end