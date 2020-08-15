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
        sleep rand(10)
      rescue RestClient::ServerBrokeConnection => e 
        puts "Error making request - server dropped us?!"
        sleep rand(10)
      rescue RestClient::NotFound => e 
        puts "Error making request - bad endpoint?!"
      rescue RestClient::BadRequest => e 
        puts "Error making request - bad creds?!"
      rescue JSON::ParserError => e 
        puts "Error parsing json!"
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
