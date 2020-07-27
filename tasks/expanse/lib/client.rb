require 'uri'
require 'csv'

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
    @token && @token.length > 0
  end

  def exposure_types
    url = "https://expander.expanse.co/api/v2/configurations/exposures"
    response_body = RestClient.get(url, @headers)
    result = JSON.parse response_body
  end
    
  def exposure_counts
    url = "https://expander.qadium.com/api/v2/summaries/ip-ports/counts"
    response_body = RestClient.get(url, @headers)
    result = JSON.parse response_body
  end

  def exposures(max_pages=100, limit_per_page=10000)
    return nil unless successfully_authenticated?

    # start with sensible defaults
    offset = 0
    more_results = true 
    out = []

    # hack!
    page = 0

    while more_results && page < max_pages
      puts "DEBUG Getting page: #{page}"
      
      more_results = nil
      page += 1 
      url = "https://expander.qadium.com/api/v2/exposures/ip-ports?limit=#{limit_per_page}&offset=#{offset}"
      response_body = RestClient.get(url, @headers)
      result = JSON.parse response_body

      puts "DEBUG Got #{result["data"].count} exposures."

      # do stuff with the data 
      out.concat(result["data"])

      # prepare the next request
      offset += limit_per_page
      if result["pagination"]
        puts "#{result["pagination"]}"
        more_results = !result["pagination"]["next"].nil?
      else 
        break
      end
    end

  out 
  end

  def cloud_exposure_counts
    url = "https://expander.expanse.co/api/v1/summaries/cloud/counts"
    response_body = RestClient.get(url, @headers)
    result = JSON.parse(response_body)["data"]
  end

  def cloud_exposures(max_pages=100, limit_per_page=10000, limit_types=["ftp-servers"])
    return nil unless successfully_authenticated?

    if limit_types.empty?
      exposure_types = cloud_exposure_types.map{|x| x["type"]}
    else 
      exposure_types = limit_types
    end

    out = []
    exposure_types.each do |exposure_type|

      # start with sensible defaults
      offset = 0
      more_results = true
      page = 0

      while more_results && (page < max_pages)
        
        more_results = nil
        puts "DEBUG Getting page: #{page}"
      
        # bump our page up
        page +=1

        # get the listing 
        url = "https://expander.expanse.co/api/v1/exposures/cloud/#{exposure_type}?page[limit]=#{limit_per_page}&page[offset]=#{offset}"
        response = RestClient.get(url, @headers)
        result = JSON.parse(response.body)
        
        puts "DEBUG Got #{result["data"].count} cloud exposures"

        out.concat(result["data"])

        # prepare the next request
        offset += limit_per_page
        if result["pagination"] 
          puts "#{result["pagination"]}"
          more_results = !result["pagination"]["next"].nil?
        else 
          break
        end

      end # end while more results 
    
    end

  out 
  end

end
end
end
end