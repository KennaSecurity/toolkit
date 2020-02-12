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
      response_body = RestClient.get(url, @headers)
      result = JSON.parse response_body

      # do stuff with the data 
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

  def cloud_exposure_types
    url = "https://expander.expanse.co/api/v1/summaries/cloud/counts"
    response_body = RestClient.get(url, @headers)
    result = JSON.parse(response_body)["data"]
  end

  def cloud_exposures(limit_types=["ftp-servers"])
    return nil unless successfully_authenticated?

    if limit_types.empty?
      exposure_types = cloud_exposure_types.map{|x| x["type"]}
    else 
      exposure_types = limit_types
    end

    out = []
    exposure_types.each do |exposure_type|

      print "Working on exposure type: #{exposure_type}"

      # start with sensible defaults
      offset = 0
      limit = 1000
      more_results = true 

      while more_results
        
        # get the listing 
        url = "https://expander.expanse.co/api/v1/exposures/cloud/#{exposure_type}?page[limit]=#{limit}&page[offset]=#{offset}"
        response = RestClient.get(url, @headers)
        result = JSON.parse(response.body)

        result["data"].each do |r|

          # get each one 
          result_id  = r["id"]
          print "Getting result: #{result_id}"

          url = "https://expander.expanse.co/api/v1/exposures/cloud/#{exposure_type}/#{URI.escape(result_id)}"

          response_body = RestClient.get(url, @headers)
          result = JSON.parse response_body
  
          # add to our out array
          out << result["data"]

        end

        # prepare the next request
        offset += limit
        if result["pagination"]
          more_results = result["pagination"]["next"]
        else 
          more_results = false
        end

      end

    end

  out 
  end

=begin
  def cloud_exposure_csvs(limit_types=[])
    return nil unless successfully_authenticated?

    if limit_types.empty?
      exposure_types = cloud_exposure_types.map{|x| x["type"]}
    else 
      exposure_types = limit_types
    end

    out = []
    exposure_types.each do |exposure_type|
      out << cloud_exposure_csv
    end
  out 
  end
=end 

  def cloud_exposure_csv(exposure_type)
    
    # get the CSV 
    url = "https://expander.expanse.co/api/v1/exposures/cloud/#{exposure_type}/csv" #?page[limit]=#{limit}&page[offset]=#{offset}"
    response = RestClient.get(url, @headers)

  CSV.parse(response.body)
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
      response_body = RestClient.get(url, @headers)
      result = JSON.parse response_body

      # do stuff with the data 
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