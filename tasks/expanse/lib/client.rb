require 'uri'
require 'csv'

module Kenna
module Toolkit
module Expanse
class Client

  ###
  ### TODO - add back later during rework for scale 
  ###

=begin
  def get_value_by_header(row, headers, field_name)

    # in case we get a string
    headers = headers.split(",") if headers.kind_of? String

    #puts "Getting value for field name: #{field_name} from: #{headers}"

    i = headers.find_index(field_name)
    return nil unless i 
    raise "Invalid index: #{i} for field_name: #{field_name}. All headers: #{headers}" unless i 

  "#{row[i]}"
  end

  def exposures_by_type_csv(exposure_type)
    exposures = []
    csv = @client.cloud_exposure_csv("ftp-servers")
    # Go through the CSV, pulling out the appropriate values
    csv.each_with_index do |row, index|
      next if index == 0 #skip the first 

      exposure_details = {}
      exposure_details[:ip] = get_value_by_header(row, csv.first, "ip")
      exposure_details[:hostname] = get_value_by_header(row, csv.first, "lastObservation.hostname")
      exposure_details[:domain] = get_value_by_header(row, csv.first, "domain")
      exposure_details[:port] =  get_value_by_header(row, csv.first, "port")
      exposure_details[:severity] = get_value_by_header(row, csv.first, "severity")
      exposure_details[:type] =  get_value_by_header(row, csv.first, "type") 
      exposures << exposure_details
    end
  
  exposures 
  end
=end


  def initialize(api_key)
    url = "https://expander.qadium.com/api/v1/idtoken"
    response = RestClient.get(url, {:Authorization => "Bearer #{api_key}"})
    @token = JSON.parse(response.body)["token"]
    @headers = {:Authorization => "JWT #{@token}"}
  end

  def successfully_authenticated?
    @token && @token.length > 0
  end

  def exposures(max_pages=100, limit_per_page=1000)
    return nil unless successfully_authenticated?

    # start with sensible defaults
    offset = 0
    limit = 1000
    more_results = true 
    out = []

    # hack!
    pages = 0 

    while more_results && pages < max_pages
      pages += 1 
      url = "https://expander.qadium.com/api/v2/configurations/exposures?limit=#{limit_per_page}&offset=#{offset}"
      response_body = RestClient.get(url, @headers)
      result = JSON.parse response_body

      # do stuff with the data 
      out.concat(result["data"])

      # prepare the next request
      offset += limit_per_page
      if result["pagination"]
        more_results = result["pagination"]["next"]
      else 
        more_results = false
      end
    end

  out 
  end

  def cloud_exposure_counts
    url = "https://expander.expanse.co/api/v1/summaries/cloud/counts"
    response_body = RestClient.get(url, @headers)
    result = JSON.parse(response_body)["data"]
  end

  def cloud_exposures(max_pages=100, limit_per_page=1000, limit_types=["ftp-servers"])
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
      more_results = true 
      pages = 0 

      while more_results && (pages < max_pages)
        
        # get the listing 
        url = "https://expander.expanse.co/api/v1/exposures/cloud/#{exposure_type}?page[limit]=#{limit_per_page}&page[offset]=#{offset}"
        response = RestClient.get(url, @headers)
        result = JSON.parse(response.body)

        result["data"].each do |r|

          # get each one 
          result_id  = r["id"]
          url = "https://expander.expanse.co/api/v1/exposures/cloud/#{exposure_type}/#{URI.escape(result_id)}"

          response_body = RestClient.get(url, @headers)
          result = JSON.parse response_body
  
          # add to our out array
          out << result["data"]

        end

        # prepare the next request
        offset += limit_per_page
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
    

=begin
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
=end

end
end
end
end