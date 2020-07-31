module Kenna
module Toolkit 
module Ssc
class Client

  def initialize(key)
    @key = key
    @baseapi = "https://api.securityscorecard.io"
    @headers = {
      "Accept" => "application/json",
      "Content-Type" => "application/json",
      "Cache-Control" => "none",
      "Authorization" => "Token #{@key}"
    }
  end

  def get_user_details(ssc_api_key)

    begin 
      response = RestClient.get "https://api.securityscorecard.io/portfolios", @headers
      user_details = JSON.parse(response.body)
    rescue RestClient::Unauthorized => e
      return nil
    rescue JSON::ParserError => e 
      return nil 
    end

    if user_details["entries"].first.kind_of? Hash
      return user_details
    else 
      puts "Error! Got user details: #{user_details}"
    end
    
  nil  # default 
  end


  def succesfully_authenticated?
    endpoint = "#{@baseapi}/portfolios"

    response = RestClient::Request.execute({
      method: :get,
      url: endpoint,
      headers: @headers
    })
      
    begin 
      json = JSON.parse("#{response.body}")
    rescue JSON::ParserError => e
    end

    return true if json["entries"]
  
  false
  end   



end
end
end
end