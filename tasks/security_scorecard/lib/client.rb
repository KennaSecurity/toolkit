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

  def succesfully_authenticated?
    json = get_portfolio

    return true if json["entries"]
  
  false
  end   

  def get_all_issues_for_all_companies_in_portfolio(portfolio_id)
    out_issues = []
    companies = get_companies_by_portfolio(portfolio_id)["entries"]
    puts "DEBUG Got #{companies.count} companies"
    companies.each do |c|
      puts "Working on company #{c}"
      get_issue_types.each do |it|
        issues = get_issues_by_type_for_company(c["domain"], it)["entries"]
        if issues 
          puts "#{issues.count} issues of type #{it}"
          out_issues.concat issues
        else 
          puts "Missing (or error) on #{it} issues"
        end
      end
    end
  out_issues
  end


  def get_portfolio
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
  end   

  def get_companies_by_portfolio(portfolio_id)
    endpoint = "#{@baseapi}/portfolios/#{portfolio_id}/companies"

    response = RestClient::Request.execute({
      method: :get,
      url: endpoint,
      headers: @headers
    })
      
    begin 
      json = JSON.parse("#{response.body}")
    rescue JSON::ParserError => e
    end
  end   


=begin
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
=end

  def get_issues_by_type_for_company(company_id, itype="patching_cadence_low")
    
    endpoint = "#{@baseapi}/companies/#{company_id}/issues/#{itype}"

    begin 
      response = RestClient::Request.execute({
        method: :get,
        url: endpoint,
        headers: @headers
      })
      
      json = JSON.parse("#{response.body}")
      
    rescue RestClient::InternalServerError => e
      puts "Error! 500 getting #{itype}: #{e}"    
      return {}
    rescue JSON::ParserError => e
      puts "Error! Parsing #{itype}: #{e}"
      return {}
    end
  
  end

  def get_issue_types
    
    endpoint = "#{@baseapi}/metadata/issue-types"

    response = RestClient::Request.execute({
      method: :get,
      url: endpoint,
      headers: @headers
    })
      
    begin 
      json = JSON.parse("#{response.body}")["entries"].map{|x| x["key"]}
    rescue JSON::ParserError => e
    end

  end
 

end
end
end
end