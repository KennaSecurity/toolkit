module Kenna 
module Toolkit
class Netsparker < Kenna::Toolkit::BaseTask

  def self.metadata
    {
      id: "netsparker",
      name: "Netsparker",
      authors: ["dbro", "jcran"],
      references: [
        "https://www.netsparkercloud.com/docs/index#!/Websites/Websites_List"
      ],
      description: "This task pulls data from the netsparker and uploads it to a netsparker connector",
      disabled: false,
      options: [
        { :name => "netsparker_api_token", 
          :type => "api_key", 
          :required => true, 
          :default => nil, 
          :description => "Netsparker API Token" },
        { :name => "netsparker_api_host", 
          :type => "hostname", 
          :required => false, 
          :default => "www.netsparkercloud.com", 
          :description => "Netsparker API Host" }, 
        { :name => "kenna_api_token", 
          :type => "api_key", 
          :required => false, 
          :default => nil, 
          :description => "Kenna API Key" },
        { :name => "kenna_api_host", 
          :type => "hostname", 
          :required => false, 
          :default => "api.kennasecurity.com", 
          :description => "Kenna API Hostname" },
        { :name => "kenna_connector_id", 
          :type => "integer", 
          :required => false, 
          :default => nil, 
          :description => "If set, we'll try to upload to this connector"  },
        { :name => "output_directory", 
          :type => "filename", 
          :required => false, 
          :default => "output/netsparker", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
      ]
    }
  end

  def run(options)
    super
  
    # netsparker specifics 
    @netsparker_token = @options[:netsparker_api_token]
    @netsparker_api_host = @options[:netsparker_api_host]
    output_directory = "#{@options[:output_directory]}/netsparker-#{Time.now.iso8601}/"

    # kenna connector specifics 
    #kenna_api_host = @options[:kenna_api_host]
    #kenna_api_token = @options[:kenna_api_key]
    #kenna_connector_id = @options[:kenna_connector_id]

    #create new timestamped folder for this script run
    Dir.mkdir("#{@save_destination}") unless File.exists?("#{@save_destination}")

    website_list = pull_website_list

    # Iterate through CSV list of websites
    website_list.each do |website| 
      puts "Pulling latest scan for - #{website}"
      scan_list_results = JSON.parse(pull_scan_list(website))
      scan_list_array = field_values(scan_list_results["List"], "Id", "TargetUrl", "InitiatedAt")
      scanId = scan_list_array.sort_by {|a,b,c| c}.reverse![0][0]
      puts "Retrieving Scan ID: #{scan_list_array.sort_by {|a,b,c| c}.reverse![0][0]} for #{website}"
      File.write("#{output_directory}/#{scanId}.xml", pull_scan_file(scanId))
    end

  end

  def field_values(array_of_hashes, *fields)
    array_of_hashes.map do |hash|
      hash.values_at(*fields)
    end
  end

  def pull_scan_file(scanId)
    begin

      scan_post_url = "https://#{@netsparker_api_host}/api/1.0/scans/report/?excludeResponseData=false&format=Xml&type=Vulnerabilities&id="

      response = RestClient::Request.execute(
        method: :get,
        url: "#{scan_post_url} + #{scanId}",
        headers: {'Accept' => 'application/xml', 'Authorization' => "Basic #{@netsparker_token}"}
      )

    rescue StandardError => e
      print_error e.message
      print_error e.backtrace.inspect
    end
    
  response.body 
  end

  def pull_website_list
    begin
      
      last_page = false 
      page = 1 
      websites = []

      until last_page
        website_list_url = "https://#{@netsparker_api_host}/api/1.0/websites/list?page=#{page}&pageSize=20"

        # make the request
        response = RestClient::Request.execute(
          method: :get,
          url: "#{website_list_url}",
          headers: {'Accept' => 'application/json', 'Authorization' => "Basic #{@netsparker_token}"}
        )

        # convert to JSON 
        result = JSON.parse(response.body)

        # grab the list 
        websites.concat result["List"]

        # handle iteration
        if result["IsLastPage"]
          last_page = true 
        else
          page += 1 
        end
      
      end

    rescue StandardError => e
      print_error e.message
      print_error e.backtrace.inspect
    end

  websites 
  end

  def pull_scan_list(websiteUrl)
    begin
      
      last_page = false 
      page = 1 
      scans = []

      until last_page
        scan_list_url = "https://#{@netsparker_api_host}/api/1.0/scans/list?websiteUrl=#{websiteUrl}&page=#{page}&pageSize=20"

        # make the request
        response = RestClient::Request.execute(
          method: :get,
          url: "#{scan_list_url}",
          headers: {'Accept' => 'application/json', 'Authorization' => "Basic #{@netsparker_token}"}
        )

        # convert to JSON 
        result = JSON.parse(response.body)

        # grab the list 
        scans.concat result["List"].map{|x| x["Id"]}

        # handle iteration
        if result["IsLastPage"]
          last_page = true 
        else
          page +=1 
        end
      end

    rescue StandardError => e
      print_error e.message
      print_error e.backtrace.inspect
    end

  scans 
  end

end
end
end

# To add the upload and connector run portion here.