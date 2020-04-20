require_relative 'lib/client'

module Kenna 
module Toolkit
class RiskIqTask < Kenna::Toolkit::BaseTask

  def self.metadata 
    {
      id: "riskiq",
      name: "RiskIQ",
      description: "This task connects to the RiskIQ API and pulls results into the Kenna Platform.",
      options: [
        { :name => "riskiq_api_key", 
          :type => "string", 
          :required => true, 
          :default => "", 
          :description => "This is the RiskIQ key used to query the API." },
        { :name => "riskiq_api_secret", 
          :type => "string", 
          :required => true, 
          :default => "", 
          :description => "This is the RiskIQ secret used to query the API." },
        { :name => "riskiq_api_host", 
          :type => "string", 
          :required => true, 
          :default => "https://api.riskiq.net/v1/", 
          :description => "This is the RiskIQ host providing the api endpoint." },
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
          :default => "output/riskiq", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
      ]
    }
  end

  def run(options)
    super
  
    kenna_api_host = @options[:kenna_api_host]
    kenna_api_token = @options[:kenna_api_token]
    kenna_connector_id = @options[:kenna_connector_id]
    riskiq_api_key = @options[:riskiq_api_key]

    # create an api client
    client = Kenna::Toolkit::RiskIq::Client.new(riskiq_api_key)
  
    @assets = []
    @vuln_defs = []

    unless @client.successfully_authenticated?
      print_error "Unable to proceed, invalid key for Expanse?"
      return 
    end
    print_good "Valid key, proceeding!"

    raise "Not yet implemented"

  end    

end
end
end