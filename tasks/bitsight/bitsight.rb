require_relative 'lib/bitsight_helpers'

module Kenna 
module Toolkit
class BitsightTask < Kenna::Toolkit::BaseTask

  include Kenna::Toolkit::BitsightHelpers

  def self.metadata 
    {
      id: "bitsight",
      name: "Bitsight",
      description: "This task connects to the Bitsight API and pulls results into the Kenna Platform.",
      options: [
        { :name => "bitsight_api_key", 
          :type => "string", 
          :required => true, 
          :default => "", 
          :description => "This is the Bitsight key used to query the API." },
        { :name => "bitsight_company_guid", 
          :type => "string", 
          :required => false, 
          :default => "", 
          :description => "This is the Bitsight company GUID used to query the API." },
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
          :default => "output/expanse", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
      ]
    }
  end

  def run(options)
    super
  
    api_host = @options[:kenna_api_host]
    api_token = @options[:kenna_api_token]
    bitsight_api_key = @options[:bitsight_api_key]
    company_guid = @options[:bitsight_company_guid]


    unless valid_bitsight_api_key?(bitsight_api_key)
      print_error "Unable to proceed, invalid key for Bitsight?"
      return 
    end
    print_good "Valid key, proceeding!"
  
    unless company_guid
      print_good "Getting my company's ID"
      company_guid = get_my_company(bitsight_api_key)
    end

    @assets = []
    @vuln_defs = []

    print_good "Getting findings for company: #{company_guid}"
    get_bitsight_findings_and_create_kdi(bitsight_api_key, company_guid)

    ####
    # Write KDI format
    ####
    kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
   
    ###
    ### Always write the file 
    ### 
    output_dir = "#{$basedir}/#{@options[:output_directory]}"
    FileUtils.mkdir_p output_dir
    
    # create full output path
    output_path = "#{output_dir}/bitsight.kdi.json"

    # write it
    File.open(output_path,"w") {|f| f.puts JSON.pretty_generate(kdi_output) } 

    ####
    ### Finish by uploading, or just tell the user 
    ####

    # optionally upload the file if a connector ID has been specified 
    if kenna_connector_id && kenna_api_host && kenna_api_token
  
      print_good "Attempting to upload to Kenna API"
      print_good "Kenna API host: #{kenna_api_host}"

      # upload it 
      if kenna_connector_id && kenna_connector_id != -1 
        @kenna.upload_to_connector(kenna_connector_id, output_path)
        # delete the temp file 
        File.delete(output_path)
      else 
        print_error "Invalid Connector ID, unable to upload."
      end


    else # just tell the user where the output is 
      print_good "Output is available at: #{output_path}"
    end

  end    

end
end
end