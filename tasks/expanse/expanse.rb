require_relative 'lib/client'

module Kenna 
module Toolkit
class ExpanseTask < Kenna::Toolkit::BaseTask

  def self.metadata 
    {
      id: "expanse",
      name: "Expanse",
      description: "This task connects to the Expanse API and pulls results into the Kenna Platform.",
      options: [
        { :name => "expanse_api_key", 
          :type => "string", 
          :required => true, 
          :default => "", 
          :description => "This is the Expanse key used to query the API." },
        { :name => "kenna_api_token", 
          :type => "api_key", 
          :required => false, 
          :default => nil, 
          :description => "Kenna API Key" },
        { :name => "kenna_api_host", 
          :type => "hostname", 
          :required => false  , 
          :default => "api.kennasecurity.com", 
          :description => "Kenna API Hostname" },
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
    expanse_api_key = @options[:expanse_api_key]

    # create an api client
    @client = Kenna::Toolkit::Expanse::Client.new(expanse_api_key)
  
    @assets = []
    @vuln_defs = []

    unless @client.successfully_authenticated?
      print_bad "Unable to proceed, invalid key for Expanse?"
      return 
    end
    print_good "Valid key, proceeding!"

=begin
    # iterate through the assets!
    print_good "Getting Bitsight assets for your company"
    get_bitsight_assets_for_company(bitsight_api_key, company_guid).each do |f|

      # Create the assets!
      #  
      #  {
      #  file: string,  + (At least one of the fields with a + is required for each asset.)
      #  ip_address: string, + (See help center or support for locator order set for your instance)
      #  mac_address: string, +
      #  hostname: string, +
      #  ec2: string, +
      #  netbios: string, +
      #  url: string, +
      #  fqdn: string, +
      #  external_id: string, +
      #  database: string, +
      #  application: string, (This field should be used as a meta data field with url or file)
      # 
      #  tags: [ string (Multiple tags should be listed and separated by commas) ],
      #  owner: string,
      #  os: string, (although not required, it is strongly recommended to populate this field when available)
      #  os_version: string,
      #  priority: integer, (defaults to 10, between 0 and 10 but default is recommended unless you 
      #                      have a documented risk appetite for assets)
      #  vulns: * (If an asset contains no open vulns, this can be an empty array, 
      #            but to avoid vulnerabilities from being closed, use the skip-autoclose flag) ]
      #  }
      
      asset_attributes = {
        ip_address: f,
      }
      # create_kdi_asset(args, asset_locator, tags=[], priority=10)
      print_good "Creating asset: #{f}"
      create_kdi_asset(asset_attributes, :ip_address, ["Bitsight"]) 
    
      # Create the vuln!
      # 
      #  scanner_identifier: string, * ( each unique scanner identifier will need a 
      #                                  corresponding entry in the vuln-defs section below, this typically should 
      #                                  be the external identifier used by your scanner)
      #  scanner_type: string, * (required)
      #  scanner_score: integer (between 0 and 10),
      #  override_score: integer (between 0 and 100),
      #  created_at: string, (iso8601 timestamp - defaults to current date if not provided)
      #  last_seen_at: string, * (iso8601 timestamp)
      #  last_fixed_on: string, (iso8601 timestamp)
      #  closed_at: string, ** (required with closed status - This field used with status may be provided on remediated vulns to indicate they're closed, or vulns that are already present in Kenna but absent from this data load, for any specific asset, will be closed via our autoclose logic)
      #  status: string, * (required - valid values open, closed, false_positive, risk_accepted)
      #  port: integer
      
      # TODO
      #vuln_attributes = {
      #  scanner_identifier: f.id,
      #  scanner_type: f.service.service_name,
      #  scanner_score: f.severity, 
      #  created_at: f.created_at,
      #  last_seen_at: f.updated_at,
      #  status: "open"
      #}
      # def create_kdi_asset_vuln(asset_id, asset_locator, args)
      #create_kdi_asset_vuln(aws_account_id, :external_id, vuln_attributes)

      #print_good "Creating vuln def: #{f.title}"      
      # Create the vuln def! 
      # 
      # {
      #   scanner_identifier: * (entry for each scanner identifier that appears in the vulns section, 
      #                          this typically should be the external identifier used by your scanner)
      #   scanner_type: string, * (matches entry in vulns section)
      #   cve_identifiers: string, (note that this can be a comma-delimited list format CVE-000-0000)
      #   wasc_identifiers: string, (note that this can be a comma-delimited list - format WASC-00)
      #   cwe_identifiers: string, (note that this can be a comma-delimited list - format CWE-000)
      #   name: string, (title or short name of the vuln, will be auto-generated if not set)
      #   description:  string, (full description of the vuln)
      #   solution: string, (steps or links for remediation teams)
      # }
      #vuln_def_attributes = {
      #  scanner_identifier: f.id,
      #  scanner_type: f.service.service_name,
      #  name: f.title,
      #  description: f.description
      #}
      # def create_kdi_vuln_def(args)
      #create_kdi_vuln_def(vuln_def_attributes)
    end
=end

    kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }

    # create output dir
    if @options[:output_directory]
      output_dir = "#{$basedir}/#{@options[:output_directory]}"
      FileUtils.mkdir_p output_dir
      
      # create full output path
      output_path = "#{output_dir}/expanse.kdi.json"

      print_good "Output being written to: #{output_path}"
      File.open(output_path,"w") {|f| f.puts JSON.pretty_generate(kdi_output) } 
    end

    #
    # TODO... upload 
    #
  end    

end
end
end