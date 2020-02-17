module Kenna
module Toolkit

	module KdiHelpers
	  # Create an asset if it doesnt already exit
	  # A "*" indicates required  
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
	  #
	  def create_kdi_asset(asset_hash)
	    raise "Unable to detect assets array! Did you create one called '@assets'? " unless @assets

	    # if we already have it, skip ... do this by selecting based on our dedupe field
	    # and making sure we don't already have it
	    return nil unless @assets.select{|a| a == asset_hash }.empty?
		 
			# create default values
			asset_hash["priority"] = 10 unless asset_hash["priority"] 
			asset_hash["tags"] = [] unless asset_hash["tags"] 
			asset_hash["vulns"] = []

			# store it in our temp store
	    @assets << asset_hash

		# return it
	  asset_hash
	  end

	  # create an instance of a vulnerability in our 
	  # Args can have the following key value pairs: 
	  # A "*" indicates required  
	  # {
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
	  # }
	  def create_kdi_asset_vuln(asset_hash, vuln_hash)
	    raise "Unable to detect assets array! Did you create one called '@assets'? " unless @assets

	    # check to make sure it doesnt exist
	    a = @assets.select{|a| a == asset_hash }.first

	    # SAnity check to make sure we are pushing data into the correct asset 
	    unless asset_hash #&& asset[:vulns].select{|v| v[:scanner_identifier] == args[:scanner_identifier] }.empty?
				puts "Unable to find asset #{asset_hash}, creating a new one... "
				create_kdi_asset asset_hash
				a = @assets.select{|a| a == asset_hash }.first
	    end 

			#puts "Creating KDI asset/vuln on #{asset_id} with args: #{args}"
			a["vulns"] << vuln_hash
		
		vuln_hash
	  end

	  # Args can have the following key value pairs: 
	  # A "*" indicates required  
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
		def create_kdi_vuln_def(vuln_def)
			
	    raise "Unable to detect vuln defs array! Did you create one called '@vuln_defs'? " unless @vuln_defs
	    return unless @vuln_defs.select{|vd| vd["scanner_identifier"] == vuln_def["scanner_identifier"] }.empty?

	    @vuln_defs << vuln_def
	  
	  true
	  end

	end

end
end