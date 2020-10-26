require_relative "lib/ms_defender_atp_helper"

module Kenna 
module Toolkit
class MSDefenderAtp < Kenna::Toolkit::BaseTask

  include Kenna::Toolkit::MSDefenderAtpHelper

  def self.metadata 
    {
      id: "ms_defender_atp",
      name: "MS Defender ATP",
      description: "Pulls assets and vulnerabilitiies from Microsoft Defenders ATP",
      options: [
        { :name => "atp_tenant_id", 
          :type => "string", 
          :required => true, 
          :default => nil, 
          :description => "MS Defender ATP Tenant ID" },
        { :name => "atp_client_id", 
          :type => "api_key", 
          :required => true, 
          :default => nil, 
          :description => "MS Defender ATP Client ID" },
        { :name => "atp_client_secret", 
          :type => "api_key", 
          :required => true, 
          :default => nil, 
          :description => "MS Defender ATP Client Secret" },
        { :name => "atp_api_host", 
          :type => "hostname", 
          :required => false, 
          :default => "https://api.securitycenter.microsoft.com", 
          :description => "url to retrieve hosts and vulns"},
        { :name => "atp_oath_host", 
          :type => "hostname", 
          :required => false, 
          :default => "https://login.windows.net", 
          :description => "url for authentication"},        
        { :name => "kenna_api_key", 
          :type => "api_key", 
          :required => false, 
          :default => nil, 
          :description => "Kenna API Key"},
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
        { :name => "batch_page_size", 
          :type => "integer", 
          :required => false, 
          :default => 5000, 
          :description => "Number of assets and their vulns to batch to the connector"},     
        { :name => "output_directory", 
          :type => "filename", 
          :required => false, 
          :default => "output/microsoft_atp", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
      ]
    }
  end

  def connectorKickoff(filename, kenna_connector_id,kenna_api_host,kenna_api_key)
        ### Write KDI format
    kdi_output = { skip_autoclose: false, assets: @paged_assets, vuln_defs: @vuln_defs }
    output_dir = "#{$basedir}/#{@options[:output_directory]}"
    write_file output_dir, filename, JSON.pretty_generate(kdi_output)
    print_good "Output is available at: #{output_dir}/#{filename}"

    ### Finish by uploading if we're all configured
    if kenna_connector_id && kenna_api_host && kenna_api_key
      print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
      upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}", false
    end
  end

  def run(opts)
    super # opts -> @options

    atp_tenant_id = @options[:atp_tenant_id]
    atp_client_id = @options[:atp_client_id]
    atp_client_secret = @options[:atp_client_secret]
    atp_api_host = @options[:atp_api_host]
    atp_oath_host = @options[:atp_oath_host]

    kenna_api_host = @options[:kenna_api_host]
    kenna_api_key = @options[:kenna_api_key]
    kenna_connector_id = @options[:kenna_connector_id]
    batch_page_size = @options[:batch_page_size]
    
    set_client_data(atp_tenant_id, atp_client_id, atp_client_secret,atp_api_host,atp_oath_host)
    page = 0
    moremachines = true
    while moremachines do 
      if page == 0 then
        machine_json = atp_get_machines()
      else
        machine_json = atp_get_machines("$skip=#{page}0000")
      end

      break if machine_json.nil? || machine_json.empty?

      #print_debug machine_json

      machine_json.each do |machine| 
        
        machine_id = machine.fetch("id")

        # Save these to persist on the vuln
        first_seen = machine.fetch("firstSeen")
        last_seen = machine.fetch("lastSeen")

        # Get the asset details & craft them into a hash
        asset = { 
          "external_id" => machine_id,
          "hostname" =>  machine.fetch("computerDnsName"),
          "ip_address" => machine.fetch("lastIpAddress"),
          "os" => machine.fetch("osPlatform"),
          "os_version" => machine.fetch("osVersion"),
          "first_seen" => machine.fetch("firstSeen"), # TODO ... this doesnt exist on the asset today, but won't hurt here.
          "last_seen" => machine.fetch("lastSeen") # TODO ... this doesnt exist on the asset today
        }

        # Construct tags
        tags = []
        tags << "MSDefenderAtp"
        tags << "riskScore: #{machine.fetch('riskScore')}" unless machine.fetch("riskScore").nil?
        tags << "exposureLevel: #{machine.fetch('exposureLevel')}" unless machine.fetch("exposureLevel").nil?
        tags << "ATP Agent Version: #{machine.fetch('agentVersion')}" unless machine.fetch("agentVersion").nil?
        tags << "rbacGroup: #{machine.fetch('rbacGroupName')}" unless machine.fetch("rbacGroupName").nil?
        tags.concat(machine.fetch("machineTags")) unless machine.fetch("machineTags").nil?
        
        # Add them to our asset hash
        asset.merge({"tags" => tags})
        create_kdi_asset(asset)
      end
      page = page + 1
    end
    morevuln = true
    page = 0
    asset_count = 0
    submit_count = 0
    asset_id = nil
    # now get the vulns 
    while morevuln do 

      if page == 0 then
        vuln_json = atp_get_vulns()
      else
        vuln_json = atp_get_vulns("$skip=#{page}0000")
      end
      break if vuln_json.nil? || vuln_json.empty?
      #print_debug vuln_json
      vuln_severity = { "Critical" => 10, "High" => 8, "Medium" => 6, "Low" => 3} # converter

      vuln_json.each do |vuln|

        #print JSON.pretty_generate vuln
        
        vuln_cve = vuln.fetch("cveId")
        machine_id = vuln.fetch("machineId")
        details = "fixingKbId = #{vuln.fetch('fixingKbId')}" unless vuln.fetch("fixingKbId").nil? || vuln.fetch("fixingKbId").empty?
          
        #end
        vuln_score = (vuln["cvssV3"] || vuln_severity[vuln.fetch("severity")] || 0 ).to_i

        if asset_id.nil? then
          asset_id = machine_id 
          asset_count += 1
        end
        if !asset_id.eql? machine_id then
          if asset_count == batch_page_size then
            submit_count +=1
            filename = "microsoft_atp_kdi_#{submit_count}.json"
            connectorKickoff(filename, kenna_connector_id,kenna_api_host,kenna_api_key)
            asset_count = 0
            clearDataArrays
          end
          asset_id = machine_id
        end


        # craft the vuln hash

        vuln_asset = {
          "external_id" => machine_id
        }

        vuln = {
          "scanner_identifier" => vuln_cve,
          "scanner_type" => "MS Defender ATP",
          # scanner score should fallback using criticality (in case of missing cvss)
          "scanner_score" => vuln_score, 
          "details" => details
        }

        # craft the vuln def hash
        vuln_def= {
          "scanner_identifier" => vuln_cve,
          "scanner_type" => "MS Defender ATP",
          "cve_identifiers" => "#{vuln_cve}"
        }

        vuln_asset = vuln_asset.compact
        vuln = vuln.compact
        vuln_def = vuln_def.compact

        # Create the KDI entries 
        create_paged_kdi_asset_vuln(vuln_asset, vuln, "external_id")
        create_kdi_vuln_def(vuln_def)
      end
      page = page+1
    end

    submit_count +=1
    filename = "microsoft_atp_kdi_#{submit_count}.json"
    connectorKickoff(filename, kenna_connector_id,kenna_api_host,kenna_api_key)

  end

end
end
end
