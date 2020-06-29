require_relative "lib/microsoft_atp_helper"

module Kenna 
module Toolkit
class MicrosoftAtp < Kenna::Toolkit::BaseTask

  include Kenna::Toolkit::MicrosoftAtpHelper

  def self.metadata 
    {
      id: "microsoft_atp",
      name: "Microsoft ATP",
      description: "Pulls assets and vulnerabilitiies from Microsoft ATP",
      options: [
        {:name => "atp_tenant_id", 
          :type => "strign", 
          :required => true, 
          :default => nil, 
          :description => "Microsoft ATP Tenant ID" },
        {:name => "atp_client_id", 
          :type => "api_key", 
          :required => true, 
          :default => nil, 
          :description => "Microsoft ATP Client ID" },
        {:name => "atp_client_secret", 
          :type => "api_key", 
          :required => true, 
          :default => nil, 
          :description => "Microsoft ATP Client Secret" },
        {:name => "kenna_api_key", 
          :type => "api_key", 
          :required => false, 
          :default => nil, 
          :description => "Kenna API Key" },
        {:name => "kenna_api_host", 
          :type => "hostname", 
          :required => false  , 
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
          :default => "output/microsoft_atp", 
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
      ]
    }
  end

  def run(opts)
    super # opts -> @options

    atp_tenant_id = @options[:atp_tenant_id]
    atp_client_id = @options[:atp_client_id]
    atp_client_secret = @options[:atp_client_secret]
    
    kenna_api_host = @options[:kenna_api_host]
    kenna_api_key = @options[:kenna_api_key]
    kenna_connector_id = @options[:kenna_connector_id]
    
    token = atp_get_auth_token(atp_tenant_id, atp_client_id, atp_client_secret)
    machine_json = atp_get_machines(token)

    machine_json.each do |machine| 
      
      machine_id = machine.fetch("id")

      # Save these to persist on the vuln
      first_seen = machine.fetch("firstSeen")
      last_seen = machine.fetch("lastSeen")

      # Get the asset details & craft them into a hash
      asset = { 
        "hostname" =>  machine.fetch("computerDnsName"),
        "ip_address" => machine.fetch("lastIpAddress"),
        "external_id" => machine_id,
        "os" => machine.fetch("osPlatform"),
        "os_version" => machine.fetch("osVersion"),
        "first_seen" => machine.fetch("firstSeen"), # TODO ... this doesnt exist on the asset today, but won't hurt here.
        "last_seen" => machine.fetch("lastSeen") # TODO ... this doesnt exist on the asset today
      }

      # Construct tags
      tags = []
      tags << "riskScore: #{machine.fetch('riskScore')}" unless machine.fetch("riskScore").nil?
      tags << "exposureLevel: #{machine.fetch('exposureLevel')}" unless machine.fetch("exposureLevel").nil?
      tags << "MSATP Agent Version: #{machine.fetch('agentVersion')}" unless machine.fetch("agentVersion").nil?
      tags.concat(machine.fetch("machineTags")) unless machine.fetch("machineTags").nil?
      
      # Add them to our asset hash
      asset.merge({"tags" => tags})
      create_kdi_asset(asset)

      # now get the vulns 
      vuln_json = atp_get_vulns(token, machine.fetch("id"))
      vuln_severity = { "Critical" => 10, "High" => 8, "Medium" => 6, "Low" => 3} # converter
      vuln_json.each do |vuln|

        #print JSON.pretty_generate vuln
        
        vuln_id = vuln.fetch("id")
        vuln_name = vuln.fetch("name")
        vuln_description = vuln.fetch("description")
        vuln_score = vuln["cvssV3"] || vuln_severity[vuln.fetch("severity")]

        # craft the vuln hash
        vuln = {
          "scanner_identifier" => vuln_id,
          "scanner_type" => "MSATP",
          "name" => vuln_name,
          # scanner score should fallback using criticality (in case of missing cvss)
          "scanner_score" => vuln_score, 
          "last_seen_at" => last_seen
        }

        # craft the vuln def hash
        vuln_def= {
          "scanner_identifier" => vuln_id,
          "name" => vuln_name,
          "scanner_type" => "MSATP",
          "description" => vuln_description
        }

        # Create the KDI entries 
        create_kdi_asset_vuln(asset, vuln)
        create_kdi_vuln_def(vuln_def)
      end

    end

    ### Write KDI format
    kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
    output_dir = "#{$basedir}/#{@options[:output_directory]}"
    filename = "microsoft_atp.kdi.json"
    write_file output_dir, filename, JSON.pretty_generate(kdi_output)
    print_good "Output is available at: #{output_dir}/#{filename}"

    ### Finish by uploading if we're all configured
    if kenna_connector_id && kenna_api_host && kenna_api_key
      print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
      upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
    end

  end


end
end
end
