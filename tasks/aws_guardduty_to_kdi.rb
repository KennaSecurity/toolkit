require 'aws-sdk-guardduty'

module Kenna 
module Toolkit
class AwsGuarddutyToKdi < Kenna::Toolkit::BaseTask

def metadata 
    {
      id: "aws_guardduty_to_kdi",
      name: "AWS GuardDuty To KDI Translator",
      description: "This task pulls results from AWS GuardDuty API and translates them into KDI JSON",
      options: [
        { 
          :name => "aws_region", 
          :type => "string", 
          :required => false, 
          :default => "us-east-1", 
          :description => "This is the AWS region." 
        },
        { 
          :name => "aws_access_key", 
          :type => "string", 
          :required => true, 
          :default => "", 
          :description => "This is the AWS access key used to query the API." 
        },
        { 
          :name => "aws_secret_key", 
          :type => "string", 
          :required => true, 
          :default => "", 
          :description => "This is the AWS secret key used to query the API." 
        }, 
        { :name => "output_directory", 
          :type => "filename", 
          :required => false, 
          :default => "output/guardduty", 
          :description => "Path to parsing output, relative to #{$basedir}"  }
      ]
    }
end

def run(opts)
  super # opts -> @options

  # Get options
  aws_region = @options[:aws_region]
  aws_access_key = @options[:aws_access_key]
  aws_secret_key = @options[:aws_secret_key]

  unless aws_region && aws_access_key && aws_secret_key
    print_error "Unable to proceed, missing required option!"
    exit 
  end

  @assets = []
  @vuln_defs = []

  # iterate through the findings, looking for CVEs
  print_good "Getting guardduty findings"
  get_guardduty_findings(aws_region, aws_access_key, aws_secret_key).each do |f|
    print_good "Got finding: #{f[:title]}"
  end

  # create output dir
  output_dir = "#{$basedir}/#{@options[:output_directory]}"
  FileUtils.mkdir_p output_dir
  
  # create full output path
  output_path = "#{output_dir}/inspector.kdi.json"

  # write a file with the output
  kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
  print_good "Output being written to: #{output_path}"
  File.open(output_path,"w") {|f| f.puts JSON.pretty_generate(kdi_output) } 

end

def create_asset(fqdn, instance_id)

  # if we already have it, skip
  return unless @assets.select{|a| a[:fqdn] == fqdn }.empty?

  @assets << {
    fqdn:  "#{fqdn}",
    ec2: "#{instance_id}",
    tags: ["AWS"],
    priority: 0,
    vulns: []
  }

end

def create_asset_vuln(fqdn, cve_id)
  # check to make sure it doesnt exist
  asset = @assets.select{|a| a[:fqdn] == fqdn }.first
  return unless asset[:vulns].select{|v| v[:scanner_identifier] == cve_id }.empty?

  asset[:vulns] << {
    scanner_identifier: "#{cve_id}",
    scanner_type: "AWS Inspector",
    created_at: DateTime.now,
    last_seen_at: DateTime.now,
    status: "open"
  }
end

def create_vuln_def(cve_id)
  return unless @vuln_defs.select{|a| a[:cve_identifiers] == cve_id }.empty?
  @vuln_defs << {
    scanner_identifier: "#{cve_id}",
    scanner_type: "AWS Inspector",
    cve_identifiers: "#{cve_id}"
  }
end

def get_guardduty_findings(region, access_key,secret_key)
   findings = [] 
   begin 
     client = Aws::GuardDuty::Client.new({
      region: region,
      credentials: Aws::Credentials.new(access_key,secret_key)
    })
    
   client.list_detectors.each do |detector| 
    detector.detector_ids.each do |did|

      finding_ids = []
      next_token = true

      until !next_token

        query_criteria = {
          detector_id: did, # required
          max_results: 10,
        }

        if next_token.kind_of? String
          query_criteria[:next_token] = next_token 
        end

        resp = client.list_findings(query_criteria) 
        finding_ids.concat resp.finding_ids
        next_token = resp.next_token

        break unless next_token.length > 0

      end

      finding_ids.each do |fid|
        findings << client.get_findings({
          detector_id: did, # required
          finding_ids: [fid] # required
        })[:findings].first
      end
    end
   end 

  rescue Aws::GuardDuty::Errors::ServiceError => e 
    # rescues all errors returned by Amazon Inspector
    print_error "Irrecoverable error connecting to AWS, exiting: #{e}"
    exit
  end

findings
end


end
end
end
