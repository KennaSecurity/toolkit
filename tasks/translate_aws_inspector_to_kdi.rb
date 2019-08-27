require 'aws-sdk-inspector'

module Kenna 
module Toolkit
class TranslateAwsInspectorToKdi < Kenna::Toolkit::BaseTask


def metadata 
    {
      id: "translate_aws_inspector_to_kdi",
      name: "Translate AWS Inspector To KDI",
      description: "This task pulls results from AWS inspector and translates them into JSON",
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
          :required => false, 
          :default => "us-east-1", 
          :description => "This is the AWS access key used to query the API." 
        },
        { 
          :name => "aws_secret_key", 
          :type => "string", 
          :required => false, 
          :default => "us-east-1", 
          :description => "This is the AWS secret key used to query the API." 
        }
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
  print_good "Getting inspector findings"
  get_inspector_findings(aws_region, aws_access_key, aws_secret_key).each do |f|

    # create an asset with our locators (regardless of whether we have vulns)
    fqdn = f[:asset_attributes][:hostname]
    instance_id = f[:attributes].select{|a|a[:key] == "INSTANCE_ID" }.first[:value]

    # this function hackily handles dedupe
    print_good "Creating asset: #{fqdn}"
    create_asset fqdn, instance_id

    # and look through our finding's attributes to see if we have any CVEs
    f[:attributes].each do |a|
       if a[:key] == "CVE_ID"

         # if so, create vuln and attach to asset
         create_asset_vuln fqdn, a[:value]

         # also create the vuln def if we dont already have it (function handles dedupe)
         create_vuln_def a[:value]

      end
    end
  end

  kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
  
  print_good "Output:"

  puts JSON.pretty_generate kdi_output

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

def get_inspector_findings(region, access_key,secret_key)
  begin
    # do stuff
    inspector = Aws::Inspector::Client.new({
      region: region,
      credentials: Aws::Credentials.new(access_key,secret_key)
    })

    # go get the inspector findings
    finding_arns = inspector.list_findings.finding_arns
    findings = inspector.describe_findings(finding_arns: finding_arns).findings.map(&:to_hash)

  rescue Aws::Inspector::Errors::ServiceError
    # rescues all errors returned by Amazon Inspector
    print_error "Irrecoverable error connecting to AWS, exiting"
    exit
  end

findings
end


end
end
end
