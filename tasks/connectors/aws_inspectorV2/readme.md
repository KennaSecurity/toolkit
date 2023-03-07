Task to get data out of AWS inspector V2

State of work:

The task will connect to AWS using region, AWS access and secret keys. You need the keys to be static within AWS. Regions are hardcoded within aws_regions_to_collect.
Task will connect to the first region and loop using a page token via all pages of findings. Then it will go to the next region until all regions for the AWS account are looped.

Limitations:L

1/ The task filters findings that have CVE IDs only. Any other type of findings (CWE/SNYK/GHSA/ALAS/etc) that are reported from AWS Inspector V2 are not received as valid from the Kenna backend and ingesting them to Kenna Cloud fails. This limits AWS Inspector V2 findings that Kenna can consume to only EC2 instances.

2/ Some of the findings do not have a CVSS score assigned by the AWS Inspector V2 API. Such fingings are given a CVSS of 1.0 and a warning message is logged to contact AWS support and ask for the finding to be triagged and a score to be set within the AWS API.

3/ Some AWS EC2 instances can be created without a name, as the name is just a tag atribute within AWS. Kenna does not like nameless assets, so EC2 instances without names are given the NoName tag before been sent to Kenna.

The AWS SDK provides the ability to move away from using AWS static keys, as it is a security risk. Using the ability to assume arn roles will give the task access using rolling AWS keys.
Use >
puts "Using role: " + role_arn
              role_credentials = Aws::AssumeRoleCredentials.new(
                client: Aws::STS::Client.new(region: region),
                role_arn: role_arn,
                role_session_name: "kenna-session"
              )
              puts region
              inspector = Aws::Inspector2::Client.new(region: region)
