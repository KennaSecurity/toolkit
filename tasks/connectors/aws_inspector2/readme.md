# AWS Inspector V2 Connector Task

This task brings in asset and vulnerability data from AWS Inspector V2.

## Running the task

See the main toolkit README for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna API.

### Recommended Steps:

1. Run with AWS keys only
2. Review output for expected data
3. Create a "Kenna Data Importer" Connector in Kenna and give it a meaningful name, like AWS Inspector V2 KDI
4. Manually run the connector with the JSON from Step 1
5. Review resulting data and diagnose any failure
6. Click on the name of the KDI Connector to get the connector ID
7. Run the task with AWS Information and Kenna API key & connector ID

## State of work:

The task will connect to AWS using region, AWS access and secret keys. You need the keys to be static within AWS. Regions are enumerated within aws_regions.
Task will connect to the first region and loop using a page token via all pages of findings. Then it will go to the next region until all regions for the AWS account are collected.

### Limitations:

1/ The task filters findings that have CVE IDs only. Any other type of findings (CWE/SNYK/GHSA/ALAS/etc) that are reported from AWS Inspector V2 are not received as valid from the Kenna backend and ingesting them to Kenna Cloud fails. This limits AWS Inspector V2 findings that Kenna can consume to only EC2 instances.

2/ The AWS SDK provides the ability to move away from using AWS static keys, as it is a security risk. Using the ability to assume arn roles will give the task access using rolling AWS keys, but they are not yet implemented in the task.
Use >
puts "Using role: " + role_arn
              role_credentials = Aws::AssumeRoleCredentials.new(
                client: Aws::STS::Client.new(region: region),
                role_arn: role_arn,
                role_session_name: "kenna-session"
              )
              puts region
              inspector = Aws::Inspector2::Client.new(region: region)
