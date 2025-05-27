# AWS Inspector V2 Connector Task

This task brings in asset and vulnerability data from AWS Inspector V2.

## Skip_autoclose and Ignore_scanner_last_seen_time Settings
**Skip_autoclose**: This setting's default is set to **True**. In some cases, you may need change the skip_autoclose default to close specific vulnerabilities. To change it, in the JSON or source code, change the skip_autoclose to **False**.

**Ignore_scanner_last_seen_time**: This setting's default is set to **False**. When it imports the data, it uses the scanners' reported time, instead of the time of the connector's last run, so it may cause an issue if you have an asset inactive-limit shorter then the frequency of your scans. For example, if you have an asset inactive limit set to 2 days, but you scan assets every 5 days, assets are then set to inactive. To solve this issue, change the ignore_scanner_last_seen_time to **True** so the assets_last_seen_time is set to when the connector runs. Currently, this setting only exists in backend administration. For help, contact **support**.

## Running the task

See the main toolkit README for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna API.

### Recommended Steps

1. Run with AWS keys only. You can provide AWS credentials and configuration through [shared ini files, environment variables](https://docs.aws.amazon.com/sdkref/latest/guide/creds-config-files.html),

```
docker run -v ~/.aws:/root/.aws --env AWS_REGION=us-east-1 --env AWS_PROFILE=example_profile --rm -it toolkit:latest \
  task=aws_inspector2
```

...or by directly providing them to the task as shown below. **(Not recommended! See below.)**

```
docker run --rm -it toolkit:latest task=aws_inspector2 aws_regions=us-east-1,us-east-2 aws_access_key_id=AKIAIOSFODNN7EXAMPLE \
  aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

2. Review output for expected data.
3. Create a "Kenna Data Importer" Connector in Kenna and give it a meaningful name, like "AWS Inspector V2 KDI."

If you're doing any scanning of ECR container images, you'll need to have Kenna Support set a custom locator order for your KDI connector similar to: `image_locator, ec2_locator, mac_address_locator, netbios_locator, external_ip_address_locator, hostname_locator, url_locator, file_locator, fqdn_locator, ip_address_locator, external_id_locator, database_locator, application_locator`

4. Manually upload the JSON output from Step 1 to the Kenna Data Connector.
5. Review resulting data and diagnose any failure.
6. Click on the name of the KDI Connector to get the connector ID.
7. Run the task with AWS credentials and your Kenna API key & connector ID.

```
docker run -v ~/.aws:/root/.aws --env AWS_PROFILE=example_profile --rm -it toolkit:latest task=aws_inspector2 \
  aws_regions=us-east-1,us-east-2 kenna_api_key=$KENNA_API_KEY kenna_connector_id=12345
```

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| aws_access_key_id | false |  AWS access key | --- |
| aws_secret_access_key | false | AWS secret key | --- |
| aws_regions | false | Comma-separated list of AWS regions to include when collecting findings | --- |
| aws_session_token | false | AWS session token | --- |
| aws_role_arn | false | AWS IAM role ARN used to assume access to Inspector v2 | --- |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.kennasecurity.com |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to /opt/app/toolkit/ | output/aws_inspector |

### AWS Authentication

This task supports several kinds of credentials, facilitated by the [AWS SDK](https://docs.aws.amazon.com/sdk-for-ruby/v3/api/#Configuration):

1. Long-term credentials: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. 
   *Note: AWS discourages passing these as clear text on the command line: "Many developers have had their account compromised by leaked keys." Environment variables are preferred, but still weaker than options 2 and 3.*
2. Temporary credentials issued by STS, which require an AWS_SESSION_TOKEN in addition to the above.
3. IAM roles. You provide your keys as in #1, but can't access the Inspector v2 API until you assume the IAM role.

You can provide AWS credentials and region via environment variables, ini files (in conjunction with `AWS_PROFILE`), or directly in the task arguments. If you're having trouble authenticating, make sure you can access inspector2 using the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html), which accepts the same environment variables and ini files. If you're running toolkit in a container, make sure the environment variables and/or credentials files are available inside the container, not just on your host system.

Note that ROLE_ARN cannot be provided as an environment variable--it has to be a task argument, which at the moment might require some strange quoting depending on how your shell handles arguments:

```
docker run -v ~/.aws:/root/.aws --env AWS_REGION=us-east-1 --env AWS_PROFILE=inspector_test --rm -it toolkit:latest \
  task=aws_inspector2 aws_role_arn="\"arn:aws:iam::123456789012:role/Inspectorv2ReadOnly\""
```

### Limitations

1. The task currently only handles package vulnerabilities, not code vulnerabilities (in AWS Lambda) or network reachability findings.
2. Suppressed findings in Inspector v2 don't exactly map to "risk accepted" or "false positive" in Kenna, so they are treated as open vulnerabilities.
