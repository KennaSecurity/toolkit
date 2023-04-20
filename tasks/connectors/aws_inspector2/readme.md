# AWS Inspector V2 Connector Task

This task brings in asset and vulnerability data from AWS Inspector V2.

## Running the task

See the main toolkit README for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna API.

### Recommended Steps

1. Run with AWS keys only. You can provide AWS credentials and configuration through [shared ini files, environment variables](https://docs.aws.amazon.com/sdkref/latest/guide/creds-config-files.html),

```
docker run -v ~/.aws:/root/.aws --env AWS_REGION=us-east-1 --env AWS_PROFILE=example_profile --rm -it toolkit:latest \
  task=aws_inspector2
```

...or by directly providing them to the task as shown below.

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

### AWS Authentication

This task supports several kinds of credentials, facilitated by the [AWS SDK](https://docs.aws.amazon.com/sdk-for-ruby/v3/api/#Configuration):

1. Long-term credentials: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.
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
