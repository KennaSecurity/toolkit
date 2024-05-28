## Running the Snyk V2 task

This toolkit brings in data from Snyk V2.

To run this task, you need the following information from Snyk V2:

1. Snyk API Token
2. Snyk environment API base URL without prefix e.g. api.eu.snyk.io, api.snyk.io or api.au.snyk.io

## Command Line

See the main Toolkit for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a JSON file in the default or specified output directory. You can review the file before attempting to upload to Kenna directly.

Recommended Steps:

1. Run with Snyk V2 Keys only to ensure you are able to get data properly from the scanner.
2. Review output for expected data.
3. Create Kenna Data Importer connector in Kenna (example name: Snyk V2 KDI).
4. Manually run the connector with the JSON from step 1.
5. Click on the name of the connector to get the connector ID.
6. Run the task with Snyk V2 Keys and Kenna Key/connector ID.

Complete list of Options:

| Option | Required | Description | Default |
| --- | --- | --- | --- |
| snyk_api_token | true | Snyk API Token | n/a |
| retrieve_from | false | Default will be 60 days before today | 60 |
| include_license | false | Retrieve license issues | false |
| page_size | false | The number of objects per page (Min 10┃Max 100┃multiple of 10) | 100 |
| batch_size | false | The maximum number of issues to submit to Kenna in each batch | 500 |
| page_num | false | Max pagination number | 5000 |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| kenna_api_key | false | Kenna API Key | n/a |
| kenna_api_host | false | Kenna API Hostname | api.kennasecurity.com |
| snyk_api_base | true  | Snyk environment API base URL without prefix e.g. api.eu.snyk.io, api.snyk.io or api.au.snyk.io | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to toolkit root directory | output/snyk |
