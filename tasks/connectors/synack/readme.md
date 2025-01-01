## Running the Synack task 

This toolkit brings in data from Synack

To run this task you need the following information from Synack: 

1. Synack API Url. Just the domain name, no prefixes. For example, api.synack.com.
2. Synack API token

## Command Line

See the main Toolkit for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with Synack keys only to ensure you are able to get data properly from Synack
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna 
1. Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with Synack keys and Kenna key/connector id



Complete list of Options:

| Option | Required | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | default               |
| --- |----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------|
| synack_api_host | false    | Synack API hostname, without prefixes. If not specified, the default api.synack.com will be used. It covers most of the cases.                                                                                                                                                                                                                                                                                                                                                                                           | api.synack.com        |
| synack_api_token | true     | Synack API token                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | n/a                   |
| batch_size | false    | Maximum number of vulnerabilities to retrieve in batches                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | 500                   |
| kenna_api_key | false    | Kenna API Key for use with connector option                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | n/a                   |
| kenna_api_host | false    | Kenna API Hostname                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | api.kennasecurity.com |
| kenna_connector_id | false    | If set, we'll try to upload to this connector                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | n/a                   |
| output_directory | false    | If set, will write a file upon completion. Path is relative to #{$basedir}                                                                                                                                                                                                                                                                                                                                                                                                                                               | output/synack         |
| asset_defined_in_tag | false    | If set to false, we will only fetch from Synack vulnerbilities that have tag starting with "kenna::". The Kenna asset for vulnerability is defined by the tag "kenna::\<asset locator type\>::\<asset locator value\>". For example, if your Synack vulnerability has a tag "kenna::url::https\:\/\/www\.cisco\.com" it will be added to asset with locator type URL set to https\:\/\/www\.cisco\.com <br/><br/> If set to false - the assets will be created from Synack vulnerability's vulnerabiliti location field. | true                  |
