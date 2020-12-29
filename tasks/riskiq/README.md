## Running RiskIQ Digital Footprinting task 

This toolkit brings in data from the RiskIQ Global Inventory API endpoint (https://api.riskiq.net/api/globalinventory/)

To run this task you need the following information from RiskIQ: 

1. API Key
1. API Secret


## Command Line

See the main Toolkit for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

API calls to RiskIQ use the "recent" parameter to limit data. Refer to the Recency section of the API page https://api.riskiq.net/api/globalinventory/ to view the time period used for the different record types. 

Data can be further limited using the riskiq_pull_incremental flag and riskiq_incremental_time to set the timeframe desired.

Recommended Steps: 

1. Run with RiskIQ Keys only to ensure you are able to get data properly
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: RiskIQ KDI) 
1, Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with RiskIQ Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| riskiq_api_key | true | This is the RiskIQ key used to query the API.| n/a |
| riskiq_api_secret | true | This is the RiskIQ secret used to query the API. | n/a |
| riskiq_create_cves| true | Create vulns for CVEs | n/a |
| riskiq_create_ssl_misconfigs | true | Create vulns for SSL Miconfigurations | n/a |
| riskiq_create_open_ports | true | Create vulns for open ports | n/a |
| riskiq_pull_incremental | false | Boolean for pulling incrementals | false |
| riskiq_incremental_time | false | Use with pull incrementals - Example '14 days ago' | '2 days ago' |
| batch_page_size | false | Number of assets for each file load to Kenna | 500 |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.kennasecurity.com |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/riskiq |
