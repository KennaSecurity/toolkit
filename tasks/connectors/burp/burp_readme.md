## Running the Burp task 

This toolkit brings in data from Portswigger Burp Suite Enterprise Edition

To run this task you need the following information from Burp: 

1. Burp instance hostname
2. Site Id
3. User API Token

## Command Line

See the main Toolkit for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps: 

1. Run with Burp Keys only to ensure you are able to get data properly from the scanner
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna (example name: Burp KDI) 
1, Manually run the connector with the json from step 1 
1. Click on the name of the connector to get the connector id
1. Run the task with Burp Keys and Kenna Key/connector id



Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| burp_api_host | true | Burp instance hostname, e.g. http://burp.example.com:8080  | n/a |
| burp_site_id | true | Burp Site ID | n/a |
| burp_api_token | true | Burp User API token | n/a |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.kennasecurity.com |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/burp |
