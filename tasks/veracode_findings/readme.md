## Running Veracode Findings Task

This toolkit brings in data from Veracode AppSec Rest API (https://help.veracode.com/r/orRWez4I0tnZNaA_i0zn9g/CkYucW99f14~~seBw4Anlg)

To run this task you need the following information from Microsoft: 

1. Veracode ID
1. Veracode Secret

The data is batched by Application before being sent to Kenna. 

1. Pull a list of applications (https://help.veracode.com/r/c_apps_intro)
1. Pull a list of findings for each application and submit to Kenna (https://help.veracode.com/r/c_findings_v2_intro)


## Command Line

See the main Toolkit for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.


Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| veracode_id | true | Veracode ID | n/a |
| veracode_key | true | Veracode API Key | n/a |
| veracode_page_size | true | Number of records to bring back with each page request from Vercode | n/a |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.kennasecurity.com |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/veracode |
