Running the AWS Inspector V1 task
This toolkit brings in data from AWS Inspector v1

To run this task you need the following information from AWS:

aws_access_key
aws_secret_key
AWSInspector permissions. If you attempt this with V2 permissions your run will fail with a permissions error.
Command Line
See the main Toolkit for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

Run with AWS Keys only to ensure you are able to get data properly from the scanner
Review output for expected data
Create a "Kenna Data Importer" Connector in Kenna (example name: AWS Inspector KDI)
Manually run the connector with the JSON from Step 1
Review resulting data if successful, or diagnose issue if there is a failure
Click on the name of the KDI Connector to get the Connector ID
Run the task with AWS Information and Kenna Key + Connector id
Complete list of Options:

Option	Required	Description	default
aws_access_key	true	---	---
aws_secret_key	true	---	---
kenna_api_key	false	Kenna API Key for use with connector option	n/a
kenna_api_host	false	Kenna API Hostname if not US shared	api.kennasecurity.com
kenna_connector_id	false	If set, we'll try to upload to this connector	n/a
output_directory	false	If set, will write a file upon completion. Path is relative to #{$basedir}	output/aws_inspector
