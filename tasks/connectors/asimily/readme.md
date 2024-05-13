# Asimily Toolkit Task

## This Task will use the Asimily API to

- Get a list devices and its respective vulnerabilities
- Output a json file in the Kenna Data Importer (KDI) format.
- Post the file to Kenna if API Key and Connector ID are provided

## Things you will need

- Asimily Username (Required)
- Asimily Password (Required)
- Asimily Portal URL (Required)
- Asimily device filter (Optional. To send the selected devices that match the filter criteria)
- Asimily Page size (Optional. Default is 100 rows max is 1000)
- Kenna Batch Size (Optional. Default is 500. How many vulnerability to collect before sending to Kenna)
- Kenna API Host (Optional, but required for automatic upload to Kenna)
- Kenna API Key (Optional, but required for automatic upload to Kenna)
- Kenna Connector ID (Optional, but required for automatic upload to Kenna)

Running the Task:

- Create a User in Asimily Portal.
- Retrieve the Kenna API Key from the Kenna UI.
  - From the Gear icon (Upper right corner), select API Keys
  - Copy the key using the copy button to the left of the obscured key
- Retrieve the Kenna Connector ID for Asimily
  - To create a connector of type Kenna Data Importer, if it has not already been created, select the Add Connector button. Make sure you name the connector with 'Asimily' in the name..
  - Click on the name of the connector 'Asimily' and copy the ID of the connector from the page that appears.

Run the Asimily task following the guidelines on the main [toolkit help page](https://github.com/KennaPublicSamples/toolkit#calling-a-specific-task) adding options as necessary

## Options

| Name | Type | Required | Description |
| ---- | ---- | ---- | ---- |
| asimily_user |user | true | Asimily Username |
| asimily_password |password | true | Asimily Password |
| asimily_api_endpoint | string | true | Your Asimily portal url, e.g. myportal.asimily.com |
| asimily_filter | string | false | To send the selected devices that match the filter criteria |
| asimily_page_size | integer | false | Optional, Page size for Asimily API calls |
| kenna_batch_size | integer | false | Optional, Kenna post batch size |
| kenna_api_key | api_key | false | Kenna API Key |
| kenna_api_host | hostname | false | Kenna API Hostname |
| kenna_connector_id | integer | false | Kenna Connector ID for Asimily |
| output_directory | filename | false | To change default filename for output. Path is relative to #{$basedir} |

## Example Command Line:

```
    toolkit:latest task=Asimily kenna_api_key="xxx" kenna_api_host="api.kennasecurity.com" asimily_api_endpoint="xxx.asimily.com" asimily_user="xxx" asimily_password="xxx" asimily_filter="xxx"  kenna_connector_id=xxx 
```

# Contact
Contact your Customer Success Representative or email info@Asimily.com for more details.