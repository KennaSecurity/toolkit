# CheckMarx SAST Toolkit Task to Kenna.VM

## This Task will use the CheckMarx SAST API to

- Get a list of webApp currently present in the user's CheckMarx SAST account
- Get a list of Findings in the user's CheckMarx SAST account associated with each WebApp
- Output a json file in the Kenna Data Importer (KDI) format.
- Post the file to Kenna if API Key and Connector ID are provided

## Things you will need

- CheckMarx SAST Username (Required)
- CheckMarx SAST Password (Required)
- CheckMarx SAST Console (Required)
- Kenna API Host (Optional but needed for automatic upload to Kenna)
- Kenna API Key (Optional but needed for automatic upload to Kenna)
- Kenna Connector ID (Optional but needed for automatic upload to Kenna)

Running the Task:

- Create a User in CheckMarx SAST.
- Retrieve the Kenna API Key from the Kenna UI.
  - From the Gear icon (Upper right corner) select API Keys
  - Copy the key using the copy button to the left of the obscured key
- Retrieve the Kenna Connector ID
  - If not already created, select the Add Connector button to create a connector of type Kenna Data Importer. Be sure to rename the connector using 'CheckMarx SAST' in the name.
  - Click on the name of the connector and from the resulting page, copy the Connector ID.

Run the CheckMarx SAST task following the guidelines on the main [toolkit help page](https://github.com/KennaPublicSamples/toolkit#calling-a-specific-task) adding options as necessary

## Options

| Name | Type | Required | Description |
| ---- | ---- | ---- | ---- |
| checkmarx_sast_user |user | true | CheckMarx SAST Username |
| checkmarx_sast_password |password | true | CheckMarx SAST Password |
| kenna_api_key | api_key | false | Kenna API Key |
| kenna_api_host | hostname | false | Kenna API Hostname |
| kenna_connector_id | integer | false | If set, we'll try to upload to this connector |
| output_directory | filename | false | Will alter default filename for output. Path is relative to #{$basedir} |


## Example Command Line:

For extracting Image vulnerability data:

    toolkit:latest task=checkmarx_sast checkmarx_sast_console=xxx checkmarx_sast_user=xxx checkmarx_sast_password=xxx
    checkmarx_sast_base_api_url=qualysapi.qg3.apps.qualys.com/qps/rest/3.0/ container_data=false kenna_connector_id=15xxxx kenna_api_host=api.sandbox.us.kennasecurity.com kenna_api_key=xxx

For extracting Container vulnerability data in addition to Images:

    toolkit:latest task=checkmarx_sast checkmarx_sast_console=xxx checkmarx_sast_user=xxx checkmarx_sast_password=xxx checkmarx_sast_base_api_url=qualysapi.qg3.apps.qualys.com/qps/rest/3.0/ container_data=true kenna_connector_id=15xxxx kenna_api_host=api.sandbox.us.kennasecurity.com kenna_api_key=xxx
