## Support
For help or any questions related to Synack toolkit task, please contact Synack support at help@synack.com

## About the Synack task

This toolkit task fetches Exploitable Vulnerabilities from Synack platform and ingests them into Kenna.
In Kenna, the Vulnerabilities will be added to an Asset. It will either create new Assets, or map to an existing one if there is a match.

It is recommended to use the option **asset_defined_in_tag** (enabled by default). It allows you to:
- filter the list of Synack Exploitable Vulnerabilities that would be ingested into Kenna
- put the Vulnerabilities in the desired Assets in Kenna

To run this task you need the following information
### From Synack
- Synack API Url. Just the domain name, no prefixes. For example, api.synack.com
- Synack API token

### From Kenna
- Kenna Connector ID
- Kenna API key

## Command Line

See the main Toolkit readme for [general instructions](https://github.com/KennaSecurity/toolkit/blob/master/README.md) on running Kenna toolkit tasks.

For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to Kenna directly.

### Recommended Steps:

1. Run with Synack keys only to ensure you are able to get data properly from Synack
1. Review output for expected data
1. Create Kenna Data Importer connector in Kenna
1. Manually run the connector with the json from step 1
1. Click on the name of the connector to get the connector id
1. Run the task with Synack keys and Kenna key/connector id

### Complete list of Options:

| Option               | Required | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | default               |
|----------------------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------|
| synack_api_host      | false    | Synack API hostname without prefixes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | api.synack.com        |
| synack_api_token     | true     | Synack API token                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | n/a                   |
| kenna_api_key        | false    | Kenna API Key for use with connector option                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | n/a                   |
| kenna_api_host       | false    | Kenna API Hostname                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | api.kennasecurity.com |
| kenna_connector_id   | false    | If set, we'll try to upload to this connector                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | n/a                   |
| kenna_batch_size     | false    | Maximum number of vulnerabilities to upload to Kenna in each batch. Increasing this value could improve performance.                                                                                                                                                                                                                                                                                                                                                                                                   | 1000                  |
| output_directory     | false    | If set, will write a file upon completion. Path is relative to #{$basedir}                                                                                                                                                                                                                                                                                                                                                                                                                                             | output/synack         |
| asset_defined_in_tag | false    | If set to true, we will only fetch from Synack vulnerbilities that have tag starting with "kenna::".<br/>The Kenna asset for vulnerability is defined by the tag "kenna::\<asset locator type\>::\<asset locator value\>".<br/>For example, if your Synack vulnerability has a tag "kenna::url::https\:\/\/www\.cisco\.com" it will be added to asset with locator type URL set to https\:\/\/www\.cisco\.com <br/><br/>If set to false - the assets will be created from Synack vulnerability's vulnerability location field. | true                  |

## Data Mappings

Here is how Synack Vulnerability data fields map to Kenna Vulnerability data

| Kenna Vulnerability Attribute | Synack Vulnerability Attribute (attribute name as seen in the UI) |
|-------------------------------|-------------------------------------------------------------------|
| name                          | title (Title)                                                     |
| scanner_identifier            | id                                                                |
| scanner_type                  | "Synack"                                                          |
| scanner_score                 | cvss_final (Score)                                                |
| description                   | description (Description)                                         |
| solution                      | recommended_fix (Recommended fix)                                 |
| details                       | validation_steps (Steps to Reproduce)                             |
| cve_identifiers               | cve_ids (Reported CVE/CWE Identifiers)                            |
| cwe_identifiers               | cwe_ids (Reported CVE/CWE Identifiers)                            |


If you set **asset_defined_in_tag** to false - the Kenna asset details will be created from Synack Vulnerability's "Vulnerability Locations" field

| Kenna Asset Attribute | Synack Vulnerability Location Attribute        | Condition                                                                           |
|-----------------------|------------------------------------------------|-------------------------------------------------------------------------------------|
| url                   | exploitable_location.value                     | exploitable_location.type == 'url'                                                  |
| application           | assessment.codename exploitable_location.value | exploitable_location.type == 'app-location' or exploitable_location.type == 'other' |
| file                  | exploitable_location.value                     | exploitable_location.type == 'file'                                                 |
| ip_address            | exploitable_location.address                   | exploitable_location.type == 'ip'                                                   |
