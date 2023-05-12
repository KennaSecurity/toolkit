## Running the Cylera task

This toolkit brings in data from Cylera

To run this task you need the following information from Cylera:

1. Cylera instance hostname
2. Cylera api user email
3. Cylera api user password

## Command Line

See the main Toolkit for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a json file in the default or specified output directory. You can review the file before attempting to upload to the Kenna directly.

Recommended Steps:

1. Run with Cylera Keys only to ensure you are able to get data properly from the scanner
2. Review output for expected data
3. Create Kenna Data Importer connector in Kenna (example name: Cylera KDI)
4. Manually run the connector with the json from step 1
5. Click on the name of the connector to get the connector id
6. Run the task with Cylera Keys and Kenna Key/connector id

Complete list of Options:

| Option | Required | Description | default |
| --- | --- | --- | --- |
| cylera_api_host | true | Cylera instance hostname, e.g. http://cylera.example.com:8080 . Must escape hostname in command line script, e.g. \\"http://cylera.example.com:8080\"  | n/a |
| cylera_api_user | true | Cylera API user email | n/a |
| cylera_api_password | true | Cylera API user password | n/a |
| cylera_confidence | false | Confidence in vulnerability detection. One of [LOW, MEDIUM, HIGH] | n/a |
| cylera_detected_after | false | Epoch timestamp after which a vulnerability was detected | n/a |
| cylera_mac_address | false | MAC address of device | n/a |
| cylera_name | false | Name of the vulnerability (complete or partial) | n/a |
| cylera_severity | false | Vulnerability severity. One of [LOW, MEDIUM, HIGH, CRITICAL] | n/a |
| cylera_status | false | Vulnerability status. One of [OPEN, IN_PROGRESS, RESOLVED, SUPPRESSED] | n/a |
| page | false | Controls which page of results to return | 0 |
| page_size | false | Controls number of results in each response. Max 100. | 100 |
| kenna_api_key | false | Kenna API Key for use with connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not US shared | api.kennasecurity.com |
| kenna_connector_id | false | If set, we'll try to upload to this connector | n/a |
| output_directory | false | If set, will write a file upon completion. Path is relative to #{$basedir} | output/cylera |

## Data Mappings

| Kenna Asset | from Cylera Vulnerability | Conditions |
| --- | --- | --- |
| ip_address | vulnerability.ip_address | |
| mac_address | vulnerability.mac_address | |
| tags | ["Vendor:#{vulnerability.vendor}", "Type:#{vulnerability.type}", "Model:#{vulnerability.model}", "Class:#{vulnerability.class}"] | if proper value exists |

| Kenna Vulnerability | from Cylera Vulnerability | Conditions |
| --- | --- | --- |
| scanner_identifier | vulnerability.vulnerability_name | |
| scanner_type | "Cylera" | |
| scanner_score | vulnerability.severity | |
| created_at | vulnerability.first_seen | |
| last_seen_at | vulnerability.last_seen | |
| status | vulnerability.status | |
| vuln_def_name | vulnerability.vulnerability_name | |

| Kenna Definition | from Cylera Vulnerability and Mitigations | Conditions |
| --- | --- | --- |
| scanner_type | "Cylera" | |
| cve_identifiers | vulnerability.vulnerability_name | if vulnerability.vulnerability_name starts with "CVE" |
| name | vulnerability.vulnerability_name | |
| solution | mitigations | |
