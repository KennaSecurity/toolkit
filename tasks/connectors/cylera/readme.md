# Running the Cylera task

Cylera provides security, operations, network and clinical data in real time. Use this toolkit task to get data from Cylera.

**Note:** For more information about toolkits and how to use them, see the <a href="https://github.com/KennaSecurity/toolkit" title="README">README</a>.

To run this task, you require the following **Cylera** information:

1. Instance hostname
2. API user email
3. API user password

## Incremental runs

The Cylera task supports incremental runs. Use them to improve performance and pull only the latest changes rather than pulling all available assets and vulnerabilities every time. To benefit from incremental runs in Cylera, store the datetime when the connector is run outside toolkit and provide this value to toolkit for time-based filtering (such as, `cylera_last_seen_after`).

The following steps illustrate using two variables to track when the last successful incremental run occurred and prevent missing data from a task failure.

1. Create a record `last_run_success_time`=`<now - retention period>` in a datastore of your choice.
2. Create a record `last_attempt_success_time`=`<now>`.
3. Trigger Cylera task with `cylera_last_seen_after`=`last_run_success_time`.
4. If the run was successful, update `last_run_success_time` by setting it to `last_attempt_success_time`.
5. Repeat Steps 2-4 each time you run the task.

**Note:** To improve efficiency, automate this process with a scheduling tool of your choice.

## Command Line

For this task, you can leave off the Kenna API key and Kenna connector ID, so the task creates a .json file in the default or specified output directory. You can then review the file before you upload it directly to Cisco Vulnerability Management.

### Recommended Steps

1. Initially, run it with **Cylera keys** only.
2. Review the output .json file to ensure you got the data you expected.
3. Create the Kenna Data Importer connector in Cisco Vulnerability Management. You could name it **Cylera KDI**, for example.
4. Upload the .json file to your connector and run it to verify there are no import errors and you can view Cylera data in Cisco VM.
5. Click the connector name and copy the connector's ID.
6. Run the task with **Cylera keys**, your **Kenna API key** and the **connector ID** to extract data from Cylera, upload it to Cisco, and import it all in one command.

### All Task Options

| Option | Required | Description | default |
| --- | --- | --- | --- |
| cylera_api_host | true | Cylera instance hostname, e.g. partner.us1.cylera.com. Must escape hostname in command line script, e.g. \\"partner.us1.cylera.com\\" | n/a |
| cylera_api_user | true | Cylera API user email | n/a |
| cylera_api_password | true | Cylera API user password | n/a |
| cylera_ip_address | false | Partial or complete IP or subnet | n/a |
| cylera_mac_address | false | Partial or complete MAC address | n/a |
| cylera_first_seen_before | false | Finds devices that were first seen before this epoch timestamp or delta time in seconds | n/a |
| cylera_first_seen_after | false | Finds devices that were first seen after this epoch timestamp or delta time in seconds | n/a |
| cylera_last_seen_before | false | Finds devices that were last seen before this epoch timestamp or delta time in seconds | n/a |
| cylera_last_seen_after | false | Finds devices that were last seen after this epoch timestamp or delta time in seconds | n/a |
| cylera_vendor | false | Device vendor or manufacturer (e.g. Natus) | n/a |
| cylera_type | false | Device type (e.g. EEG) | n/a |
| cylera_model | false | Device model (e.g. NATUS NeuroWorks XLTECH EEG Unit) | n/a |
| cylera_class | false | Device class (e.g. Medical). One of: [Medical, Infrastructure, Misc IoT] | n/a |
| cylera_confidence | false | Confidence in vulnerability detection. One of [LOW, MEDIUM, HIGH] | n/a |
| cylera_detected_after | false | Finds vulnerabilities detected after this epoch timestamp | n/a |
| cylera_name | false | Name of the vulnerability (complete or partial) | n/a |
| cylera_severity | false | Vulnerability severity. One of: [LOW, MEDIUM, HIGH, CRITICAL] | n/a |
| cylera_status | false | Vulnerability status. One of: [OPEN, IN_PROGRESS, RESOLVED, SUPPRESSED] | n/a |
| cylera_page | false | Controls the page of results to return | 0 |
| cylera_page_size | false | Controls the number of results in each response. Max 100. | 100 |
| kenna_api_key | false | Your API key | n/a |
| kenna_api_host | false | API hostname -- Defaults to US API endpoint. | api.kennasecurity.com |
| kenna_connector_id | false | If set, tries to upload to this connector | n/a |
| output_directory | false | If set, saves the output file uploaded to Cisco VM. Path is relative to #{$basedir} | output/cylera |

## Data Mappings

| Kenna Asset | from Cylera Devices | Conditions |
| --- | --- | --- |
| ip_address | device.ip_address | |
| mac_address | device.mac_address | |
| os | device.os | |
| tags | ["Vendor:#{device.vendor}", "Type:#{device.type}", "Model:#{device.model}", "Class:#{device.class}"] | If a proper value exists |

| Cisco Vulnerability | from Cylera Vulnerability | Conditions |
| --- | --- | --- |
| scanner_identifier | vulnerability.vulnerability_name | |
| scanner_type | "Cylera" | |
| scanner_score | vulnerability.severity | |
| created_at | vulnerability.first_seen | |
| last_seen_at | vulnerability.last_seen | |
| status | vulnerability.status | |
| vuln_def_name | vulnerability.vulnerability_name | |

| Cisco Definition | from Cylera Vulnerability and Mitigations | Conditions |
| --- | --- | --- |
| scanner_type | "Cylera" | |
| cve_identifiers | vulnerability.vulnerability_name | If it starts with "CVE" |
| name | vulnerability.vulnerability_name | |
| solution | "#{mitigation.mitigations}\nAdditional Info\n#{mitigation.additional_info}\nVendor Response\n#{mitigation.vendor_response}" | If a proper value exists |
| descriptions | mitigation.description | If a value exists |
