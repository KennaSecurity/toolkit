## Running the Cylera task

Cylera provides security, operations, network and clinical data in real-time. Use this toolkit gets data from Cylera.

To run this task, you require the following **Cylera** information:

1. Instance hostname
2. API user email
3. API user password

### Incremental runs
A Cylera task supports incremental runs. Use them run to improve performance, and to pull only the latest changes; rather than pulling all available assets and vulnerabilities everytime.

To benefit from incremental runs in Cylera, store the time or day (if the task is run daily), when the connector is triggered. Also, use the stored time for time-based filtering (such as, cylera_last_seen_after).

In the following incremental run example, use two (2) variables to track when the last successful task run occured to prevent missing data from a task failure.

1. Create a record `last_run_success_time`=`<today - retention period>` in a database of your choice.
2. Create a record `last_attempt_success_time`=`<today>`.
3. Trigger Cylera task with `cylera_last_seen_after`=`last_run_success_time`.
4. If the run was successful, update `last_run_success_time` by setting it to `last_attempt_success_time`.
5. Repeat this process for each connector run.

**Note: To improve efficiency, automate this process with a scheduling tool of your choice.**

## Command Line

For instructions on running tasks, see the main Toolkit. 

**Note:** For instructions on running tasks, see the main Toolkit page.

For this task, you can leave off the Kenna API Key and Kenna Connector ID, so the task creates a .JSON file in the default or specified output directory. You can then review the file, before you upload it directly to the Cisco.

**Use these Recommended Steps:**

1. To ensure you can get data properly from the scanner, run it with **Cylera Keys** only. 
2. Review the data output to ensure you got the expected data.
3. Create the Kenna Data Importer connector in Cisco Vunerability Management  (for example, name it: **Cylera KDI**).
4. Go back to Step 1, and then run the **connector** manually with the .JSON file. 
5. To get the connector ID, click the **connector** name. 
6. Run the task with **Cylera Keys** and **Kenna Key/connector ID**.

**Complete the following list of Options:**

| Option | Required | Description | default |
| --- | --- | --- | --- |
| cylera_api_host | true | Cylera instance hostname, e.g. partner.us1.cylera.com. Must escape hostname in command line script, e.g. \\"partner.us1.cylera.com\\" | n/a |
| cylera_api_user | true | Cylera API user email | n/a |
| cylera_api_password | true | Cylera API user password | n/a |
| cylera_ip_address | false | Partial or complete IP or subnet | n/a |
| cylera_mac_address | false | Partial or complete MAC address | n/a |
| cylera_first_seen_before | false | Finds devices that were first seen before this epoch timestamp | n/a |
| cylera_first_seen_after | false | Finds devices that were first seen after this epoch timestamp | n/a |
| cylera_last_seen_before | false | Finds devices that were last seen before this epoch timestamp | n/a |
| cylera_last_seen_after | false | Finds devices that were last seen after this epoch timestamp | n/a |
| cylera_vendor | false | Device vendor or manufacturer (e.g. Natus) | n/a |
| cylera_type | false | Device type (e.g. EEG) | n/a |
| cylera_model | false | Device model (e.g. NATUS NeuroWorks XLTECH EEG Unit) | n/a |
| cylera_class | false | Device class (e.g. Medical). One of the [Medical, Infrastructure, Misc IoT] | n/a |
| cylera_confidence | false | Confidence in vulnerability detection. One of [LOW, MEDIUM, HIGH] | n/a |
| cylera_detected_after | false | Epoch timestamp after the vulnerability was detected | n/a |
| cylera_name | false | Name of the vulnerability (complete or partial) | n/a |
| cylera_severity | false | Vulnerability severity. One of [LOW, MEDIUM, HIGH, CRITICAL] | n/a |
| cylera_status | false | Vulnerability status. One of the [OPEN, IN_PROGRESS, RESOLVED, SUPPRESSED] | n/a |
| cylera_page | false | Controls the page of results to return | 0 |
| cylera_page_size | false | Controls the number of results in each response. Max 100. | 100 |
| kenna_api_key | false | Uses the Kenna API Key with the connector option | n/a |
| kenna_api_host | false | Kenna API Hostname if not the US shared | api.kennasecurity.com |
| kenna_connector_id | false | If set, tries to upload to this connector | n/a |
| output_directory | false | If set, writes a file after it's complete. Path is relative to #{$basedir} | Output/Cylera |

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
| cve_identifiers | vulnerability.vulnerability_name | If it's a vulnerability, the vulnerability_name starts with "CVE" |
| name | vulnerability.vulnerability_name | |
| solution | "#{mitigation.mitigations}\nAdditional Info\n#{mitigation.additional_info}\nVendor Response\n#{mitigation.vendor_response}" | If a proper value exists |
| descriptions | mitigation.description | If a value exists |
