## Running the Whitesource task

This toolkit brings in data from Whitesource.

To run this task, you need the following information from Whitesource:

1. Whitesource user key.
2. Whitesource token for organization, product, or project.
3. Whitesource API base URL.

## Command Line

See the main Toolkit for instructions on running tasks. For this task, if you leave off the Kenna API Key and Kenna Connector ID, the task will create a JSON file in the default or specified output directory. You can review the file before attempting to upload it to Kenna directly.

Recommended Steps:

1. Run with Whitesource Keys only to ensure you are able to get data properly from the scanner.
2. Review output for expected data.
3. Create a Kenna Data Importer connector in Kenna (example name: Whitesource KDI).
4. Manually run the connector with the JSON from step 1.
5. Click on the name of the connector to get the connector ID.
6. Run the task with Whitesource Keys and Kenna Key/connector ID.

**Example Command:**

```shell
docker run -it --rm \
-v ~/Desktop/toolkit_input:/opt/app/toolkit/input \
-v ~/Desktop/toolkit_output:/opt/app/toolkit/output \
-t toolkit:latest task=whitesource:whitesource_user_key=<your_whitesource_user_key>:whitesource_request_token=<your_whitesource_request_token>:whitesource_api_base='"<your_whitesource_api_base_url>"'
```

**Note:** When specifying the `whitesource_api_base` URL, ensure to enclose the URL in single quotes `' '` if it's already surrounded by double quotes `" "`. This is necessary to correctly pass the URL as a parameter.

Complete list of Options:

| Option                    | Required | Description                                                                                                                                                                                                          | Default                |
|---------------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------|
| whitesource_user_key      | true     | Whitesource user key.                                                                                                                                                                                                | n/a                    |
| whitesource_request_type  | false    | One of [organization, product, project]. The corresponding token must be provided.                                                                                                                                   | organization           |
| whitesource_request_token | true     | The token required for the request type e.g., Org token, Product token, Project token. The token for an organization is also known as the API Key.                                                                   | n/a                    |
| whitesource_alert_type    | false    | The type of alert to import. Allowed: NEW_MAJOR_VERSION, NEW_MINOR_VERSION, SECURITY_VULNERABILITY, REJECTED_BY_POLICY_RESOURCE, MULTIPLE_LIBRARY_VERSIONS, HIGH_SEVERITY_BUG, MULTIPLE_LICENSES, REJECTED_DEFACTO_RESOURCE | SECURITY_VULNERABILITY |
| whitesource_days_back     | false    | Get results n days back up to today. Default gets all history.                                                                                                                                                       | n/a                    |
| kenna_batch_size          | false    | Maximum number of issues to retrieve in batches.                                                                                                                                                                     | 100                    |
| kenna_api_key             | false    | Kenna API Key for use with the connector option.                                                                                                                                                                     | n/a                    |
| kenna_api_host            | false    | Kenna API Hostname if not the US shared.                                                                                                                                                                             | api.kennasecurity.com  |
| kenna_connector_id        | false    | If set, we'll try to upload to this connector.                                                                                                                                                                       | n/a                    |
| output_directory          | false    | If set, will write a file upon completion. Path is relative to #{$basedir}.                                                                                                                                          | output/whitesource     |
| whitesource_api_base      | true    | Whitesource API base URL.                                                                                                                                           | n/a                    |
