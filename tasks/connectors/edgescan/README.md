## Support

For all issues and inquiries relating to this toolkit implementation, contact Edgescan support at: shout@edgescan.com.

## Prerequisites

This task communicates with the Edgescan and Kenna APIs. To do it, use the following information:

#### From Edgescan:

- Edgescan API token

#### From Kenna:

- Kenna API key
- Kenna connector ID

## Running a Task

For more detailed information about running the task, see [here](https://github.com/KennaSecurity/toolkit/blob/master/README.md).
Here are some quick examples:

- To print a list of available options: `docker run -it --rm kennasecurity/toolkit:latest task=edgescan option=help`
- To sync all Edgescan data into Kenna: `docker run -it --rm kennasecurity/toolkit:latest task=edgescan edgescan_token='abc' kenna_api_key='abc' kenna_connector_id=123`

## Types of Exports

The connector exports all open vulnerabilities and their corresponding assets from Edgescan.
By default, the vulnerabilities are application and network types, and you can disable both types.

## List of Available Options

> **Note:** To see the following list on your console, run `docker run -it --rm toolkit:latest task=edgescan option=help`.

| Option             | Required | Description                                                                  | Default                  |
| ------------------ | -------- | ---------------------------------------------------------------------------- | ------------------------ |
| edgescan_token     | true     | Edgescan token                                                               | none                     |
| edgescan_page_size | false    | Number of records to bring back with each page request from Edgescan         | 100                      |
| edgescan_api_host  | false    | Edgescan API hostname                                                        | live.edgescan.com        |
| kenna_api_key      | true     | Kenna API key                                                                | none                     |
| kenna_connector_id | true     | Kenna connnector ID                                                          | none                     |
| kenna_api_host     | false    | Kenna API hostname                                                           | api.us.kennasecurity.com |
| output_directory   | false    | The task will write JSON files here (path is relative to the base directory) | output/edgescan          |
| create_findings    | false    | The task will create findings, instead of vulnerabilities                    | false                    |
| network_vulns      | false    | The task will include network layer vulnerabilities                          | true                     |
| application_vulns  | false    | The task will include application layer vulnerabilities                      | true                     |
| assets_from_hosts  | false    | The task will create assets from hosts only, instead of location specifiers  | false                    |

## Data Mappings

Edgescan assets do not map directly to Kennna assets because Edgescan assets are more flexible in their definition.
Edgescan location specifiers and hosts are more like Kenna assets. Location specifiers define the location and hosts hold extra information.
Not all location specifiers have a host, and not all vulnerabilities have a directly related location specifier.
## To Create Assets
To create the correct corresponding Kenna assets, the connector uses data from all three of the following sources:

| Kenna Asset       | From Edgescan Host               | Conditions             |
| ----------------- | -------------------------------- | ---------------------- |
| external_id       | "ES#{asset.id} #{host.location}" |                        |
| tags              | asset.tags                       |                        |
| application       | "#{asset.name} (ES#{asset.id})"  | if asset.type == "app" |
| ip_address        | host.location                    |                        |
| hostname          | host.hostnames.first             |                        |
| url               | -                                |                        |
| os_version        | host.os_name                     |                        |

| Kenna Asset       | from Edgescan Location Specifier          | Conditions                |
| ----------------- | ----------------------------------------- | ------------------------- |
| external_id       | "ES#{asset.id} #{specifier.location}"     |                           |
| tags              | asset.tags                                |                           |
| application       | "#{asset.name} (ES#{asset.id})"           | if asset.type == "app"    |
| ip_address        | specifier.location                        | if location is an IP      |
| hostname          | specifier.location                        | if location is a URL      |
| url               | specifier.location                        | if location is a hostname |
| os_version        | -                                         |                           |

> **Note:** Location specifiers of type `cidr` and `block` that define a range of IP addresses will have a Kenna asset for each IP address

| Kenna Asset       | From Edgescan Vulnerability               | Conditions                |
| ----------------- | ----------------------------------------- | ------------------------- |
| external_id       | "ES#{asset.id} #{vulnerability.location}" |                           |
| tags              | asset.tags                                |                           |
| application       | "#{asset.name} (ES#{asset.id})"           | if asset.type == "app"    |
| ip_address        | vulnerability.location                    | if location is an IP      |
| hostname          | vulnerability.location                    | if location is a URL      |
| url               | vulnerability.location                    | if location is a hostname |
| os_version        | -                                         |                           |

| Kenna Vulnerability | From Edgescan Vulnerability    | Conditions                                           |
| ------------------- | ------------------------------ | ---------------------------------------------------- |
| scanner_type        | "EdgescanApp" or "EdgescanNet" | if vulnerability.layer == "application" or "network" |
| scanner_identifier  | vulnerability.definition_id    |                                                      |
| created_at          | vulnerability.created_at       |                                                      |
| last_seen_at        | vulnerability.updated_at       |                                                      |
| scanner_score       | vulnerability.threat * 2       | edgescan threat ranges from 1 to 5                   |
| status              | vulnerability.status           |                                                      |
| details             | vulnerability.details          |                                                      |

| Kenna Finding       | from Edgescan Vulnerability    | Conditions                                           |
| ------------------- | ------------------------------ | ---------------------------------------------------- |
| scanner_type        | "EdgescanApp" or "EdgescanNet" | if vulnerability.layer == "application" or "network" |
| scanner_identifier  | vulnerability.definition_id    |                                                      |
| created_at          | vulnerability.created_at       |                                                      |
| last_seen_at        | vulnerability.updated_at       |                                                      |
| severity            | vulnerability.threat * 2       | edgescan threat ranges from 1 to 5                   |
| additional_fields   | {status, details}              |                                                      |

| Kenna Definition    | From Edgescan Definition       | Conditions                                           |
| ------------------- | ------------------------------ | ---------------------------------------------------- |
| scanner_type        | "EdgescanApp" or "EdgescanNet" | if vulnerability.layer == "application" or "network" |
| scanner_identifier  | definition.id                  |                                                      |
| name                | definition.name                |                                                      |
| description         | definition.description_src     |                                                      |
| solution            | definition.remediation_src     |                                                      |
| cve_identifiers     | definition.cves                |                                                      |
| cwe_identifiers     | definition.cwes                |                                                      |

## For Developers

Use this environment variable to make the task comminicate with `localhost:3000` instead of `live.edgescan.com`:

- `EDGESCAN_ENVIRONMENT="local"`
