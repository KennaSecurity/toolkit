## Support

All issues and inquiries relating to this toolkit implementation must contact Edgescan support at `shout@edgescan.com`.

## Prerequisites

This task will communicate with the Edgescan and Kenna APIs. In order to do so it will need the following pieces of information.

#### From Edgescan:

- Edgescan API token

#### From Kenna:

- Kenna API key
- Kenna connector ID

## Running the task

More in depth details about running the task are available [here](https://github.com/KennaSecurity/toolkit/blob/master/README.md).
These are some quick examples:

- To print a list of available options: `docker run -it --rm kennasecurity/toolkit:latest task=edgescan option=help`
- To sync all Edgescan data into Kenna: `docker run -it --rm kennasecurity/toolkit:latest task=edgescan edgescan_token='abc' kenna_api_key='abc' kenna_connector_id=123`

## List of available options

> **Note:** You can also run `docker run -it --rm toolkit:latest task=edgescan option=help` to see this list in your console

| Option             | Required | Description                                                                  | default                  |
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

## For devs

Pass in this env variable to make the task talk to `localhost:3000` instead of `live.edgescan.com`:

- `EDGESCAN_ENVIRONMENT="local"`
