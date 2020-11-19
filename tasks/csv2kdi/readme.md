# CSV Converstion to Kenna KDI JSON Format & ingest to Kenna Platform

## This Task will take a CSV (utf-8) file as input and utilize the metafile to map the field for conversion into the Kenna KDI JSON format
## More information on the Kenna KDI can be found at help.kennasecurity.com
## A non-toolkit version of the script can be found at

This script will transform csv files into json that can be consumed by the Kenna Data Importer. It also can process assets only if required.


Meta Data file
Notes show fields that are required to be mapped. Column can reference the column name if the source data file has headers or the column index if there are no headers.

locator column is required and is used to deduplicate data in the script itself. Additional deduplication may occur in Kenna after the upload depend on the set locator preference order.

## Options


- Task Option: csv_in (string)              | Required? false | CSV to be converted to KDI JSON
               (default: "input.csv")
- Task Option: has_header (string)          | Required? false | Does the input file have a header?
               (default: "true")
- Task Option: meta_file (string)           | Required? false | File to map input to Kenna fields
               (default: "meta.csv")
- Task Option: skip_autoclose (string)      | Required? false | If vuln not in scan, do you want to close vulns?
               (default: "false")
- Task Option: assets_only (string)         | Required? false | Field to indicate assets only - no vulns
               (default: "false")
- Task Option: domain_suffix (string)       | Required? false | Optional domain suffix for hostnames
               (default: nil)
- Task Option: input_directory (string)     | Required? false | Where input files are found. Path is relative to /opt/app/toolkit/
               (default: "input")
- Task Option: output_directory (string)    | Required? false | If set, will write a file upon completion. Path is relative to /opt/app/toolkit/
               (default: "output")
- Task Option: kenna_api_host (string)      | Required? false | Host used for the API endpoint
               (default: "api.kennasecurity.com")
- Task Option: kenna_connector_id (integer) | Required? false | ID required for connector to ingest file converted
               (no default)
- Task Option: kenna_api_key (string)       | Required? false | Kenna API code to be used to ingest (get from Kenna platform under "user" menu
               (no default)

Example command to get task help for csv2kdi:
docker run -it --rm toolkit:latest task=csv2kdi:help

Example command
docker run -it --rm \
       -v ~/input:/opt/app/toolkit/input \
	   -v ~/output:/opt/app/toolkit/output \
	   toolkit:latest task=csv2kdi:csv_in=input.csv:meta_file=metafile.csv:kenna_connector_id=156373:kenna_api_key=APICODE-KEY

	   ( Note: on -v option: Example above would have the ~/input resides on host and /opt/app/toolkit/input resides in the container )
     ( Note - 2: The container will run as the default user starting it so therefore will need perms to write to the mounted output volume or change perms appropriately)

Sample run output:
dzq6k6@Kenna-Gerhart:/mnt/c/Users/toby/OneDrive/Documents/GitHub/toolkit$ docker run -it --rm \
       -v ~/input:/opt/app/toolkit/input \
	   -v ~/output:/opt/app/toolkit/output \
	   toolkit:latest task=csv2kdi:csv_in=input.csv:meta_file=metafile.csv:kenna_connector_id=156373:kenna_api_key=place_APIKEY_here

Running: Kenna::Toolkit::Csv2kdi
[+] (20201024133027) Setting csv_in to default value: input.csv
[+] (20201024133027) Setting has_header to default value: true
[+] (20201024133027) Setting meta_file to default value: meta.csv
[+] (20201024133027) Setting skip_autoclose to default value: false
[+] (20201024133027) Setting assets_only to default value: false
[+] (20201024133027) Setting input_directory to default value: input
[+] (20201024133027) Setting output_directory to default value: output
[+] (20201024133027) Setting kenna_api_host to default value: api.kennasecurity.com
[+] (20201024133027) Got option: task: csv2kdi
[+] (20201024133027) Got option: csv_in: input.csv
[+] (20201024133027) Got option: meta_file: metafile.csv
[+] (20201024133027) Got option: kenna_connector_id: 156373
[+] (20201024133027) Got option: kenna_api_key: F*******whz
[+] (20201024133027) Got option: has_header: true
[+] (20201024133027) Got option: skip_autoclose: false
[+] (20201024133027) Got option: assets_only: false
[+] (20201024133027) Got option: domain_suffix:
[+] (20201024133027) Got option: input_directory: input
[+] (20201024133027) Got option: output_directory: output
[+] (20201024133027) Got option: kenna_api_host: api.kennasecurity.com
[+] (20201024133027)
[+] (20201024133027) Launching the csv2kdi task!
[+] (20201024133027)
[+] (20201024133029) Output is available at: /opt/app/toolkit/output/kdiout156373_20201024133028.json
[+] (20201024133029) Attempting to upload to Kenna API at api.kennasecurity.com
[+] (20201024133029) Attempting to upload to Kenna API
[+] (20201024133029) Kenna API host: api.kennasecurity.com
[+] (20201024133029) Sending request
[+] (20201024133031) Success!
[+] (20201024133051) Kenna Data Importer-toolkit connector running!
[+] (20201024133112) Kenna Data Importer-toolkit connector running!
[+] (20201024133127) Done!
