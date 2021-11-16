
# ABOUT

The Kenna toolkit is a set of functions for data and api manipulation around the Kenna Security Vulnerability Management platform.  It's organized into 'tasks' - units of functionality that can be called and interacted with from the Docker or Podman command line.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# USAGE

## System Requirements

---

- A container tool capable of running a standalone docker image.
  - [Podman](https://podman.io/)
  - [Docker](https://www.docker.com)
- 8GB RAM
- Network Access

## Running The Latest Image

---

The easiest way to get started is to use the pre-built image on Docker Hub.

A first example that will pull the latest image, and print the list of tasks:

    docker pull kennasecurity/toolkit && docker run -it kennasecurity/toolkit

A slightly more complicated example. Below is a one-liner that will pull the latest image, and execute a task to check your api key.
In this case, the expanse task:

    docker pull kennasecurity/toolkit && docker run -it kennasecurity/toolkit task=kenna_api_key_check kenna_api_key=$KENNA_API_KEY

## Building your own Image

---

If you've made some modifications to the code and/or just want to build the image yourself, you can easily do that.

Then, build the image using the following command:

Building Your Own Image With Docker:

    docker build . -t toolkit:latest

Building Your Own Image With Podman:

    podman build . -t toolkit:latest

## Launching Your Own Container Image

---

Excellent, now you have an image, and are ready to launch it!

Launching Your Own Container Image Docker:

    docker run -it --rm toolkit:latest

Launching Your Own Container Image Podman:

    podman run -it --rm toolkit:latest

If everything's working, lets move on to accessing the toolkit's functionality through tasks.

## Calling A Specific Task

---

In order to utilize the toolkit's functionality, you'll want to pass a 'task=[name of task]' variable. See below for all the possible task names!

Calling A Specific Task WIth Docker:

    docker run -it --rm toolkit:latest task=example

Calling A Specific Task With Podman:

    podman run -it --rm toolkit:latest task=example

## Calling a Task with Arguments

---

Sometimes, you'll need to send arguments to tasks in order to specify how they should behave.

Each task has its own arguments, and the toolkit attempts to make it simple to pass in additional arguments. The format for passing variables in is one big string, separated by spaces. An example:

    'arg1=val1 arg2=val2 arg3=val3'

Task line help and access to available readme.md files are available by invoking the command format:
    docker run -it --rm -t toolkit:latest task=csv2kdi:help      #(task's parameter help)
    docker run -it --rm -t toolkit:latest task=csv2kdi:readme    #(task's readme in a paging format)

Here's an example ('aws_inspector' task) with arguments being passed to it:

Docker:

    docker run -it --rm -t toolkit:latest task=aws_inspector aws_region=us-east-1 aws_access_key=$AWS_ACCESS_KEY aws_secret_key='$AWS_SECRET_KEY'

Podman:

    podman run -it --rm -t toolkit:latest task=aws_inspector aws_region=us-east-1 aws_access_key=$AWS_ACCESS_KEY aws_secret_key='$AWS_SECRET_KEY'

## Getting Data In & Out Of The API

---

Many tasks will require input and output json or log files. The way to handle this is with docker volumes. Volumes can be mapped into the container's OS at runtime.  The toolkit's tasks are programmed to use directories relative to "/opt/toolkit" to facilitate input and output. Specifically, tasks should use these directories as the base when looking for files:

    - Default Input Directory: /opt/toolkit/input
    - Default Output Directory: /opt/toolkit/output

## Configuring Persistent Storage Volumes

---

Below is an example that maps volumes to directories on the local system - both input and output.

Configuring A Volume With Docker:

    docker run  -it --rm \
    -v ~/Desktop/toolkit_input:/opt/app/toolkit/input \
    -v ~/Desktop/toolkit_output:/opt/app/toolkit/output \
    -t toolkit:latest task=example

Configuring A Volume With Podman:

    podman run  -it --rm \
    -v ~/Desktop/toolkit_input:/opt/app/toolkit/input \
    -v ~/Desktop/toolkit_output:/opt/app/toolkit/output \
    -t toolkit:latest task=example

## Toolkit Capabilities (TASKS)

---

These are the current tasks available:

- aqua: This task pulls assets and vulnerabilities from Aqua and translates them into KDI JSON which is consumed by the Kenna platform
- aws_guardduty: This task pulls results from AWS GuardDuty API and translates them into KDI JSON
- aws_inspector: This task pulls results from AWS inspector API and translates them into KDI JSON
- bitsight: This task connects to the Bitsight API and pulls results into the Kenna Platform.
- cobaltio: This task connects to the Cobalt.io API and pulls findings into the Kenna Platform.
- contrast: This task connects to the Contrast Security API and pulls results into the Kenna Platform.
- csv2kdi: This task converts a csv formatted file to the Kenna JSON & optionally pulls results into Kenna
- edgescan: Pulls assets and vulnerabilitiies from Edgescan
- expanse: This task connects to the Expanse API and pulls results into the Kenna Platform.
- generator: This task generates some demo data in KDI format
- kenna_api_key_check: This task simply verifies a Kenna API token vs a given host
- ms_defender_atp: Pulls assets and vulnerabilities from Microsoft Defenders ATP
- nozomi: Pulls assets and vulnerabilities/issues from Nozomi Networks
- riskiq: This task connects to the RiskIQ API and pulls results into the Kenna Platform.
- security_scorecard: This task connects to the Security Scorecard API and pulls results into the Kenna Platform.
- snyk: Pulls assets and vulnerabilities from Snyk
- lacework: Pulls assets and vulnerabilities from Lacework
- upload_file: This task uploads a file to a specified connector
- user_role_sync: This task creates users and assigns them to roles via the API
- veracode_asset_vulns: This task pulls data from the Veracode API for the Asset and Vulns model of Kenna AppSec.
- veracode_findings: This task pulls data from the Veracode API for the Findings model of Kenna AppSec.
- qualys_was: This task pulls data from the Qualys Was API and push results into the Kenna Platform. 

## Advanced Usage

---

Proxy:
If you need to use a proxy with this container the suggested implementation is to use the built-in [Docker](https://docs.docker.com/network/proxy/) or [Podman](https://access.redhat.com/solutions/3939131) proxy support.

## Toolkit Task Development

---
The `toolkit/tasks/connectors/_sample_task` folder contains a fully working example that you can clone to use as a
starting point for your connector. We recommend you split the code into 2 sections: the `Task` itself and an `APIclient`.
The API client is responsible only for interactions with the service (scanner) to obtain the data needed by the task.
The `APIClient` can also format the obtained data in order to ease the `Task` process. The `Task` is responsible for the
creation of Kenna objects, upload, and execution of Kenna processes.

The following is a simplified and fully commented code snippet of the entire process and can be used as guideline:
```ruby
def run
  initialize_options # Process set options from command line parameters
  client = Client.new(user_id, user_token) # Instantiate the client using options passed as parameters
  page = 1
  loop do
    page_data = client.get_page(page) # Get data from the client in batches
    page_data.each do |issue| # For each resulting issue ...
      asset = extract_asset(issue) # Builds an asset for Kenna
      finding = extract_finding(issue) # Builds the finding (issue) object for Kenna
      definition = extract_definition(issue) # Builds the issue definition (unique definitions)
      create_kdi_asset_finding(asset, finding) # Creates the association in current Kenna batch
      create_kdi_vuln_def(definition) # Creates the definition (deduplicated) in current Kenna batch
    end
    # Below line uploads current batch to Kenna
    kdi_upload(@output_directory, "report_#{page}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
    break if page_data.empty? # Stop loop if there is no more data
    page += 1
  end
  # Below line starts the import process in Kenna for all uploaded batches
  kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
rescue ApiError => e # Api exception handler for the entire process
  fail_task e.message
end

```

The methods `extract_asset`, `extract_finding` and `extract_definition` should return a hash with JSON data in the format
specified by the [KDI Json Format](https://help.kennasecurity.com/hc/en-us/articles/360026413111-Kenna-Data-Importer-JSON-Connector-).

Depending on the final destination for the data upload, you need to use one of `create_kdi_asset_finding` or `create_kdi_asset_vuln` methods.

**Note that this process runs in a constrained environment and you must wisely use the memory and processor
resources, making use of batching or pagination techniques.** 

Please, refer to the provided sample for specific details on `Client` implementation, exception handling, and log tracing. 

## CONTRIBUTORS

- @kenna-bmcdevitt (api client)
- @linda (original scripts)
- @jgamblin (container work)
- @dbro (initial implementation and testing, various tasks)
- @jcran (initial implementation, various tasks)
- @jdoss (container work)

## Security Badges

![Lint Code Base](https://github.com/KennaPublicSamples/toolkit/workflows/Lint%20Code%20Base/badge.svg)
![Bundler Audit](https://github.com/KennaPublicSamples/toolkit/workflows/Bundler%20Audit/badge.svg)
