
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

## Running on GitHub Actions

You can run the Toolkit on GitHub Actions using your CI/CD available minutes.

Please, refer to these [detailed instructions](https://github.com/KennaSecurity/All_Samples/tree/master/no_server_toolkit_run_git_actions).

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

To see the current tasks available please visit the Tasks Library [here](https://github.com/KennaSecurity/toolkit/tree/main/tasks/readme.md)

## Advanced Usage

---

Proxy:
If you need to use a proxy with this container the suggested implementation is to use the built-in [Docker](https://docs.docker.com/network/proxy/) or [Podman](https://access.redhat.com/solutions/3939131) proxy support.

## Help us become better

---

When you find an error, please create a GitHub issue with a detailed description of the error. Our team will solve it as
soon as possible. [Instructions for creating an issue.](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-an-issue)

Please send all toolkit feature requests to kenna.toolkit.list@cisco.com.

## Development

---

You can find connector development documentation in the project [Wiki](https://github.com/KennaSecurity/toolkit/wiki/Toolkit-Documentation)

## CONTRIBUTORS

- @kenna-bmcdevitt (api client)
- @linda (original scripts)
- @jgamblin (container work)
- @dbro (initial implementation and testing, various tasks)
- @jcran (initial implementation, various tasks)
- @jdoss (container work)
- @caleb-eckenwiler (Documentation)

## Security Badges

![Lint Code Base](https://github.com/KennaPublicSamples/toolkit/workflows/Lint%20Code%20Base/badge.svg)
![Bundler Audit](https://github.com/KennaPublicSamples/toolkit/workflows/Bundler%20Audit/badge.svg)
