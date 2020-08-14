
# ABOUT

The Kenna toolkit is a set of functions for data and api manipulation around the the Kenna Security Vulnerability Management platform.  It's organized into 'tasks' - units of functionality that can be called and interacted with from the Docker or Podman command line.

All the code samples in this GitHub repository are offered “as is” and include no warranty of any kind. Use them at your own risk. In no event will Kenna be liable to end user or any other party for damages of any kind arising from the use of these samples.

# USAGE

# Requirements

## macOS

    - Docker Desktop, or an orchestrator capable of running a standalone docker image
    - 8GB RAM (this is relative, some tasks will require much less memory)

## Linux

    - [Podman](https://podman.io/)

# Running the latest image (from Quay)

The easiest way to get started is to use the pre-built image on Quay.

A first example that will pull the latest image, and print the list of tasks:

    IMAGE="quay.io/kennasecurity/toolkit" && docker pull $IMAGE && docker run -it $IMAGE

A slightly more complicated example. Below is a one-liner that will pull the latest image, and execute a task to check your api key.
In this case, the expanse task:

    IMAGE="docker pull quay.io/kennasecurity/toolkit" && \
    docker pull $IMAGE && docker run -it $IMAGE task=kenna_api_key_check:kenna_api_key=$KENNA_API_KEY

# Building your own Image

If you've made some modifications to the code and/or just want to build the image yourself, you can easily do that.

Then, build the image using the following command:

## Docker

    
    docker build . -t toolkit:latest
    

## Podman

    podman build . -t toolkit:latest

# Launching your own Container Image

Excellent, now you have an image, and are ready to launch it!

## Docker

    docker run -it --rm toolkit:latest
  
## Podman

    podman run -it --rm toolkit:latest

If everything's working, lets move on to accessing the toolkit's functionality through tasks.

## Calling a Specific Task

In order to utilize the toolkit's funcitonality, you'll want to pass a 'task=[name of task]' variable. See below for all the possible task names!

## Docker

    docker run -it --rm toolkit:latest task=example

## Podman

    podman run -it --rm toolkit:latest task=example

## Calling a Task with Arguments

Sometimes, you'll need to send arguments to tasks in order to specify how they should behave.

Each tasks has its own arguments, and the toolkit attempts to make it simple to pass in additional arguments. The format for passing variable in, is one big string, separated by colons. An example:

    'arg1=val1:arg2=val2:arg3=val3'

Here's an example ('aws_inspeector' task) with arguments being passed to it:

## Docker

    docker run -it --rm -t toolkit:latest task=aws_inspector:aws_region=us-east-1:aws_access_key=$AWS_ACCESS_KEY:aws_secret_key='$AWS_SECRET_KEY'

## Podman

    podman run -it --rm -t toolkit:latest task=aws_inspector:aws_region=us-east-1:aws_access_key=$AWS_ACCESS_KEY:aws_secret_key='$AWS_SECRET_KEY'

# Getting Data Into the System (and Getting the Output OUT)

Many tasks will require input and output json or log files. The way to handle this is with docker volumes. Volumes can be mapped into the container's OS at runtime.  The toolkit's tasks are programmed to use directories relative to "/opt/toolkit" to facilitate input and output. Specifically, tasks shoudl use these directories as the base when looking for files:

    - Default Input Directory: /opt/toolkit/input
    - Default Output Directory: /opt/toolkit/output

Below is an example that maps volumes to directories on the local system - both input and output.

## Docker

    docker run  -it --rm \
    -v ~/Desktop/toolkit_input:/opt/toolkit/input \
    -v ~/Desktop/toolkit_output:/opt/toolkit/output \
    -t toolkit:latest task=example

## Podman

    podman run  -it --rm \
    -v ~/Desktop/toolkit_input:/opt/toolkit/input \
    -v ~/Desktop/toolkit_output:/opt/toolkit/output \
    -t toolkit:latest task=example

# TOOLKIT CAPABILITIES (TASKS)

These are the current tasks available:

    [+] ========================================================
    [+]  Welcome to the Kenna Security API & Scripting Toolkit!
    [+] ========================================================
    [ ]
    [ ] Usage:
    [ ]
    [ ] In order to use the toolkit, you must pass a 'task' argument
    [ ] which specifies the function to perform. Each task has a set
    [ ] of required and optional parameters which can be passed to
    [ ] it via the command line.
    [ ]
    [ ] To see the usage for a given tasks, simply pass the task name
    [ ] via the task=[name] argument and the options, separated by colons.
    [ ]
    [ ] For DEBUG output and functionality, set the debug=true option.
    [ ]
    [ ] Example:
    [ ]
    [ ] docker run -it --rm toolkit:latest task=example:option1=true:option2=abc
    [ ]
    [ ] podman run -it --rm toolkit:latest task=example:option1=true:option2=abc
    [ ]
    [ ] At this time, toolkit usage is strictly *UNSUPPORTED*.
    [ ]
    [ ]
    [ ] Tasks:
    [ ] Tasks:
    [+]  - aws_guardduty: This task pulls results from AWS GuardDuty API and translates them into KDI JSON
    [+]  - aws_inspector: This task pulls results from AWS inspector API and translates them into KDI
    [+]  - bitsight: This task connects to the Bitsight API and pulls results into the Kenna Platform.
    [+]  - expanse: This task connects to the Expanse API and pulls results into the Kenna Platform.
    [+]  - footprinting_csv_to_kdi: This task parses digital footprinting data from CSV files into KDI and optionally uploads them.
    [+]  - generator: This task generates some demo data in KDI format!
    [+]  - kenna_api_key_check: This task simply verifies a Kenna AOU token vs a given host
    [+]  - microsoft_atp: Pulls assets and vulnerabilitiies from Microsoft ATP
    [+]  - riskiq: This task connects to the RiskIQ API and pulls results into the Kenna Platform.
    [+]  - upload_file: This task uploads a file to a specified connector
    [ ]

# CONTRIBUTORS

    - @kenna-bmcdevitt (api client)
    - @linda (original scripts)
    - @jgamblin (container work)
    - @dbro (initial implementation and testing, various tasks)
    - @jcran (initial implementation, various tasks)
    - @jdoss (container work)

# Security Badges

![Lint Code Base](https://github.com/KennaPublicSamples/toolkit/workflows/Lint%20Code%20Base/badge.svg)
![Bunlder Audit](https://github.com/KennaPublicSamples/toolkit/workflows/Bunlder%20Audit/badge.svg)
[![Docker Repository on Quay](https://quay.io/repository/kennasecurity/toolkit/status "Docker Repository on Quay")](https://quay.io/repository/kennasecurity/toolkit)
