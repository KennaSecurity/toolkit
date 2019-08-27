
ABOUT:
======

The Kenna toolkit is a powerful set of functions for data and api manipulation outside of the Kenna platform.  

USAGE INSTRUCTIONS:
===================

Building The Image: 
==================

(First, make sure you have Docker installed)

Build the image using the following command: 

```
toolkit master [20190821]$ docker build . -t toolkit:latest
Sending build context to Docker daemon  695.8MB
Step 1/8 : FROM quay.io/kennasecurity/ruby:2.6.2
 ---> f06698035a65
Step 2/8 : LABEL maintainer="Kenna Security"
 ---> Using cache
 ... 
<snip>
 ... 
 ---> 6c825c96c9d7
Step 8/8 : ENTRYPOINT ["./toolkit.sh" ]
 ---> Running in 29e51e6d8537
Removing intermediate container 29e51e6d8537
 ---> ef90eefdb0ce
Successfully built toolkit:latest
```

Launching the Docker Image: 
===========================

Sweet, now you have an image, and are ready to launch it!

The docker image uses docker "volumes" in order to get data into the system and out of it. Below is an example that maps the two volumes. To learn more about how docker volumes work, you can visit this link: https://docs.docker.com/storage/volumes/

Arguments ARE REQUIRED for some scripts, so you'll want to pay close attention to this section. There is a standard way of passing arguments in, and few you'll want to make note of. 
 
 - kenna_script

For scripts that touch the API, you'll need to pass the following in: 
 
 - kenna_api_host
 - kenna_api_key

Each tasks has its own arguments, and the toolkit attempts to make it simple to pass in additional arguments. The format for passing variable in, is one big string, separated by colons. An example: 
```
'arg1=val1:arg2=val2:arg3=val3'
```

The only required argument in all cases is the 'task' argument which specifies the functionality:
```
 'task=example:kenna_api_host=api.kennasecurity.com'
```

An Example Run: 
```
$ docker run \
  -v ~/Desktop/toolkit_output:/opt/app/src/output \
  -v ~/Desktop/toolkit_input:/opt/app/src/input \
  -t toolkit:latest task=example:kenna_api_host=api.kennasecurity.com;kenna_api_key=[REDACTED]
```

Another example run ('translate_aws_inspector_to_kdi' task) with a single mapped volume (output): 
```
docker run -v ~/Desktop/toolkit_output:/opt/toolkit/output toolkit:latest task=translate_aws_inspector_to_kdi:aws_region=us-east-1:aws_access_key=$AWS_ACCESS_KEY:aws_secret_key='$AWS_SECRET_KEY'
```

Getting Data Into the System (and Getting the Output OUT)! 
==========================================================

Volumes can be mounted in docker in order to allow interaction with the local filesystem. One directory for input and another for output are often required. These volumes are configured at runtime, so check the examples above on how to specify the paths when launching an image.


TOOLKIT CAPABILITIES (TASKS): 
=============================

These are the current tasks available: 

 - asset_upload_tag: This task does uploads assets through the API
 - example: Just an Example.
 - footprinting_csv_to_kdi: Convert Digital Footprinting CSV files to KDI and upload.
 - translate_aws_inspector_to_kdi: This task hits the AWS Inspector API and outputs the results to a file in the output directory.
 - user_role_sync: This task creates users and assigns them to roles via the API

TOOLKIT CHANGELOG:
==================

20190827:	
 - Add translate_aws_inspector_to_kdi script
20190821:
 - Initial discussions and implementation by @jcran and @dbro

CONTRIBUTORS:
=============
 - @linda (original scripts, ideas)
 - @jgamblin (docker work,ideas)
 - @jcran (initial implementation, various tasks)
 - @dbro (initial implementation and testing, various tasks)
 

