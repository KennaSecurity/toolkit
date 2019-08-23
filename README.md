
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

Each script may have its own arguments, so we make it simple to pass in additional arguments. The format for passing variable in, is one big string, separated by semicolons. For example: 
```
'arg1=val1;arg2=val2;arg3=val3'
```

This format allows us to have a standar interface to the scripts, and to easily pass script-specific arguments in. An example argument string that can be passed to a docker run: 
```
 'kenna_script=hello_world;kenna_api_host=api.kennasecurity.com;kenna_api_key=asdfadsfasdfasdfasdf;arg1=val1;arg2=val2'
```

An Example Run: 
```
$ ARGUMENTS='kenna_api_host=api.kennasecurity.com;kenna_api_key=asdfadsfasdfasdfasdf'
$ docker run -v ~/Desktop/toolkit_output:/opt/app/src/output \
  -v ~/Desktop/toolkit_input:/opt/app/src/input  \
  -t toolkit $ARGUMENTS
```

Getting Data Into the System (and Getting the Output OUT)! 
==========================================================

The Docker image is set up with VOLUMES in order to mount two directories at runtime. One directory for input and another for output. These are configured at runtime, so check the instructions below on how to specify the paths when launching an image.

==============
TOOLKIT TASKS: 
==============

The tasks are currently being converted over from scripts, these are the current tasks available: 

 - asset_upload_tag: This task does uploads assets through the API
 - example: Just an Example.
 - help: Print the Help
 - footprinting_csv_to_kdi: Convert Digital Footprinting CSV files to KDI and upload.
 - user_role_sync: This task creates users and assigns them to roles via the API

==================
TOOLKIT CHANGELOG:
==================
	
20190821:
 - Initial discussions and implementation by @jcran and @dbro

=============
CONTRIBUTORS:
=============
 - @linda
 - @jcran
 - @dbro


