
ABOUT:
======

The Kenna toolkit is a powerful set of functions for data and api manipulation outside of the Kenna platform.  It's organized into 'tasks' - units of functionality that can be called and interacted with from the (docker) command line.

USAGE:
======

Building The Image: 
==================

First, make sure you have Docker installed! Then, build the image using the following command: 

```
toolkit master [20190821]$ docker build . -t toolkit:latest
Sending build context to Docker daemon  695.8MB
Step 1/8 : FROM quay.io/kennasecurity/ruby:2.6.2
 ---> f06698035a65
<snip>
Successfully built toolkit:latest
```

Launching the Docker Image: 
===========================

Excellent, now you have an image, and are ready to launch it!

```
$ docker run -t toolkit:latest
[+] ========================================================      
[+]  Welcome to the Kenna Security API & Scripting Toolkit!       
[+] ========================================================      
[ ]                                                               
<snip> 
```

If everything's working, lets move on to accessing the toolkit's functionality through tasks. 

Calling a Specific Task:
========================

In order to utilize the toolkit's funcitonality, you'll want to pass a 'task=[name of task]' variable. See below for all the possible task names! 

```
$ docker run -t toolkit:latest task=example
```

Calling a Task with Arguments:
==============================

Sometimes, you'll need to send arguments to tasks in order to specify how they should behave. 

Each tasks has its own arguments, and the toolkit attempts to make it simple to pass in additional arguments. The format for passing variable in, is one big string, separated by colons. An example: 
```
'arg1=val1:arg2=val2:arg3=val3'
```

Here's an example ('inspector_to_kdi' task) with arguments being passed to it:

```
docker run task=inspector_to_kdi:aws_region=us-east-1:aws_access_key=$AWS_ACCESS_KEY:aws_secret_key='$AWS_SECRET_KEY'
```



Getting Data Into the System (and Getting the Output OUT)! 
==========================================================

Many tasks will require input and output json or log files.  The toolkit uses directories under /opt/toolkit to facilitate input and output.
 
 - Default Input Directory: /opt/toolkit/input
 - Default Output Directory: /opt/toolkit/output

Below is an example that maps volumes to directories on the local system - both input and output. 

```
$ docker run \
  -v ~/Desktop/toolkit_output:/opt/app/src/output \
  -v ~/Desktop/toolkit_input:/opt/app/src/input \
  -t toolkit:latest task=example
```


TOOLKIT CAPABILITIES (TASKS): 
=============================

These are the current tasks available: 

 - asset_upload_tag: This task does uploads assets through the API
 - example: Just an Example.
 - footprinting_csv_to_kdi: Convert Digital Footprinting CSV files to KDI and upload.
 - inspector_to_kdi: This task hits the AWS Inspector API and outputs the results to a file in the output directory.
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
 

