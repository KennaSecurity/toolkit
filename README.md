
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

Many tasks will require input and output json or log files. The way to handle this is with docker volumes. Volumes can be mapped into the container's OS at runtime.  The toolkit's tasks are programmed to use directories relative to "/opt/toolkit" to facilitate input and output. Specifically, tasks shoudl use these directories as the base when looking for files:
 
 - Default Input Directory: /opt/toolkit/input
 - Default Output Directory: /opt/toolkit/output

Below is an example that maps volumes to directories on the local system - both input and output. 

```
$ docker run \
  -v ~/Desktop/toolkit_input:/opt/toolkit/input \
  -v ~/Desktop/toolkit_output:/opt/toolkit/output \
  -t toolkit:latest task=example
```

TOOLKIT CAPABILITIES (TASKS): 
=============================

These are the current tasks available: 

```                                                            
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
[ ] For VERBOSE output, set the verbose=true option.                   
[ ]                                                                    
[ ] Example:                                                           
[ ] docker run -it jcran/toolkit:latest toolkit.sh task=example:option1=true:option2=abc              
[ ]                                                                    
[ ] At this time, toolkit usage is strictly UNSUPPORTED.               
[ ]                                                                    
[ ]                                                                    
[ ] Tasks:
[+]  - aws_guardduty: This task pulls results from AWS GuardDuty API and translates them into KDI JSON
[+]  - aws_inspector: This task pulls results from AWS inspector API and translates them into KDI JSON
[+]  - bitsight: This task connects to the Bitsight API and pulls results into the Kenna Platform.
[+]  - expanse: This task connects to the Expanse API and pulls results into the Kenna Platform.
[+]  - footprinting_csv_to_kdi: This task parses digital footprinting data from CSV files into KDI and optionally uploads them.
[+]  - inspect_api_token: This task pulls results from AWS inspector and translates them into JSON
[+]  - riskiq: This task connects to the RiskIQ API and pulls results into the Kenna Platform.
[+]  - upload_file: This task uploads a file to a specified connector
[+]  - user_role_sync: This task creates users and assigns them to roles via the API
[ ]                                                                    
```

CONTRIBUTORS:
=============
 - @kenna-bmcdevitt (api client) 
 - @linda (original scripts)
 - @jgamblin (docker work)
 - @dbro (initial implementation and testing, various tasks)
 - @jcran (initial implementation, various tasks)

