


American Express - Kenna KDI Translators


Preparing to build the Docker file:
===================================

The Dockerfile requrires you to specify an API token and an (optional) hostname. You can do this by passing them as arguments at runtime (see below), or placing your API Token in the .token file before building the image. The default hostname is api.kennasecurity.com, so please specify a hostname if this is not what you want. 

You'll also want to configure the connectors which the results will will be uploaded to. These connectors and their IDs live in the upload_kdi.rb directory. You'll want to have a connector per uploaded file. The connectors are currently configured for the standard US platform api.kennasecurity.com. 

How to Update the Data Files:
=============================

You'll want to update the data files in order to have the most recent data being parsed. This data can be placed in the /data/parse directory, with the structure listed below. The files must be named exactly the same in order to be processed. 

You'll pass both the input and output directories as variables at runtime, so don't worry about getting the files into the image at build time. Once parsed, the files will be uploaded to the Kenna API.

Directory and File Structure: 
=============================

Bitsight: 
	data/parse/bitsight/bitsight_application_security.csv
	data/parse/bitsight/bitsight_dkim.csv
	data/parse/bitsight/bitsight_dnssec.csv
	data/parse/bitsight/bitsight_insecure_systems.csv
	data/parse/bitsight/bitsight_open_ports.csv
	data/parse/bitsight/bitsight_patching_cadence.csv
	data/parse/bitsight/bitsight_server_software.csv
	data/parse/bitsight/bitsight_spf.csv
	data/parse/bitsight/bitsight_ssl_certificates.csv
	data/parse/bitsight/bitsight_ssl_configurations.csv

Expanse: 
	data/parse/expanse/expanse_application_server_software.csv
	data/parse/expanse/expanse_certificate_advertisements.csv
	data/parse/expanse/expanse_development_environments.csv
	data/parse/expanse/expanse_dns_servers.csv
	data/parse/expanse/expanse_expired_when_scanned_certificate_advertisements.csv
	data/parse/expanse/expanse_ftp_servers.csv
	data/parse/expanse/expanse_ftps_servers.csv
	data/parse/expanse/expanse_healthy_certificate_advertisements.csv
	data/parse/expanse/expanse_insecure_signature_certificate_advertisements.csv
	data/parse/expanse/expanse_internal_ip_address_advertisements.csv
	data/parse/expanse/expanse_load_balancers.csv
	data/parse/expanse/expanse_long_expiration_certificate_advertisements.csv
	data/parse/expanse/expanse_mysql_servers.csv
	data/parse/expanse/expanse_netbios_name_servers.csv
	data/parse/expanse/expanse_open_ports.csv
	data/parse/expanse/expanse_pop3_servers.csv
	data/parse/expanse/expanse_rdp_servers.csv
	data/parse/expanse/expanse_self_signed_certificate_advertisements.csv
	data/parse/expanse/expanse_server_software.csv
	data/parse/expanse/expanse_short_key_certificate_advertisements.csv
	data/parse/expanse/expanse_sip_servers.csv
	data/parse/expanse/expanse_smtp_servers.csv
	data/parse/expanse/expanse_snmp_servers.csv
	data/parse/expanse/expanse_ssh_servers.csv
	data/parse/expanse/expanse_telnet_servers.csv
	data/parse/expanse/expanse_unencrypted_ftp_servers.csv
	data/parse/expanse/expanse_unencrypted_logins.csv
	data/parse/expanse/expanse_web_servers.csv
	data/parse/expanse/expanse_wildcard_certificate_advertisements.csv

RiskIQ: 
	data/parse/riskiq/riskiq_ips.csv
	data/parse/riskiq/riskiq_open_port_database_servers.csv
	data/parse/riskiq/riskiq_open_port_iot.csv
	data/parse/riskiq/riskiq_open_port.csv
	data/parse/riskiq/riskiq_open_port_registered.csv
	data/parse/riskiq/riskiq_open_port_remote_access.csv
	data/parse/riskiq/riskiq_open_port_system.csv
	data/parse/riskiq/riskiq_open_port_web_servers.csv
	data/parse/riskiq/riskiq_websites.csv

Security Scorecard: 
	data/parse/ssc/SecurityScorecard_Issues_List.csv

Each file has a "verification" copy of the version that the parser can handle, in the data/archive/ directory. This verification file ensures that we can warn the user if the format is changed, and we can no longer parse successfully. In other words, if an input file changes format or columns, the parser will need to change, and we'd replace the verification file with the new version.

Safeguards around data format:
 - If no API key is configured, the system will raise an error and fail to proceed.
 - If a CSV data file is missing, the system will raise an error and fail to proceed.
 - If a CSV data file is missing a needed column, the system will raise an error and fail to proceed.

As long as the format of input data stays the same, the parsers will work without error!

Building the Docker Image: 
==========================

If you wish, add the hostname and token in the .hostname and .token files respectively, this will ensure the upload script can complete successfully. These variables can also be passed at runtime (preferred for security reasons). 

Now, build the docker image using the following command: 

```footprinting master [20190516]$ docker build .
Sending build context to Docker daemon  695.8MB
Step 1/9 : FROM quay.io/kennasecurity/ruby:2.6.2
 ---> f06698035a65
Step 2/9 : LABEL maintainer="Kenna Security"
 ---> Using cache
 ---> 87b3be74882e
Step 3/9 : USER root
 ---> Using cache
 ---> 2fac44c584cd
Step 4/9 : ADD . /opt/app/src
 ---> Using cache
 ---> d442c658f807
Step 5/9 : WORKDIR /opt/app/src
 ---> Using cache
 ---> 9e694698383d
Step 6/9 : VOLUME  /opt/app/src/output
 ---> Using cache
 ---> f3ab822b37ba
Step 7/9 : RUN gem install bundler
 ---> Running in 1daefb0e8fad
Successfully installed bundler-2.0.1
1 gem installed
Removing intermediate container 1daefb0e8fad
 ---> 16b688a87b4c
Step 8/9 : RUN bundle install
 ---> Running in 5b4049c3c239
Fetching gem metadata from https://rubygems.org/........
Using bundler 2.0.1
Fetching unf_ext 0.0.7.6
Installing unf_ext 0.0.7.6 with native extensions
Fetching unf 0.1.4
Installing unf 0.1.4
Fetching domain_name 0.5.20180417
Installing domain_name 0.5.20180417
Fetching http-cookie 1.0.3
Installing http-cookie 1.0.3
Fetching mime-types-data 3.2019.0331
Installing mime-types-data 3.2019.0331
Fetching mime-types 3.2.2
Installing mime-types 3.2.2
Fetching netrc 0.11.0
Installing netrc 0.11.0
Fetching rest-client 2.0.2
Installing rest-client 2.0.2
Bundle complete! 1 Gemfile dependency, 9 gems now installed.
Bundled gems are installed into `/opt/app/bundle`
Removing intermediate container 5b4049c3c239
 ---> 6c825c96c9d7
Step 9/9 : ENTRYPOINT ["bundle", "exec", "/opt/app/src/run_all.sh" ]
 ---> Running in 29e51e6d8537
Removing intermediate container 29e51e6d8537
 ---> ef90eefdb0ce
Successfully built ef90eefdb0ce```


Launching the Docker Image: 
===========================

Sweet, now you have an image, and are ready to send it some data.

The docker image uses docker "volumes" in order to get data into the system and out of it. Below is an example that maps the two volumes. To learn more about how docker volumes work, you can visit this link: https://docs.docker.com/storage/volumes/

Below, the following variables are passed: 
 - TOKEN = the kenna api token (default: [none]) 
  - HOSTNAME = the kenna api hostname (default: api.kennasecurity.com)


Example run: 
```
$ docker run -v /Users/jcran/Desktop/output:/opt/app/src/output \
  -v /Users/jcran/Desktop/data:/opt/app/src/data  \
  -it ef90eefdb0ce $TOKEN $HOSTNAME

[+] Starting translation process!
[+] Running Security Scorecard Translator
[+] Running Bitsight Application Security Translator
[+] Running Bitsight DKIM Translator
[+] Running Bitsight DNSSec Translator
[+] Running Bitsight Open Ports Translator
[+] Running Bitsight Patching Cadence Translator
<snip>
[+] Running RiskIQ Open Ports Web Servers Translator
[+] Running RiskIQ Websites Translator
[+] Translation Done!
[+] 
[+] Uploading...
20190516T20051558040033 (bitsight_application_security.json): Sending request
20190516T20051558040035 (bitsight_application_security.json): Success!
20190516T20051558040035 (bitsight_application_security.json): Waiting for 30 seconds... 
20190516T20051558040065 (bitsight_application_security.json): Bitsight - Application Security running
20190516T20051558040065 (bitsight_application_security.json): Waiting for 30 seconds... 
20190516T20051558040096 (bitsight_application_security.json): Done!
20190516T20051558040096 (bitsight_dkim.json): Sending request
20190516T20051558040099 (bitsight_dkim.json): Success!
20190516T20051558040099 (bitsight_dkim.json): Waiting for 30 seconds... 
20190516T20051558040129 (bitsight_dkim.json): Bitsight - DKIM running
20190516T20051558040129 (bitsight_dkim.json): Waiting for 30 seconds... 
...
```

Changelog:
==========

	20190722:
	 - Updated to work with runtime arguments and an alternate KPD uri
	 - Updated entrypoint to make further enhancements simpler 

	20190516: 
	 - Initial release
	 - Dockerized scripts 
	 - Updated scripts for Expanse

	20190213:
	 - Updated all translators to use locators of hostname/port/url
	 - Added RiskIQ Website data 

	20190205:
	 - Initial translators for RiskIQ
	 - Initial translators for Expanse
	 - Initial translators for Bitsight
	 - Initial translators for Security Scorecard

