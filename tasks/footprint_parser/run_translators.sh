#!/bin/bash

echo "[+] Starting translation process!"

MAPPING_FILE="output/mapping.txt"

##Clean mapping file
if [ -f $MAPPING_FILE ]; then
   echo "[+] Removing old mapping.txt file"
   rm -f $MAPPING_FILE
fi

## Run translators
NAME="Security Scorecard Translator"
INPUT=data/parse/ssc/SecurityScorecard_Issues_List.csv 
OUTPUT=output/security_scorecard_issues.json
TRANSLATOR=translators/ssc_csv_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Bitsight Application Security Translator"
INPUT=data/parse/bitsight/bitsight_application_security.csv 
OUTPUT=output/bitsight_application_security.json
TRANSLATOR=translators/bitsight_application_security_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Bitsight DKIM Translator"
INPUT=data/parse/bitsight/bitsight_dkim.csv
OUTPUT=output/bitsight_dkim.json
TRANSLATOR=translators/bitsight_dkim_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Bitsight DNSSec Translator"
INPUT=data/parse/bitsight/bitsight_dnssec.csv
OUTPUT=output/bitsight_dnssec.json
TRANSLATOR=translators/bitsight_dnssec_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Bitsight Open Ports Translator"
INPUT=data/parse/bitsight/bitsight_open_ports.csv
OUTPUT=output/bitsight_open_ports.json
TRANSLATOR=translators/bitsight_open_ports_kdi_translator.rb 
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Bitsight Patching Cadence Translator"
INPUT=data/parse/bitsight/bitsight_patching_cadence.csv
OUTPUT=output/bitsight_patching_cadence.json
TRANSLATOR=translators/bitsight_patching_cadence_kdi_translator.rb 
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Bitsight Server Software Translator"
INPUT=data/parse/bitsight/bitsight_server_software.csv
OUTPUT=output/bitsight_server_software.json
TRANSLATOR=translators/bitsight_server_software_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Bitsight SPF Translator"
INPUT=data/parse/bitsight/bitsight_spf.csv
OUTPUT=output/bitsight_spf.json
TRANSLATOR=translators/bitsight_spf_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Bitsight SSL Certificates Translator"
INPUT=data/parse/bitsight/bitsight_ssl_certificates.csv
OUTPUT=output/bitsight_ssl_certificates.json
TRANSLATOR=translators/bitsight_ssl_certificates_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Bitsight SSL Configurations Translator"
INPUT=data/parse/bitsight/bitsight_ssl_configurations.csv 
OUTPUT=output/bitsight_ssl_configurations.json
TRANSLATOR=translators/bitsight_ssl_configurations_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Bitsight Insecure Systems Translator"
INPUT=data/parse/bitsight/bitsight_insecure_systems.csv
OUTPUT=output/bitsight_insecure_systems.json
TRANSLATOR=translators/bitsight_insecure_systems_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Application Server Software Translator"
INPUT=data/parse/expanse/expanse_application_server_software.csv
OUTPUT=output/expanse_application_server.json
TRANSLATOR=translators/expanse_application_server_kdi_translator.rb 
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED
#
NAME="Expanse Development Environments Translator"
INPUT=data/parse/expanse/expanse_development_environments.csv
OUTPUT=output/expanse_development_environments.json
TRANSLATOR=translators/expanse_development_environments_kdi_translator.rb 
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED
#
NAME="Expanse DNS Servers Translator"
INPUT=data/parse/expanse/expanse_dns_servers.csv
OUTPUT=output/expanse_dns_servers.json
TRANSLATOR=translators/expanse_dns_servers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

# Not sure if this is wanted
#NAME="Expanse Domain Control Validated Certificate Translator"
#INPUT=data/parse/expanse/Expanse-DomainControlValidatedCertificateAdvertisements-3_4_2019.csv
#OUTPUT=output/expanse_domain_control_validated_certificate.json
#TRANSLATOR=translators/expanse_domain_control_validated_certificate_kdi_translator.rb
#echo "[+] Running $NAME"
#ruby $TRANSLATOR $INPUT  > $OUTPUT
#
#cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Expired When Scanned Certificate Translator"
INPUT=data/parse/expanse/expanse_expired_when_scanned_certificate_advertisements.csv
OUTPUT=output/expanse_expired_when_scanned_certificate.json
TRANSLATOR=translators/expanse_expired_when_scanned_certificate_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse FTPs Servers Translator"
INPUT=data/parse/expanse/expanse_ftps_servers.csv
OUTPUT=output/expanse_ftps_servers.json
TRANSLATOR=translators/expanse_ftps_servers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

# Not sure if this is wanted
#NAME="Expanse Healthy Certificate Translator"
#INPUT=data/parse/expanse/Expanse-HealthyCertificateAdvertisements-3_4_2019.csv
#OUTPUT=output/expanse_healthy_certificate.json
#TRANSLATOR=translators/expanse_healthy_certificate_kdi_translator.rb
#echo "[+] Running $NAME"
#ruby $TRANSLATOR $INPUT  > $OUTPUT
#
#cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Insecure Signature Certificate Translator"
INPUT=data/parse/expanse/expanse_insecure_signature_certificate_advertisements.csv
OUTPUT=output/expanse_insecure_signature.json
TRANSLATOR=translators/expanse_insecure_signature_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Internal Ip Advertisement Translator"
INPUT=data/parse/expanse/expanse_internal_ip_address_advertisements.csv
OUTPUT=output/expanse_internal_ip_advertisement.json
TRANSLATOR=translators/expanse_internal_ip_advertisement_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Load Balancer Translator"
INPUT=data/parse/expanse/expanse_load_balancers.csv
OUTPUT=output/expanse_load_balancer.json
TRANSLATOR=translators/expanse_load_balancer_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Long Expiration Certificate Translator"
INPUT=data/parse/expanse/expanse_long_expiration_certificate_advertisements.csv
OUTPUT=output/expanse_long_expiration_certificate.json
TRANSLATOR=translators/expanse_long_expiration_certificate_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse MySQL Servers Translator"
INPUT=data/parse/expanse/expanse_mysql_servers.csv
OUTPUT=output/expanse_mysql_servers.json
TRANSLATOR=translators/expanse_mysql_servers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Open Ports Translator"
INPUT=data/parse/expanse/expanse_open_ports.csv
OUTPUT=output/expanse_open_ports.json
TRANSLATOR=translators/expanse_open_ports_kdi_translator.rb 
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Pop3 Servers Translator"
INPUT=data/parse/expanse/expanse_pop3_servers.csv
OUTPUT=output/expanse_pop3_servers.json
TRANSLATOR=translators/expanse_pop3_servers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Self Signed Certificate Translator"
INPUT=data/parse/expanse/expanse_self_signed_certificate_advertisements.csv
OUTPUT=output/expanse_self_signed_certificate.json
TRANSLATOR=translators/expanse_self_signed_certificate_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Server Software Translator"
INPUT=data/parse/expanse/expanse_server_software.csv
OUTPUT=output/expanse_server_software.json
TRANSLATOR=translators/expanse_server_software_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Short Key Certificate Translator"
INPUT=data/parse/expanse/expanse_short_key_certificate_advertisements.csv
OUTPUT=output/expanse_short_key_certificate.json
TRANSLATOR=translators/expanse_short_key_certificate_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse SIP Servers Translator"
INPUT=data/parse/expanse/expanse_sip_servers.csv
OUTPUT=output/expanse_sip_servers.json
TRANSLATOR=translators/expanse_sip_servers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse SMTP Servers Translator"
INPUT=data/parse/expanse/expanse_smtp_servers.csv
OUTPUT=output/expanse_smtp_servers.json
TRANSLATOR=translators/expanse_smtp_servers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse SNMP Servers Translator"
INPUT=data/parse/expanse/expanse_snmp_servers.csv
OUTPUT=output/expanse_snmp_servers.json
TRANSLATOR=translators/expanse_snmp_servers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse SSH Servers Translator"
INPUT=data/parse/expanse/expanse_ssh_servers.csv
OUTPUT=output/expanse_ssh_servers.json
TRANSLATOR=translators/expanse_ssh_servers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Telnet Servers Translator"
INPUT=data/parse/expanse/expanse_telnet_servers.csv
OUTPUT=output/expanse_telnet_servers.json
TRANSLATOR=translators/expanse_telnet_servers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Unencrypted FTP Servers Translator"
INPUT=data/parse/expanse/expanse_unencrypted_ftp_servers.csv
OUTPUT=output/expanse_unencrypted_ftp_servers.json
TRANSLATOR=translators/expanse_unencrypted_ftp_servers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Unencrypted Logins Translator"
INPUT=data/parse/expanse/expanse_unencrypted_logins.csv 
OUTPUT=output/expanse_unencrypted_logins.json
TRANSLATOR=translators/expanse_unencrypted_logins_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Webservers Translator"
INPUT=data/parse/expanse/expanse_web_servers.csv
OUTPUT=output/expanse_webservers.json
TRANSLATOR=translators/expanse_webservers_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="Expanse Wildcard Certificate Translator"
INPUT=data/parse/expanse/expanse_wildcard_certificate_advertisements.csv
OUTPUT=output/expanse_wildcard_certificate.json
TRANSLATOR=translators/expanse_wildcard_certificate_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="RiskIQ IPs Translator"
INPUT=data/parse/riskiq/riskiq_ips.csv
OUTPUT=output/riskiq_ips.json
TRANSLATOR=translators/riskiq_ips_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="RiskIQ Open Ports Database Translator"
INPUT=data/parse/riskiq/riskiq_open_port_database_servers.csv
OUTPUT=output/riskiq_open_port_database.json
TRANSLATOR=translators/riskiq_open_db_ports_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="RiskIQ Open Ports IOT Translator"
INPUT=data/parse/riskiq/riskiq_open_port_iot.csv
OUTPUT=output/riskiq_open_port_iot.json
TRANSLATOR=translators/riskiq_open_ports_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="RiskIQ Open Ports Networking Equipment Translator"
INPUT=data/parse/riskiq/riskiq_open_port_networking_equipment.csv
OUTPUT=output/riskiq_open_port_networking_equipment.json
TRANSLATOR=translators/riskiq_open_ports_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="RiskIQ Open Ports Registered Translator"
INPUT=data/parse/riskiq/riskiq_open_port_registered.csv
OUTPUT=output/riskiq_open_port_registered.json
TRANSLATOR=translators/riskiq_open_ports_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="RiskIQ Open Ports Remote Access Translator"
INPUT=data/parse/riskiq/riskiq_open_port_remote_access.csv
OUTPUT=output/riskiq_open_port_remote_access.json
TRANSLATOR=translators/riskiq_open_ports_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="RiskIQ Open Ports System Translator"
INPUT=data/parse/riskiq/riskiq_open_port_system.csv
OUTPUT=output/riskiq_open_port_system.json
TRANSLATOR=translators/riskiq_open_ports_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="RiskIQ Open Ports Web Servers Translator"
INPUT=data/parse/riskiq/riskiq_open_port_web_servers.csv
OUTPUT=output/riskiq_open_port_web_servers.json
TRANSLATOR=translators/riskiq_open_ports_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

NAME="RiskIQ Websites Translator"
INPUT=data/parse/riskiq/riskiq_websites.csv
OUTPUT=output/riskiq_websites.json
TRANSLATOR=translators/riskiq_websites_kdi_translator.rb
echo "[+] Running $NAME"
ruby $TRANSLATOR $INPUT  > $OUTPUT
cat $MAPPING_FILE | grep UNMAPPED

echo "[+] Translation Done!"

