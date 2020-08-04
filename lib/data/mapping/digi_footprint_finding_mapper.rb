module Kenna
module Toolkit
module Data
module Mapping
class DigiFootprintFindingMapper
  
=begin

DONE - 0 issues of type admin_subdomain
DONE - 0 issues of type leaked_credentials
DONE - 1 issues of type spf_record_malformed
DONE - 0 issues of type spf_record_softfail
DONE - 0 issues of type spf_record_wildcard
DONE - 0 issues of type spf_record_missing
DONE - 5 issues of type csp_no_policy
DONE - 0 issues of type open_resolver
DONE - 1 issues of type x_frame_options_incorrect
DONE - 1 issues of type x_xss_protection_incorrect
DONE - 0 issues of type object_storage_bucket_with_risky_acl
DONE - 0 issues of type hosted_on_object_storage
DONE - 0 issues of type references_object_storage
DONE - 1 issues of type waf_detected
DONE - 0 issues of type dnssec_detected
DONE - ddos_protection
DONE - 0 issues of type csp_unsafe_policy
DONE - 0 issues of type csp_too_broad
DONE - 0 issues of type service_cassandra
DONE - 0 issues of type service_couchdb
DONE - 0 issues of type service_elasticsearch
DONE - 0 issues of type service_ftp
DONE - 0 issues of type service_imap
DONE - 0 issues of type service_microsoft_sql
DONE - 0 issues of type service_mysql
DONE - 0 issues of type service_pop3
DONE - 0 issues of type service_postgresql
DONE - 0 issues of type service_rdp
DONE - 0 issues of type service_redis
DONE - 0 issues of type service_rsync
DONE - 0 issues of type service_smb
DONE - 0 issues of type service_telnet
DONE - 0 issues of type service_mongodb
DONE - 0 issues of type service_vnc
DONE - 0 issues of type ssh_weak_mac
DONE - 0 issues of type ssh_weak_cipher
DONE - 0 issues of type tlscert_revoked
DONE - 0 issues of type tlscert_self_signed
DONE - 0 issues of type tls_weak_cipher
DONE - 0 issues of type tlscert_expired
DONE - 0 issues of type tlscert_weak_signature
DONE - 0 issues of type tlscert_no_revocation
DONE - 0 issues of type chatter
DONE - 3 issues of type hsts_incorrect
DONE - 3 issues of type typosquat

5 issues of type unsafe_sri 
0 issues of type new_booter_shell
0 issues of type new_defacement
0 issues of type non_malware_events_last_month
0 issues of type attack_feed
0 issues of type employee_satisfaction
0 issues of type github_information_leak_disclosure
0 issues of type google_information_leak_disclosure
0 issues of type marketing_site
0 issues of type short_term_lending_site
0 issues of type social_network_issues
0 issues of type tor_node_events_last_month
0 issues of type domain_uses_hsts_preloading
0 issues of type uce
0 issues of type outdated_os
0 issues of type domain_missing_https
2 issues of type insecure_https_redirect_pattern
0 issues of type redirect_chain_contains_http
1 issues of type x_content_type_options_incorrect
0 issues of type exposed_ports
1 issues of type outdated_browser
0 issues of type cookie_missing_http_only
0 issues of type cookie_missing_secure_attribute
0 issues of type patching_cadence_high
0 issues of type patching_cadence_medium
0 issues of type patching_cadence_low
0 issues of type service_vuln_host_high
0 issues of type service_vuln_host_medium
0 issues of type service_vuln_host_low
0 issues of type web_vuln_host_high
0 issues of type web_vuln_host_medium
0 issues of type web_vuln_host_low
0 issues of type service_end_of_life
0 issues of type service_end_of_service
0 issues of type tlscert_excessive_expiration
0 issues of type no_standard_browser_policy
0 issues of type tlscert_extended_validation
0 issues of type malware_1_day
0 issues of type malware_30_day
0 issues of type malware_365_day
0 issues of type tls_ocsp_stapling
0 issues of type ssh_weak_protocol
=end

  def self.get_canonical_vuln_details(orig_source, specific_details)

    ###
    ### Transform the identifier from the upstream source downcasing and
    ### then removing spaces and dashes in favor of an underscore 
    ###
    orig_vuln_id = "#{specific_details["scanner_identifier"]}".downcase.gsub(" ","_").gsub("-","_")

    #orig_description = specific_details["description"]
    #orig_recommendation = specific_details["recommendation"]
    out = {}

    # Do the mapping
    ###################
    self._mapping_data.each do |map|
      map[:matches].each do |match|
        next unless match[:source] == orig_source 
        if match[:vuln_id] =~ orig_vuln_id
          out = {
            scanner_identifier: orig_vuln_id,
            source: "#{orig_source} (Kenna Normalized)",
            name: map[:name],
            cwe_id: map[:cwe],
            description: "#{map[:description]}".strip,
            recommendation: "#{map[:recommendation]}".strip
          }.stringify_keys
        end
      end
    end

    # we didnt map it, so just pass it back
    if out.empty?
      #puts "WARNING! Unable to map canonical vuln for type: #{orig_vuln_id}" 
      out = {
        scanner_identifier: orig_vuln_id,
        source: orig_source,
      }.stringify_keys.merge(specific_details)
    end

  out 
  end

  def self.get_mapping_stats

    stats = {}
    stats[:bitsight] = []
    stats[:expanse] = []
    stats[:intrigue] = []
    stats[:riskiq] = []
    stats[:ssc] = []

    # Collect the count 
    _mapping_data("","").each do |map|
      map[:matches].each do |m|
        stats[:bitsight] << m[:vuln_id] if m[:source] == "Bitsight"
        stats[:expanse]  << m[:vuln_id] if m[:source] == "Expanse"
        stats[:intrigue] << m[:vuln_id] if m[:source] == "Intrigue"
        stats[:riskiq]  << m[:vuln_id] if m[:source] == "RiskIQ"
        stats[:ssc] << m[:vuln_id] if m[:source] == "SecurityScorecard"
      end
    end

    stats.each {|k,v| puts "#{k} #{v.count}" }

  stats
  end


  private

  def self._mapping_data
    [
      {
        name: "Application Content Security Policy Issue",
        cwe: "CWE-358",
        score: 20,
        description: "A problem with this application's content security policy was identified.",
        recommendation: "Update the certificate to include the hostname, or ensuure that clients access the host from the matched hostname..",
        matches: [
          {
            source: "SecurityScorecard",
            vuln_id: /^csp_no_policy$/
          },
          {
            source: "SecurityScorecard",
            vuln_id: /^csp_unsafe_policy$/
          },
          {
            source: "SecurityScorecard",
            vuln_id: /^csp_too_broad$/
          }
        ]
      },
      {
        name: "Application Security Content Security Policy",
        cwe: "CWE-693",
        score: 20,
        description: "One or more application security headers was detected missing or misconfigured.",
        recommendation: "Correct the header configuration on the server..",
        matches: [
          #
          {
            source: "Bitsight",
            vuln_id: /^web_application_headers$/
          },
          {
            source: "SecurityScorecard",
            vuln_id: /^x_xss_protection_incorrect$/
          },
          {
            source: "SecurityScorecard",
            vuln_id: /^x_content_type_options_incorrect$/
          },
          {
            source: "SecurityScorecard",
            vuln_id: /^x_frame_options_incorrect$/
          },
        ]
      },
      {
        name: "Application Subresource Integrity",
        cwe: "CWE-358",
        score: 20,
        description: "An unsafe subresource was detected.",
        recommendation: "Update the application's content..",
        matches: [
          {
            source: "SecurityScorecard",
            vuln_id: /^unsafe_sri$/
          }
        ]
      },
      {
      name: "Application Software Version Detected",
      score: 10,
      cwe: "CWE-693",
      description: "Software details were detected.",
      recommendation: "Verify this is not leaking sensitive data:.",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^server_software$/
        },
        {
          source: "Expanse",
          vuln_id: /^application_server_software$/
        }, 
        {
          source: "Expanse",
          vuln_id: /^server_software$/
        }, 
        {
          source: "Expanse",
          vuln_id: /^detected_webserver$/
        }
      ]
    },
    {
      name: "Database Server Detected",
      score: 60,
      cwe: "CWE-693",
      description: "System was detected.",
      recommendation: "Verify this is expected:.",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^detected_server_mysql$/
        },
        {
          source: "RiskIQ",
          vuln_id: /^open_db_port_tcp$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^service_mysql$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^service_microsoft_sql$/
        }
      ]
    },
    {
      name: "Cloud Object Storage Host",
      cwe: nil,
      score: 0,
      description: "This resource was detected on cloud storage",
      recommendation: "this is an informational finding",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^hosted_on_object_storage$/
        }
      ]
    },
    {
      name: "Cloud Object Storage Reference",
      cwe: nil,
      score: 0,
      description: "This resource has a link to a resource on cloud storage",
      recommendation: "this is an informational finding",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^references_object_storage$/
        }
      ]
    },
    {
      name: "DDOS Protection Detected",
      cwe: nil,
      score: 0,
      description: "DDOS Protection was detected.",
      recommendation: "This is an informational finding.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^ddos_protection$/
        }
      ]
    },
    {
      name: "Development System Detected",
      score: 30,
      cwe: "CWE-693",
      description: "System fit the pattern of a development system.",
      recommendation: "Verify this system should be exposed:.",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^development_system_detected$/
        }
      ]
    },
    {
      name: "DKIM Key Misconfiguration",
      cwe: "CWE-358",
      score: 20,
      description: "A problem with this domain's DKIM configuration was discovered.",
      recommendation: "Check the DKIM configuration:.",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^dkim_public_key_size_is_less_than$/
        },
        {
          source: "Bitsight",
          vuln_id: /^dkim_this_dkim_record_is_intended_for_testing_purposes*$/
        }
      ]
    },
    {
      name: "Domain Squatting",
      cwe: "CWE-358",
      score: 20,
      description: "A domain typosquat was detected.",
      recommendation: "Contact the registrar.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^typosquat$/
        }
      ]
    },
    {
      name: "DNSSEC Detected",
      cwe: nil,
      score: 0,
      description: "DNSSEC Detected.",
      recommendation: "This is an infomrational finding.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^dnssec_detected$/
        }
      ]
    },
    {
      name: "DNSSEC DS Record Missing",
      cwe: "CWE-298",
      score: 20,
      description: "DNSSEC Misconfiguration.",
      recommendation: "DNSSEC Misconfiguration:.",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^dnskey_record_found_but_no_ds_record_found$/
        }
      ]
    },
    {
      name: "DNSSEC Not Configured",
      cwe: "CWE-298",
      score: 20,
      description: "No DNSSEC Configured.",
      recommendation: "Configure DNSSEC:.",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^dnssec_is_not_configured_on_this_domain$/
        }
      ]
    },
    {
      name: "DNSSEC Parent Zone Not Signed",
      cwe: "CWE-298",
      score: 20,
      description: "DNSSEC Misconfiguration.",
      recommendation: "DNSSEC Misconfiguration:.",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^parent_zone_is_not_signed$/
        }
      ]
    },
    {
      name: "Exposed Cloud Object Storage (S3 Bucket)",
      cwe: "CWE-284",
      score: 80,
      description: "A cloud storage bucket was found with risky ACLss",
      recommendation: "Check the ACLs and adjust if needed.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^object_storage_bucket_with_risky_acl$/
        }
      ]
    },
    {
      name: "Hacker Chatter",
      cwe: "CWE-326",
      score: 10,
      description: "Hacker chatter was detected.",
      recommendation: "Determine if this poses a risk..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^chatter$/
        }
      ]
    },
    {
      name: "Insecure Cookie",
      cwe: "CWE-298",
      score: 20,
      description: "The cookie is missing HTTPOnly flag.",
      recommendation: "Update cookie to include this flag..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^cookie_missing_http_only$/
        },
        {
          source: "Intrigue",
          vuln_id: /^insecure_cookie_detected$/
        }

      ]
    },
    {
      name: "Internal IP Address Exposure",
      score: 10,
      cwe: "CWE-202",
      description: "A subdomain was found pointing to an internal system.",
      recommendation: "Remove the entry from public DNS..",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^internal_ip_address_advertisement$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^admin_subdomain$/
        }
      ]
    },
    {
      name: "Leaked Credentials",
      score: 80,
      cwe: "CWE-359",
      description: "Credentials were found exposed.",
      recommendation: "Revoke the credentials and/or prompt a reset. Examine systems to which the credentials provided access for signs of compromise.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^leaked_credentials$/
        }
      ]
    },
    {
      name: "Load Balancer Detected",
      score: 0,
      cwe: nil,
      description: "A Load balancer was detected",
      recommendation: "This is an informational finding.",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^detected_load_balancer$/
        }
      ]
    },
    {
      name: "Open DNS Resolver",
      score: 80,
      cwe: "CWE-693",
      description: "Some DNS servers perform their hierarchical lookups by means of recursion, and rather than limit the ability to make recursive requests to local or authorized clients, DNS servers referred to as Open Resolvers allow recursive DNS requests from any client. Open Resolvers (especially with the newer RFC specifications supporting extensions to the DNS system such as IPv6 and DNSSEC) require the ability to send DNS replies much larger than their respective requests, and an attacker can abuse this fact to amplify his or her available outgoing bandwidth and subsequently direct it at a target in a DNS Amplification Attack.",
      recommendation: "Disable recursive queries on this DNS REsolver..",
      references: [
        "https://blogs.infoblox.com/ipv6-coe/finding-and-fixing-open-dns-resolvers/"
      ],
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^open_resolver$/
        }
      ]
    },
    
    {
      name: "Sensitive Service Detected",
      score: 10,
      cwe: "CWE-693",
      description: "A System was detected running a potentially sensitive service.",
      recommendation: "Verify this is expected.",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^detected_server_dns$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_ftps$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_pop3$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_sip$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_smtp$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_snmp$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_ssh$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_telnet$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_unencrypted_ftp$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_unencrypted_logins$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^service_\w+$/
        }
        ]
      },
      {
        name: "SSH Misconfiguration",
        cwe: "CWE-358",
        score: 20,
        description: "A problem with this ssh server was detected.",
        recommendation: "Updated the configuration on the SSH server..",
        matches: [
          {
            source: "SecurityScorecard",
            vuln_id: /^ssh_weak_cipher$/
          }, 
          {
            source: "SecurityScorecard",
            vuln_id: /^ssh_weak_mac$/
          }, 
        ]
      },
      {
      name: "SPF Misconfiguration",
      cwe: "CWE-183",
      score: 20,
      description: "This domain has a weak SPF configuration.",
      recommendation: "Correct the SPF configuration on the server..",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^multiple_records_returned_for_both_spf_and_txt_queries\.?$/
        },
        {
          source: "Bitsight",
          vuln_id: /^spf_record_is_ineffective$/
        },
        {
          source: "Bitsight",
          vuln_id: /^spf_record_is_improperly_formatted$/
        },
        {
          source: "Bitsight",
          vuln_id: /^too_many_dns_lookups$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^spf_record_malformed$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^spf_record_softfail$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^spf_record_wildcard$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^spf_record_missing$/
        },

      ]
    },
    {
      name: "SPF Record Missing",
      cwe: "CWE-183",
      score: 20,
      description: "This domain has a weak SPF configuration.",
      recommendation: "Correct the SPF configuration on the server..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^spf_record_missing$/
        },
        {
          source: "Bitsight",
          vuln_id: /^no_spf_record_for_subdomain$/
        },
        {
          source: "Bitsight",
          vuln_id: /^no_spf_record_for_include_or_redirect_domain$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Not Configured)",
      cwe: "CWE-298",
      score: 20,
      description: "This domain is missing SSL.",
      recommendation: "Add SSL..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^domain_missing_https$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Short Certificate Key)",
      cwe: "CWE-298",
      score: 20,
      description: "This certificate's key is short.",
      recommendation: "Replace the certificate..",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^ssl_certificates_rsa_public_key_is_less_than$/
        },
        {
          source: "Expanse",
          vuln_id: /^certificate_short_key$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Long Certificate Expiration)",
      cwe: "CWE-298",
      score: 20,
      description: "This certificate's expiration date is far in the future.",
      recommendation: "Verify the certificate's expiration date..",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^certificate_long_expiration$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Certificate Name Mismatch)",
      cwe: "CWE-298",
      score: 20,
      description: "This server has a certificate that does not match the hostname provided.",
      recommendation: "Update the certificate to include the hostname, or ensuure that clients access the host from the matched hostname..",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^ssl_configurations_certificate_name_mismatch$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Cipher)",
      cwe: "CWE-326",
      score: 20,
      description: "This server has a weak SSL configuration.",
      recommendation: "Correct the SSL configuration on the server..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^tls_weak_cipher$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^ssl_weak_cipher$/
        },
        {
          source: "Intrigue",
          vuln_id: /^weak_cipher_suite_detected$/
        },
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Expired or Expiring Certificate)",
      cwe: "CWE-298",
      score: 60,
      description: "This server has an expired or expiring certificate.",
      references: ["https://www.acunetix.com/vulnerabilities/web/your-ssl-certificate-is-about-to-expire/"],
      recommendation: "Renew or replace the certificate.",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^ssl_certificates_expired_certificate$/
        },
        {
          source: "Expanse",
          vuln_id: /^certificate_expired_when_scanned$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^tlscert_expired$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (HSTS)",
      cwe: "CWE-298",
      score: 20,
      description: "This server incorrectly implements HSTS best practices.",
      recommendation: "Update the configuration..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^hsts_incorrect$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Intermediate Certificate Missing)",
      cwe: "CWE-298",
      score: 20,
      description: "This server has a certificate whose validation chain cannot be verified.",
      references: ["https://knowledge.digicert.com/solution/SO16297.html"],
      recommendation: "Ensure that the certificate is valid..",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^ssl_configurations_missing_intermediate_certificates$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Insecure Redirect Chain)",
      cwe: "CWE-298",
      score: 20,
      description: "A non-ssl endpoint was detected in the redirect chain.",
      recommendation: "Ensure that all endpoints in the chain are encrypted..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^redirect_chain_contains_http$/
        }, 
        {
          source: "SecurityScorecard",
          vuln_id: /^insecure_https_redirect_pattern$/
        }, 
        
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Other)",
      cwe: "CWE-326",
      score: 40,
      description: "This server has a weak SSL configuration.",
      recommendation: "Correct the SSL configuration on the server..",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^insecure_signature_certificate_advertisement$/
        },
        {
          source: "Bitsight",
          vuln_id: /^ssl_certificates_large_number_of_dns_names$/
        },
        {
          source: "Bitsight",
          vuln_id: /^ssl_certificates_symantec_certificate_distrusted$/
        },
        {
          source: "Bitsight",
          vuln_id: /^ssl_configurations_diffie-hellman_prime_is_less_than$/
        },
        {
          source: "Bitsight",
          vuln_id: /^ssl_configurations_short_diffie-hellman_prime_is_very_common$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^tlscert_no_revocation/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Revoked Certificate)",
      cwe: "CWE-299",
      score: 50,
      description: "This server has a revoked certificate.",
      recommendation: "Replace the certificate..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^tlscert_revoked$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Self-Signed or Self-Issued Certificate)",
      cwe: "CWE-298",
      score: 20,
      description: "This server has a self-signed certificate.",
      recommendation: "Replace the certificate with one that can be validated..",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^ssl_certificates_self-signed_certificate$/
        },
        {
          source: "Bitsight",
          vuln_id: /^ssl_configurations_certificate_with_non-standard_root$/
        },
        {
          source: "Expanse",
          vuln_id: /^certificate_self_signed$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^tlscert_self_signed$/
        },
        {
          source: "Intrigue",
          vuln_id: /^self_signed_certificate$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Weak Signature)",
      cwe: "CWE-326",
      score: 40,
      description: "This server has a weak SSL configuration.",
      recommendation: "Correct the SSL configuration on the server..",
      matches: [
        
        {
          source: "Bitsight",
          vuln_id: /^ssl_certificates_insecure_signature_algorithm_sha1$/
        },  
        {
          source: "SecurityScorecard",
          vuln_id: /^tlscert_weak_signature$/
        },
        {
          source: "Expanse",
          vuln_id: /^certificate_insecure_signature$/
        }
      ]
    },
    {
      name: "SSL/TLS Configuration (Wildcard Certificate)",
      cwe: "CWE-298",
      score: 0,
      description: "Wildcard certificate detected.",
      recommendation: "No action required..",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^wildcard_certificate$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Protocol)",
      cwe: "CWE-326",
      score: 50,
      description: "This server has a weak SSL protocol.",
      recommendation: "Correct the allowed protocols on the server..",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^ssl_configurations_allows_insecure_protocol_sslv3$/
        },
        {
          source: "Bitsight",
          vuln_id: /^ssl_configurations_allows_insecure_protocol_tlsv1.0$/
        },
        {
          source: "Bitsight",
          vuln_id: /^ssl_configurations_allows_insecure_protocol_sslv2$/
        },
        {
          source: "Intrigue",
          vuln_id: /^deprecated_protocol_detected$/
        }
      ]
    },
    {
      name: "System Flagged as Spam",
      cwe: "CWE-358",
      score: 30,
      description: "A system was identified on a spam blacklist.",
      recommendation: "Ensure the system has not been compromised..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^uce$/
        }
      ]
    },
    {
      name: "System Running File-Sharing Software",
      cwe: "CWE-358",
      score: 30,
      description: "A system was identified on a file-sharing network.",
      recommendation: "Ensure the system has not been compromised..",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^insecure_systems_file_sharing_tracker$/
        }
      ]
    },
    {
      name: "System Running Outdated Browser Software",
      score: 10,
      cwe: "CWE-693",
      description: "A system was identified running an outdated browser.",
      recommendation: "Update the system..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^outdated_browser$/
        },
      ]
    },
    {
      name: "WAF Protection Detected",
      cwe: nil,
      score: 0,
      description: "WAF Protection was detected.",
      recommendation: "This is an informational finding.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^waf_detected$/
        }
      ]
    },
  ]
  end

end
end
end
end
end