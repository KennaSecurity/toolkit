module Kenna
module Toolkit
module Data
module Mapping
class DigiFootprintFindingMapper
  
=begin
SSC TDDO:
0 issues of type new_booter_shell
0 issues of type new_defacement
0 issues of type employee_satisfaction
0 issues of type marketing_site
0 issues of type short_term_lending_site
0 issues of type no_standard_browser_policy
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
      name: "Compromised System",
      score: 90,
      cwe: "506",
      description: "System was discovered by an attack feed.",
      recommendation: "Check this system for signs of compromise",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^attack_feed$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^malware_1_day$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^malware_30_day$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^malware_365_day$/
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
      name: "End-of-Life (EOL) System or Software",
      cwe: nil,
      score: 0,
      description: "This system was determined to be running software or services that are EOL.",
      recommendation: "Investigate this software to determine if this is intended and if supported options exist.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^outdated_os$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^service_end_of_life$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^service_end_of_service$/
        }        
      ]
    },
    {
      name: "Social Network Accounts Leaking Email Addresses",
      cwe: "CWE-200",
      score: 20,
      description: "Leaked Company Emails Open to Spear-Phishing or other email-based interaction",
      recommendation: "Best practice indicates you should disabld this access.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^social_network_issues$/ # Unsolicited Commercial Email
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
      name: "Github - Sensitive Data Leakage",
      cwe: "CWE-284",
      score: 80,
      description: "Sensitive information was found leaked via Github",
      recommendation: "Investigate and remove the sensitive data if not intended.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^github_information_leak_disclosure$/
        }
      ]
    },
    {
      name: "Google - Sensitive Data Leakage",
      cwe: "CWE-284",
      score: 80,
      description: "Sensitive information was found leaked via Google",
      recommendation: "Investigate and remove the sensitive data if not intended.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^google_information_leak_disclosure$/
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
          source: "SecurityScorecard",
          vuln_id: /^cookie_missing_secure_attribute$/
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
      name: "P2P Activity Detected",
      score: 10,
      cwe: "CWE-506",
      description: "This system was detected with P2P Activity ",
      recommendation: "Check the system for signs of compromise ",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^non_malware_events_last_month$/
        },
      ]
    },
    { # TODO... this should have the CVEs pulled out of it, and should never really match?
      name: "Vulnerability Detected: Vulnerability Patching Cadence",
      cwe: nil,
      score: 0,
      description: "Vulnerability seen on network more than 60 days after CVE was published.",
      recommendation: "Monitor CVE lists and vulnerability repositories for exploit code that may affect your infrastructure.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^patching_cadence_high$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^patching_cadence_medium$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^patching_cadence_low$/
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
          { # NOTE ... many matches here, may need to be split up 
            source: "SecurityScorecard",
            vuln_id: /^service_\w+$/
          }, 
          { # correct place for this? # Open TCP Ports Observed
            source: "SecurityScorecard",
            vuln_id: /^exposed_ports$/
          }
        ]
      },
      {
        name: "SSH Misconfiguration",
        cwe: "CWE-358",
        score: 20,
        description: "A problem with this SSH server's configuration was detected.",
        recommendation: "Updated the configuration on the SSH server.",
        matches: [
          {
            source: "SecurityScorecard",
            vuln_id: /^ssh_weak_cipher$/
          }, 
          {
            source: "SecurityScorecard",
            vuln_id: /^ssh_weak_mac$/
          }, 
          {
            source: "SecurityScorecard",
            vuln_id: /^ssh_weak_protocl$/
          }, 
        ]
      },
      {
      name: "SPF Misconfiguration",
      cwe: "CWE-183",
      score: 20,
      description: "This domain has a weak SPF configuration.",
      recommendation: "Correct the SPF configuration on the server.",
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
      name: "SSL/TLS - Extended Validation Certificate",
      cwe: nil,
      score: 0,
      description: "An extended valiation certificate was found.",
      recommendation: "No action needed, this is an informational finding.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^tlscert_extended_validation$/
        }
      ]
    },
    {
      name: "SSL/TLS - HSTS Configured",
      cwe: nil,
      score: 0,
      description: "",
      recommendation: "No action needed, this is a positive finding",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^domain_uses_hsts_preloading$/
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
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^tlscert_excessive_expiration$/
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
      name: "SSL/TLS Revocation Check (OCSP Stapling Detected)",
      cwe: nil,
      score: 0,
      description: "OCSP Stapling is known as TLS certificate status Request extension used to check the status of certificate revocation of x.509 digital certificate. OCSP is useful for clients who possess limited processing power and memory and even for CAs who have large CRLs (Certificate Revocation Lists). OCSP can provide more appropriate information about the revocation of a certificate than CRL. OCSP can check the certificate issued by CA while CRL only provides the revocation list of serial numbers and therefore, it is possible to detect the usage of fraudulent certificate.",
      references: [
        "https://www.clickssl.net/blog/ocsp-stapling-check-your-certificate-revocation"
      ],
      recommendation: "No action required, this is an informational finding.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^tls_ocsp_stapling$/
        }
      ]
    },
    {
      name: "Subresource Integrity Issues",
      cwe: "CWE-353",
      score: 30,
      description: "Subresource Integrity (SRI) is a security feature that enables browsers to verify that resources they fetch (for example, from a CDN) are delivered without unexpected manipulation. It works by allowing you to provide a cryptographic hash that a fetched resource must match.",
      references: [
        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
      ],
      recommendation: "Ensure the system has not been compromised..",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^unsafe_sri$/
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
          vuln_id: /^uce$/ # Unsolicited Commercial Email
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
      name: "Tor Exit Node Discoverd",
      score: 10,
      cwe: "CWE-506",
      description: "A Tor exit node was discovered",
      recommendation: "Check the system for signs of compromise ",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^tor_node_events_last_month$/
        },
      ]
    },
    {
      name: "Vulnerability Detected - Application Layer",
      cwe: "CWE-200",
      score: 0,
      description: "A vulnerability was detected at the application layer",
      recommendation: "Investigate the vulnerability.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^web_vuln_host_high$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^web_vuln_host_medium$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^web_vuln_host_low$/
        }
      ]
    },
    {
      name: "Vulnerability Detected - OS/System Layer",
      cwe: "CWE-200",
      score: 0,
      description: "A vulnerability was detected at the service or OS layer",
      recommendation: "Investigate the vulnerability.",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^service_vuln_host_high$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^service_vuln_host_medium$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^service_vuln_host_low$/
        }
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
    }
  ]
  end

end
end
end
end
end