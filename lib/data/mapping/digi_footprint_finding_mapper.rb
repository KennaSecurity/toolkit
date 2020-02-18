module Kenna
module Toolkit
module Data
module Mapping
class DigiFootprintFindingMapper
  
  def self.get_canonical_vuln_details(orig_source, specific_details)

    orig_vuln_id = specific_details["scanner_identifier"]

    orig_description = specific_details["description"]
    orig_recommendation = specific_details["recommendation"]
    out = {}

    # Do the mapping
    ###################
    _mapping_data(orig_description,orig_recommendation).each do |map|
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

  def self._mapping_data(description="",recommendation="")
    [
      {
      name: "Open Port Detected",
      score: 10,
      cwe: "CWE-693",
      description: "An open port was detected. #{description}",
      recommendation: "Verify the port should be open. #{recommendation}",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^open_port_.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^open_port_\d+$/
        },
        {
          source: "Intrigue",
          vuln_id: /^open_port_.*$/
        },
        {
          source: "RiskIQ",
          vuln_id: /^open_port_.*$/
        },
        {
          source: "SecurityScorecard",
          vuln_id: /^exposed_ports$/
        }
      ]
    },
    {
      name: "Application Software Version Detected",
      score: 10,
      cwe: "CWE-693",
      description: "Software details were detected: #{description}",
      recommendation: "Verify this is not leaking sensitive data: #{recommendation}",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^server_software_.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^application_server_software_.*$/
        }, 
        {
          source: "Expanse",
          vuln_id: /^server_software_.*$/
        }, 
        {
          source: "Expanse",
          vuln_id: /^detected_webserver_.*$/
        }
      ]
    },
    {
      name: "Server Detected",
      score: 10,
      cwe: "CWE-693",
      description: "System was detected. #{description}",
      recommendation: "Verify this is expected: #{recommendation}",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^detected_server_dns.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_ftps.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_pop3.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_sip.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_smtp.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_snmp.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_ssh.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_telnet.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_unencrypted_ftp.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^detected_server_unencrypted_logins.*$/
        }
      ]
    },
    {
      name: "Database Server Detected",
      score: 60,
      cwe: "CWE-693",
      description: "System was detected. #{description}",
      recommendation: "Verify this is expected: #{recommendation}",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^detected_server_mysql.*$/
        },
        {
          source: "RiskIQ",
          vuln_id: /^open_db_port_tcp.*$/
        }
      ]
    },
    {
      name: "Load Balancer Detected",
      score: 0,
      cwe: "CWE-693",
      description: "#{description}",
      recommendation: "Verify this is expected. #{recommendation}",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^detected_load_balancer.*$/
        }
      ]
    },
    {
      name: "Development System Detected",
      score: 30,
      cwe: "CWE-693",
      description: "System fit the pattern of a development system: #{description}",
      recommendation: "Verify this system should be exposed: #{recommendation}",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^development_system_detected$/
        }
      ]
    },
    {
      name: "System Flagged as Spam",
      cwe: "CWE-358",
      score: 30,
      description: "A system was identified on a spam blacklist. #{description}",
      recommendation: "Ensure the system has not been compromised. #{recommendation}",
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
      description: "A system was identified on a file-sharing network. #{description}",
      recommendation: "Ensure the system has not been compromised. #{recommendation}",
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
      description: "A system was identified running an outdated browser #{description}",
      recommendation: "Update the system. #{recommendation}",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^outdated_browser$/
        },
      ]
    },
    {
      name: "Application Content Security Policy Issue",
      cwe: "CWE-358",
      score: 20,
      description: "A problem with this application's content security policy was identified. #{description}",
      recommendation: "Update the certificate to include the hostname, or ensuure that clients access the host from the matched hostname. #{recommendation}",
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
      name: "Application Subresource Integrity",
      cwe: "CWE-358",
      score: 20,
      description: "An unsafe subresource was detected. #{description}",
      recommendation: "Update the application's content. #{recommendation}",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^unsafe_sri$/
        }
      ]
    },
    {
      name: "SSH Misconfiguration",
      cwe: "CWE-358",
      score: 20,
      description: "A problem with this ssh server was detected. #{description}",
      recommendation: "Updated the configuration on the SSH server. #{recommendation}",
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
      name: "DKIM Key Misconfiguration",
      cwe: "CWE-358",
      score: 20,
      description: "A problem with this domain's DKIM configuration was discovered: #{description}",
      recommendation: "Check the DKIM configuration: #{recommendation}",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^dkim_public_key_size_is_less_than_.*$/
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
      description: "A domain typosquat was detected: #{description}",
      recommendation: "Contact the registrar. #{recommendation}",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^typosquat$/
        }
      ]
    },
    {
      name: "DNSSEC DS Record Missing",
      cwe: "CWE-298",
      score: 20,
      description: "DNSSEC Misconfiguration: #{description}",
      recommendation: "DNSSEC Misconfiguration: #{recommendation}",
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
      description: "No DNSSEC Configured: #{description}",
      recommendation: "Configure DNSSEC: #{recommendation}",
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
      description: "DNSSEC Misconfiguration: #{description}",
      recommendation: "DNSSEC Misconfiguration: #{recommendation}",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^parent_zone_is_not_signed$/
        }
      ]
    },
    {
      name: "Insecure Cookie",
      cwe: "CWE-298",
      score: 20,
      description: "The cookie is missing HTTPOnly flag. #{description}",
      recommendation: "Update cookie to include this flag. #{recommendation}",
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
      name: "Internal IP Exposure",
      cwe: "CWE-200",
      score: 20,
      description: "An internal ip address has leaked externally. #{description}",
      recommendation: "Verify this information should be exposed. #{recommendation}",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^internal_ip_address_advertisement.*$/
        }
      ]
    },
    {
      name: "Application Security Headers",
      cwe: "CWE-693",
      score: 20,
      description: "One or more application security headers was detected missing or misconfigured. #{description}",
      recommendation: "Correct the header configuration on the server. #{recommendation}",
      matches: [
        #
        {
          source: "Bitsight",
          vuln_id: /^web_application_headers_.*$/
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
      name: "SPF Misconfiguration",
      cwe: "CWE-183",
      score: 20,
      description: "This domain has a weak SPF configuration. #{description}",
      recommendation: "Correct the SPF configuration on the server. #{recommendation}",
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
        }
      ]
    },
    {
      name: "SPF Record Missing",
      cwe: "CWE-183",
      score: 20,
      description: "This domain has a weak SPF configuration. #{description}",
      recommendation: "Correct the SPF configuration on the server. #{recommendation}",
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
          vuln_id: /^no_spf_record_for_include_or_redirect_domain.*$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Not Configured)",
      cwe: "CWE-298",
      score: 20,
      description: "This domain is missing SSL. #{description}",
      recommendation: "Add SSL. #{recommendation}",
      matches: [
      
        {
          source: "SecurityScorecard",
          vuln_id: /^domain_missing_https.*$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Short Certificate Key)",
      cwe: "CWE-298",
      score: 20,
      description: "This certificate's key is short. #{description}",
      recommendation: "Replace the certificate. #{recommendation}",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^ssl_certificates_rsa_public_key_is_less_than_.*$/
        },
        {
          source: "Expanse",
          vuln_id: /^certificate_short_key_.*$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Long Certificate Expiration)",
      cwe: "CWE-298",
      score: 20,
      description: "This certificate's expiration date is far in the future. #{description}",
      recommendation: "Verify the certificate's expiration date. #{recommendation}",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^certificate_long_expiration_.*$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Certificate Name Mismatch)",
      cwe: "CWE-298",
      score: 20,
      description: "This server has a certificate that does not match the hostname provided. #{description}",
      recommendation: "Update the certificate to include the hostname, or ensuure that clients access the host from the matched hostname. #{recommendation}",
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
      description: "This server has a weak SSL configuration. #{description}",
      recommendation: "Correct the SSL configuration on the server. #{recommendation}",
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
      description: "This server has an expired or expiring certificate. #{description}",
      references: ["https://www.acunetix.com/vulnerabilities/web/your-ssl-certificate-is-about-to-expire/"],
      recommendation: "Renew or replace the certificate. #{recommendation}",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^ssl_certificates_expired_certificate$/
        },
        {
          source: "Expanse",
          vuln_id: /^certificate_expired_when_scanned.*$/
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
      description: "This server incorrectly implements HSTS best practices. #{description}",
      recommendation: "Update the configuration. #{recommendation}",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^hsts_incorrect.*$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Intermediate Certificate Missing)",
      cwe: "CWE-298",
      score: 20,
      description: "This server has a certificate whose validation chain cannot be verified. #{description}",
      references: ["https://knowledge.digicert.com/solution/SO16297.html"],
      recommendation: "Ensure that the certificate is valid. #{recommendation}",
      matches: [
        {
          source: "Bitsight",
          vuln_id: /^ssl_configurations_missing_intermediate_certificates.*$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Insecure Redirect Chain)",
      cwe: "CWE-298",
      score: 20,
      description: "A non-ssl endpoint was detected in the redirect chain #{description}",
      recommendation: "Ensure that all endpoints in the chain are encrypted. #{recommendation}",
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
      description: "This server has a weak SSL configuration. #{description}",
      recommendation: "Correct the SSL configuration on the server. #{recommendation}",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^insecure_signature_certificate_advertisement_.*$/
        },
        {
          source: "Bitsight",
          vuln_id: /^ssl_certificates_large_number_of_dns_names_.*$/
        },
        {
          source: "Bitsight",
          vuln_id: /^ssl_certificates_symantec_certificate_distrusted.*$/
        },
        {
          source: "Bitsight",
          vuln_id: /^ssl_configurations_diffie-hellman_prime_is_less_than_.*$/
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
      description: "This server has a revoked certificate. #{description}",
      recommendation: "Replace the certificate. #{recommendation}",
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
      description: "This server has a self-signed certificate. #{description}",
      recommendation: "Replace the certificate with one that can be validated. #{recommendation}",
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
          vuln_id: /^certificate_self_signed.*$/
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
      description: "This server has a weak SSL configuration. #{description}",
      recommendation: "Correct the SSL configuration on the server. #{recommendation}",
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
          vuln_id: /^certificate_insecure_signature.*$/
        }
      ]
    },
    {
      name: "SSL/TLS Configuration (Wildcard Certificate)",
      cwe: "CWE-298",
      score: 0,
      description: "Wildcard certificate detected. #{description}",
      recommendation: "No action required. #{recommendation}",
      matches: [
        {
          source: "Expanse",
          vuln_id: /^wildcard_certificate_.*$/
        }
      ]
    },
    {
      name: "SSL/TLS Misconfiguration (Protocol)",
      cwe: "CWE-326",
      score: 50,
      description: "This server has a weak SSL protocol. #{description}",
      recommendation: "Correct the allowed protocols on the server. #{recommendation}",
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
      name: "Hacker Chatter",
      cwe: "CWE-326",
      score: 10,
      description: "Hacker chatter was detected. #{description}",
      recommendation: "Determine if this poses a risk. #{recommendation}",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^chatter$/
        }
      ]
    },
    {
      name: "SaaS Service Usage",
      cwe: "CWE-326",
      score: 10,
      description: "Saas Service Usage Detected. #{description}",
      recommendation: "Determine if this poses a risk. #{recommendation}",
      matches: [
        {
          source: "SecurityScorecard",
          vuln_id: /^hosted_on_object_storage$/
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