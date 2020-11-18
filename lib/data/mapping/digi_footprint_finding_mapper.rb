module Kenna
  module Toolkit
    module Data
      module Mapping
        class DigiFootprintFindingMapper
          # https://help.bitsighttech.com/hc/en-us/articles/360025011954-Diligence-Finding-Details#patching_cadence
          # Bitsight:
          #  - Domain Squatting - Findings for this risk vector cannot be queried via the API

          def self.get_canonical_vuln_details(orig_source, specific_details, description = "", remediation = "", override_score = true)
            ###
            ### Transform the identifier from the upstream source downcasing and
            ### then removing spaces and dashes in favor of an underscore
            ###
            orig_vuln_id = (specific_details['scanner_identifier']).to_s.downcase.gsub(" ", "_").gsub("-", "_")

            # orig_description = specific_details["description"]
            # orig_recommendation = specific_details["recommendation"]
            out = {}

            # Do the mapping
            ###################
            _mapping_data.each do |map|
              map[:matches].each do |match|
                next unless match[:source] == orig_source

                next unless match[:vuln_id] =~ orig_vuln_id

                out = {
                  scanner_type: orig_source,
                  scanner_identifier: orig_vuln_id.to_s,
                  source: "#{orig_source} (Kenna Normalized)",
                  scanner_score: (map[:score] / 10).to_i,
                  override_score: (map[:score]).to_i,
                  name: map[:name],
                  description: "#{map[:description]}\n\n #{description}".strip,
                  recommendation: "#{map[:recommendation]}\n\n #{remediation}".strip
                }

                # if we're told to override the score, override it
                out[:override_score] = map[:score].to_i if override_score

                # only add in cwe_identifiers if we have a valid CWE
                # if map[:cwe]
                #  out[:cwe_identifiers] = "#{map[:cwe]}"
                # end

                out = out.stringify_keys
              end
            end

            # we didnt map it, so just pass it back
            if out.empty?
              # puts "WARNING! Unable to map canonical vuln for type: #{orig_vuln_id}"
              out = {
                scanner_identifier: orig_vuln_id,
                scanner_type: orig_source,
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
            _mapping_data("", "").each do |map|
              map[:matches].each do |m|
                stats[:bitsight] << m[:vuln_id] if m[:source] == "Bitsight"
                stats[:expanse]  << m[:vuln_id] if m[:source] == "Expanse"
                stats[:intrigue] << m[:vuln_id] if m[:source] == "Intrigue"
                stats[:riskiq] << m[:vuln_id] if m[:source] == "RiskIQ"
                stats[:ssc] << m[:vuln_id] if m[:source] == "SecurityScorecard"
              end
            end

            stats.each { |k, v| puts "#{k} #{v.count}" }

            stats
          end

          def self._mapping_data
            [
              {
                name: "Application Content Security Policy Issue",
                # cwe: "CWE-358",
                score: 20,
                description: "A problem with this application's content security policy was identified.",
                recommendation: "Update the certificate to include the hostname, or ensuure that clients access the host from the matched hostname.",
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
                name: "Application Security Headers",
                # cwe: "CWE-693",
                score: 20,
                description: "One or more application security headers was detected missing or misconfigured.",
                recommendation: "Correct the header configuration on the server.",
                matches: [
                  {
                    source: "Bitsight",
                    vuln_id: /^web_application_headers$/
                  },
                  {
                    source: "Bitsight",
                    vuln_id: /^application_security$/
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
                # cwe: "CWE-358",
                score: 20,
                description: "An unsafe subresource was detected.",
                recommendation: "Update the application's content.",
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
                # cwe: "CWE-693",
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
                  },
                  # {
                  #  source: "Expanse",
                  #  vuln_id: /^web_servers?$/
                  # }
                ]
              },
              {
                name: "Browser Software Inconsistent",
                score: 10,
                # cwe: "CWE-671",
                description: "Multiple browser software packages detected.",
                recommendation: "Verify this is expected",
                matches: [
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^no_standard_browser_policy$/
                  },
                ]
              },
              {
                name: "Client Software Outdated or Vulnerable",
                score: 10,
                # cwe: "CWE-693",
                description: "A system was identified running an outdated browser or other client software.",
                recommendation: "Update the system.",
                matches: [
                  {
                    source: "Bitsight",
                    vuln_id: /^mobile_software$/
                  },
                  {
                    source: "Bitsight",
                    vuln_id: /^desktop_software$/
                  },
                  {
                    source: "Bitsight",
                    vuln_id: /^insecure_systems$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^outdated_browser$/
                  },
                ]
              },
              {
                name: "Compromised Application",
                score: 90,
                # cwe: "CWE-506",
                description: "System was discovered by an attack feed.",
                recommendation: "Check this application for signs of compromise",
                matches: [
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^new_booter_shell$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^new_defacement$/
                  }
                ]
              },
              {
                name: "Compromised System",
                score: 90,
                # cwe: "CWE-506",
                description: "System was discovered by an attack feed. It may be compromised by malware or a bot.",
                recommendation: "Check this system for signs of compromise",
                matches: [
                  {
                    source: "Bitsight",
                    vuln_id: /^potentially_exploited$/
                  },
                  {
                    source: "Bitsight",
                    vuln_id: /^botnet_infections$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^attack_feed$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^attack_detected$/
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
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^suspicious_traffic$/
                  }
                ]
              },
              {
                name: "Database Server Detected",
                score: 60,
                # cwe: "CWE-693",
                description: "System was detected.",
                recommendation: "Verify this is expected:.",
                matches: [
                  {
                    source: "Expanse",
                    vuln_id: /^detected_server_mysql$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^ms_sql_servers?$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^my_sql_servers?$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^sharepoint_servers?$/
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
                name: "Development System Detected",
                score: 30,
                # cwe: "CWE-693",
                description: "System fit the pattern of a development system.",
                recommendation: "Verify this system should be exposed:.",
                matches: [
                  {
                    source: "Expanse",
                    vuln_id: /^development_system_detected$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^development_environments?$/
                  }
                ]
              },
              {
                name: "DKIM Misconfiguration",
                # cwe: "CWE-358",
                score: 20,
                description: "A problem with this domain's DKIM configuration was discovered.",
                recommendation: "Check the DKIM configuration:.",
                matches: [
                  {
                    source: "Bitsight",
                    vuln_id: /^dkim$/
                  }
                ]
              },
              {
                name: "Domain Squatting",
                # cwe: "CWE-358",
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
                name: "DNSSEC Misconfiguration",
                # cwe: "CWE-298",
                score: 20,
                description: ".",
                recommendation: "See specifics for more detail about the DNSSEC misconfiguration.",
                matches: [
                  {
                    source: "Bitsight",
                    vuln_id: /^dnssec$/
                  }
                ]
              },
              {
                name: "End-of-Life (EOL) System or Software",
                # cwe: nil,
                score: 50,
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
                name: "Social Network Accounts Leaking Data",
                # cwe: "CWE-200",
                score: 20,
                description: "Leaked Company Emails Open to Spear-Phishing or other email-based interaction",
                recommendation: "Best practice indicates you should disabld this access.",
                matches: [
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^social_network_issues$/ # Unsolicited Commercial Email
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^exposed_personal_information_info$/
                  }
                ]
              },
              {
                name: "Exposed Cloud Object Storage (S3 Bucket)",
                # cwe: "CWE-284",
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
                # cwe: "CWE-284",
                score: 80,
                description: "Sensitive information was found leaked via Github",
                recommendation: "Investigate and remove the sensitive data if not intended.",
                matches: [
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^github_information_leak_disclosure$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^exposed_personal_information$/
                  }
                ]
              },
              {
                name: "Google - Sensitive Data Leakage",
                # cwe: "CWE-284",
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
                # cwe: "CWE-326",
                score: 10,
                description: "Hacker chatter was detected.",
                recommendation: "Determine if this poses a risk.",
                matches: [
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^chatter$/
                  }
                ]
              },
              {
                name: "Insecure Cookie",
                # cwe: "CWE-298",
                score: 20,
                description: "The cookie is missing HTTPOnly flag.",
                recommendation: "Update cookie to include this flag.",
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
                # cwe: "CWE-202",
                description: "A dns record was found pointing to an internal system.",
                recommendation: "Remove the entry from public DNS.",
                matches: [
                  {
                    source: "Expanse",
                    vuln_id: /^internal_ip_address_advertisements?$/
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
                # cwe: "CWE-359",
                description: "Credentials were found exposed.",
                recommendation: "Revoke the credentials and/or prompt a reset. Examine systems to which the credentials provided access for signs of compromise.",
                matches: [
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^leaked_credentials$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^leaked_credentials_info$/
                  }
                ]
              },
              {
                name: "Mobile Application Security Misconfiguration",
                # cwe: "CWE-693",
                score: 20,
                description: "A problem with this application's configuration was discoverd .",
                recommendation: "Fix it",
                matches: [
                  {
                    source: "Bitsight",
                    vuln_id: /^mobile_application_security$/
                  },
                ]
              },
              {
                name: "Open DNS Resolver",
                score: 80,
                # cwe: "CWE-693",
                description: "Some DNS servers perform their hierarchical lookups by means of recursion, and rather than limit the ability to make recursive requests to local or authorized clients, DNS servers referred to as Open Resolvers allow recursive DNS requests from any client. Open Resolvers (especially with the newer RFC specifications supporting extensions to the DNS system such as IPv6 and DNSSEC) require the ability to send DNS replies much larger than their respective requests, and an attacker can abuse this fact to amplify his or her available outgoing bandwidth and subsequently direct it at a target in a DNS Amplification Attack.",
                recommendation: "Disable recursive queries on this DNS REsolver.",
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
                # cwe: "CWE-506",
                description: "This system was detected with P2P Activity ",
                recommendation: "Check the system for signs of compromise ",
                matches: [
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^non_malware_events_last_month$/
                  },
                ]
              },
              {
                ####
                #### individual tasks should not send anything that would map to this entry,
                ####  instead it shoudl be a CVE
                ####
                name: "Vulnerability Detected (Patching Cadence *** INCORRECTLY MAPPED?)",
                # cwe: nil,
                score: 0,
                description: "Vulnerability seen on network more than 60 days after CVE was published.",
                recommendation: "Monitor CVE lists and vulnerability repositories for exploit code that may affect your infrastructure.",
                matches: [
                  {
                    source: "Bitsight",
                    vuln_id: /^patching_cadence$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^patching_cadence_.*$/
                  }
                ]
              },
              {
                name: "Non-Sensitive (HTTP) Service Detected or Open Port Detected",
                score: 10,
                # cwe: "CWE-693",
                description: "A System was detected running a non-sensitive service.",
                recommendation: "Verify this is expected and firewall the port if it is not.",
                matches: [
                  # {
                  #  source: "Bitsight",
                  #  vuln_id: /^http_open_port$/
                  # },
                  {
                    source: "Expanse",
                    vuln_id: /^web_servers?$/
                  },
                  # {
                  #  source: "SecurityScorecard",
                  #  vuln_id: /^http_open_port$/
                  # },
                  {
                    source: "RiskIQ",
                    vuln_id: /^http_open_port$/
                  }
                ]
              },
              {
                name: "Sensitive Service Detected or Open Port Detected",
                score: 60,
                # #cwe: "CWE-693",
                description: "A System was detected running a potentially sensitive service.",
                recommendation: "Verify this is expected and firewall the port if it is not.",
                matches: [
                  { # correct place for this? # Open TCP Ports Observed
                    source: "Bitsight",
                    vuln_id: /^open_ports$/
                  },
                  { # literally match anyting coming from them in this vein
                    source: "Expanse",
                    vuln_id: /^.*_servers?$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^detected_server_.*$/
                  },
                  { # NOTE: .. many matches here, may need to be split up
                    source: "SecurityScorecard",
                    vuln_id: /^service_.*+$/
                  },
                  { # correct place for this? # Open TCP Ports Observed
                    source: "SecurityScorecard",
                    vuln_id: /^exposed_ports$/
                  },
                  {
                    source: "RiskIQ",
                    vuln_id: /^other_open_port$/
                  }
                ]
              },
              {
                name: "SSH Misconfiguration",
                # cwe: "CWE-358",
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
                # cwe: "CWE-183",
                score: 20,
                description: "This system was found to have an SPF finding - which may be a positive finding, or a misconfiguration.",
                recommendation: "Correct the SPF configuration on the server.",
                matches: [
                  {
                    source: "Bitsight", # TODO... this can be a positive finding
                    vuln_id: /^spf$/
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
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^spf_record_missing$/
                  },
                ]
              },
              {
                name: "SSL/TLS Misconfiguration",
                # cwe: "CWE-326",
                score: 40,
                description: "This server has a configuration weakness with its SSL/TLS settings or certificate.",
                recommendation: "Correct the SSL configuration on the server. See specifics for more detail about the SSL/TLS misconfiguration",
                matches: [
                  { source: "Bitsight", vuln_id: /^ssl_certificates$/ },
                  { source: "Bitsight", vuln_id: /^ssl_configurations$/ },
                  { source: "Expanse", vuln_id: /^certificate_insecure_signature$/ },
                  { source: "Expanse", vuln_id: /^domain_control_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^short_key_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^long_expiration_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^wildcard_certificate$/ },
                  { source: "Expanse", vuln_id: /^insecure_signature_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^wildcard_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^certificate_short_key$/ },
                  { source: "Expanse", vuln_id: /^certificate_long_expiration$/ },
                  { source: "Intrigue", vuln_id: /^weak_cipher_suite_detected$/ },
                  { source: "SecurityScorecard", vuln_id: /^ssl_weak_cipher$/ },
                  { source: "SecurityScorecard", vuln_id: /^tls_weak_cipher$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_no_revocation/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_revoked$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_weak_signature$/ },
                  { source: "SecurityScorecard", vuln_id: /^hsts_incorrect$/ },
                  { source: "SecurityScorecard", vuln_id: /^tls_ocsp_stapling$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_excessive_expiration$/ },
                  { source: "SecurityScorecard", vuln_id: /^insecure_https_redirect_pattern$/ }
                ]
              },
              {
                name: "Insecure Resource Request",
                score: 40,
                # cwe: "CWE-506",
                description: "A resource was requested over an insecure protocol",
                recommendation: "Transition the resource to an HTTPS request",
                matches: [
                  { source: "SecurityScorecard", vuln_id: /^domain_missing_https$/ },
                  { source: "SecurityScorecard", vuln_id: /^redirect_chain_contains_http$/ }
                ]
              },
              {
                name: "Self-Signed Certificate",
                score: 40,
                # cwe: "CWE-506",
                description: "A self-signed certificate was detected",
                recommendation: "Certificate should be issued from a valid CA",
                matches: [
                  { source: "Expanse", vuln_id: /^self_signed_certificate_advertisements?$/ },
                  { source: "Expanse", vuln_id: /^certificate_self_signed$/ },
                  { source: "Intrigue", vuln_id: /^self_signed_certificate$/ },
                  { source: "RiskIQ", vuln_id: /^self_signed_certificate$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_self_signed$/ }
                ]
              },
              {
                name: "Expired Certificate",
                score: 40,
                # cwe: "CWE-506",
                description: "An expried Ceritficate was Found",
                recommendation: "Replace ths ceritificate",
                matches: [
                  { source: "Expanse", vuln_id: /^certificate_expired_when_scanned$/ },
                  { source: "Expanse", vuln_id: /^expired_when_scanned_certificate_advertisements?$/ },
                  { source: "SecurityScorecard", vuln_id: /^tlscert_expired$/ }
                ]
              },
              {
                name: "Subresource Integrity Issues",
                # cwe: "CWE-353",
                score: 30,
                description: "Subresource Integrity (SRI) is a security feature that enables browsers to verify that resources they fetch (for example, from a CDN) are delivered without unexpected manipulation. It works by allowing you to provide a cryptographic hash that a fetched resource must match.",
                references: [
                  "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
                ],
                recommendation: "Ensure the system has not been compromised.",
                matches: [
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^unsafe_sri$/
                  }
                ]
              },
              {
                name: "Unencrypted Login",
                # cwe: "CWE-319",
                score: 50,
                description: "An unencrypted login was detected.",
                recommendation: "Ensure all logins happen over an encrypted channel.",
                matches: [
                  {
                    source: "Expanse",
                    vuln_id: /^unencrypted_logins?$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^detected_server_unencrypted_ftp$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^detected_server_unencrypted_logins$/
                  }
                ]
              },

              {
                name: "Unsolicited Email Sent from System",
                # cwe: "CWE-358",
                score: 30,
                description: "A system was identified on a spam blacklist.",
                recommendation: "Ensure the system has not been compromised.",
                matches: [
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^uce$/ # Unsolicited Commercial Email
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^short_term_lending_site$/ # Unsolicited Commercial Email
                  }
                ]
              },
              {
                name: "System Running File-Sharing Software",
                # cwe: "CWE-358",
                score: 30,
                description: "A system was identified on a file-sharing network.",
                recommendation: "Ensure the system has not been compromised.",
                matches: [
                  {
                    source: "Bitsight",
                    vuln_id: /^file_sharing$/
                  }
                ]
              },
              {
                name: "Tor Exit Node Discoverd",
                score: 10,
                # cwe: "CWE-506",
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
                # cwe: "CWE-200",
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
                # cwe: "CWE-200",
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
                name: "Non-Security, Benign, or Informational Finding",
                # cwe: "CWE-000",
                score: 0,
                description: "This is an informational finding.",
                recommendation: "Update the certificate to include the hostname, or ensuure that clients access the host from the matched hostname.",
                matches: [
                  {
                    source: "Bitsight", # this is something we manually labeled as a benign finding
                    vuln_id: /^benign_finding$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^certificate_advertisements?$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^healthy_certificate_advertisements?$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^domain_control_validated_certificate_advertisements?$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^employee_satisfaction$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^teleconferencing_and_collaboration$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^marketing_site$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^colocated_.*$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^vpn$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^waf_detected$/
                  },
                  {
                    source: "SecurityScorecard",  # this is something we manually labeled as a benign finding
                    vuln_id: /^benign_finding$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^hosted_on_object_storage$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^references_object_storage$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^load_balancers?$/
                  },
                  {
                    source: "Expanse",
                    vuln_id: /^load_balancers?$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^dnssec_detected$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^tlscert_extended_validation$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^domain_uses_hsts_preloading$/
                  },
                  {
                    source: "SecurityScorecard",
                    vuln_id: /^ddos_protection$/
                  },
                ]
              }
            ]
          end
        end
      end
    end
  end
end
