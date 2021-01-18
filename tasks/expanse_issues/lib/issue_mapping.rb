# frozen_string_literal: true

# included by mapper

module Kenna
  module Toolkit
    module ExpanseIssues
      module IssueMapping
        ###
        ### Each entry (type) should have a set of mappings for each KDI section:
        ###   Asset
        ###   Vuln
        ###   VulnDef
        ###
        ### Also, each mapping should be one of the following types:
        ###   calc - just copies data from the source
        ###   copy - just copies data from the source
        ###   data - static data, use directly without worrying about source data
        ###

        def field_mapping_for_issue_types
          {
            "AdobeFlash" => {},
            "AjpServer" => {},
            "ApacheWebServer" => {},
            "BuildingControlSystem" => {},
            "ColocatedImapServer" => {},
            "ColocatedMongoServer" => {},
            "ColocatedMssqlServer" => {},
            "ColocatedMulticastDnsServer" => {},
            "ColocatedMysqlServer" => {},
            "ColocatedNetBiosNameServer" => {},
            "ColocatedNtpServer" => {},
            "ColocatedPop3Server" => {},
            "ColocatedPostgresServer" => {},
            "ColocatedPptpServer" => {},
            "ColocatedRdpServer" => {},
            "ColocatedRedisServer" => {},
            "ColocatedRpcBindServer" => {},
            "ColocatedSmbServer" => {},
            "ColocatedSnmpServer" => {},
            "ColocatedSshServer" => {},
            "ColocatedTelnetServer" => {},
            "ColocatedUnencryptedFtpServer" => {},
            "DataStorageAndAnalysis" => {},
            "DefaultApacheTomcatPage" => {},
            "DevelopmentEnvironment" => {},
            "DomainControlValidatedCertificate" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Domain Control Validated Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "DrupalWebServer" => {},
            "ElasticsearchServer" => {},
            "EmbeddedSystem" => {},
            "ExpiredWhenScannedCertificate" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Expired Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "ExpiringCertificate" => {},
            "ExposedDirectoryListing" => {},
            "Grafana" => {},
            "ImapServer" => {},
            "InsecureApacheWebServer" => {},
            "InsecureDrupalWebServer" => {},
            "InsecureMicrosoftIisWebServer" => {},
            "InsecureSignatureCertificate" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Insecure Signature Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "InsecureTelerikWebUI" => {},
            "InsecureTLS" => {},
            "InternalIPAddressAdvertisement" => {
              "asset" => [],
              "vuln" => [

                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Detected Internal IP advertisement with configuration: #{JSON.pretty_generate(x['firstObservation']['configuration'])}"
                        }                                                      }

              ],
              "vuln_def" => []
            },
            "JenkinsServer" => {},
            "Kubernetes" => {},
            "LongExpirationCertificate" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Long Expiration Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "MemcachedServer" => {},
            "MicrosoftDnsServer" => {},
            "MicrosoftOWAServer" => {},
            "MissingCacheControlHeader" => {},
            "MissingContentSecurityPolicyHeader" => {},
            "MissingPublicKeyPinsHeader" => {},
            "MissingStrictTransportSecurityHeader" => {},
            "MissingXContentTypeOptionsHeader" => {},
            "MissingXFrameOptionsHeader" => {},
            "MissingXXssProtectionHeader" => {},
            "MssqlServer" => {},
            "MulticastDnsServer" => {},
            "MysqlServer" => {},
            "NetBiosNameServer" => {},
            "NetworkingAndSecurityInfrastructure" => {},
            "NfsRpcBindServer" => {},
            "NginxWebServer" => {},
            "NtpServer" => {},
            "OpenBgpServer" => {},
            "PanOsDevice" => {},
            "Pop3Server" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Detected Pop3 Server with configuration: #{JSON.pretty_generate(x['firstObservation']['configuration'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "PostgresServer" => {},
            "PptpServer" => {},
            "RdpServer" => {},
            "RedisServer" => {},
            "RpcBindServer" => {},
            "RsyncServer" => {},
            "RtspServer" => {},
            "SapNetWeaverApplicationServer" => {},
            "Section889Violation" => {},
            "SelfSignedCertificate" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Self Signed Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }

              ],
              "vuln_def" => []
            },
            "SharepointServer" => {},
            "ShortKeyCertificate" => {
              "asset" => [],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Short Key Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        }                                                      }
              ],
              "vuln_def" => []
            },
            "SipServer" => {},
            "SmbServer" => {},
            "SnmpServer" => {},
            "SshServer" => {},
            "TeleconferencingAndCollaboration" => {},
            "TelnetServer" => {},
            "TomcatWebServer" => {},
            "UnencryptedFtpServer" => {},
            "UnencryptedLogin" => {},
            "UpnpServer" => {},
            "VMwareESXi" => {},
            "VMwareWorkspaceOneAccessServer" => {},
            "VncOverHttpServer" => {},
            "VncServer" => {},
            "VpnDevice" => {},
            "WebLogin" => {},
            "WildcardCertificate" => {
              "asset" => [
                { action: "proc",
                  target: "hostname",
                  proc: lambda { |x|
                          x["domain"]&.gsub("\*", "WILDCARD")
                        } }
              ],
              "vuln" => [
                { action: "proc",
                  target: "details",
                  proc: lambda { |x|
                          "Wildcard Certificate: #{JSON.pretty_generate(x['certificate'])}"
                        } }
              ],
              "vuln_def" => []
            },
            "WildcardDnsRecord" => {
              "asset" => [
                { action: "proc",
                  target: "hostname",
                  proc: lambda { |x|
                          puts "#{x["domain"]} asset named mapping"
                          x["domain"]&.gsub("\*", "WILDCARD")
                        } }
              ]
            },
            "WordpressServer" => {},
            "XmppServer" => {}
          }
        end
      end
    end
  end
end
