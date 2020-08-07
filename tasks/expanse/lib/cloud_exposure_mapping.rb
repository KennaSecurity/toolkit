# included by mapper

module Kenna
module Toolkit
module Expanse
module CloudExposureMapping

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

=begin

UNMAPPED!!!!!!

BUILDING_CONTROL_SYSTEM
COLOCATED_AJP_SERVER
COLOCATED_BACNET_SERVER
COLOCATED_BGP_SERVER
COLOCATED_CASSANDRA_SERVER
COLOCATED_COUCH_DB_SERVER
COLOCATED_DNS_SERVER
COLOCATED_ETHERNET_IP_SERVER
COLOCATED_FTPS_SERVER
COLOCATED_IKE2_SERVER
COLOCATED_IMAP_SERVER
COLOCATED_INTERNAL_IP_ADDRESS_ADVERTISEMENT
COLOCATED_MEMCACHED_SERVER
COLOCATED_MODBUS_SERVER
COLOCATED_MONGO_SERVER
COLOCATED_MS_SQL_SERVER
COLOCATED_MULTICAST_DNS_SERVER
COLOCATED_MY_SQL_SERVER
COLOCATED_NAT_PMP_SERVER
COLOCATED_NET_BIOS_NAME_SERVER
COLOCATED_NTP_SERVER
COLOCATED_PC_ANYWHERE_SERVER
COLOCATED_POP3_SERVER
COLOCATED_POSTGRES_SERVER
COLOCATED_RDP_SERVER
COLOCATED_REDIS_SERVER
COLOCATED_RPCBIND_SERVER
COLOCATED_RSYNC_SERVER
COLOCATED_SALT_STACK_SERVER
COLOCATED_SHAREPOINT_SERVER
COLOCATED_SIP_SERVER
COLOCATED_SMB_SERVER
COLOCATED_SMTP_SERVER
COLOCATED_SNMP_SERVER
COLOCATED_SSH_SERVER
COLOCATED_TELNET_SERVER
COLOCATED_UNENCRYPTED_FTP_SERVER
COLOCATED_UPNP_SERVER
COLOCATED_VNC_SERVER
COLOCATED_VX_WORKS_SERVER
COLOCATED_XMPP_SERVER
DATA_STORAGE_AND_ANALYSIS
EMBEDDED_SYSTEM
JENKINS_SERVER
NETWORKING_AND_SECURITY_INFRASTRUCTURE
VPN

=end

  def field_mapping_for_cloud_exposures
    {
      'application-server-software' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Exposed App Server Software: #{x["firstObservation"]["configuration"]["applicationServerSoftware"]}" } },
          ],
        'vuln_def' => [ 
        ]
      },
      'bacnet-servers' => {}, 
      'certificate-advertisements' => {}, 
      'development-environments' => {},
      'dns-servers' => {}, 
      'domain-control-validated-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Domain Control Validated Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
        ],
        'vuln_def' => [ 
        ]
      },
      'ethernet-ip-servers' => {}, 
      'expired-when-scanned-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Expired Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
          ],
        'vuln_def' => [ ]
      },
      'ftp-servers' => {}, 
      'ftps-servers' => {}, 
      '-healthy-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Healthy Certificate Advertisement: #{JSON.pretty_generate(x["certificate"])}" } },  
        ],
        'vuln_def' => [ ]
      },
      'insecure-signature-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Insecure Signature Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
          ],
        'vuln_def' => [ 
          
        ]
      },
      'internal-ip-address-advertisements'=> {
        'asset' => [],
        'vuln' => [
          
          { action: "proc", target: "details", proc: lambda{|x| 
            "Detected Internal IP advertisement with configuration: #{JSON.pretty_generate(x["firstObservation"]["configuration"])}" } },

          ],
        'vuln_def' => [ 
          
        ]
      },
      'load-balancers' => {},
      'long-expiration-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Long Expiration Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
        ],
        'vuln_def' => [ 

        ]
      },
      'memcached-servers' => {}, 
      'modbus-servers' => {}, 
      'ms-sql-servers' => {}, 
      'my-sql-servers' => {}, 
      'net-bios-name-servers' => {},
      'pop3-servers' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Detected Pop3 Server with configuration: #{JSON.pretty_generate(x["firstObservation"]["configuration"])}" } },  
        ],
        'vuln_def' => [ 
          
        ]
      }, 
      'rdp-servers' => {},
      'self-signed-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Self Signed Certificate: #{JSON.pretty_generate(x["certificate"])}" } },

        ],
          'vuln_def' => [ 
        ]
      },
      'server-software' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Exposed Server Software: #{x["firstObservation"]["configuration"]["serverSoftware"]}" } },
        ],
        'vuln_def' => [ 
        ]
      },
      'short-key-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Short Key Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
          ],
        'vuln_def' => [ 
        ]
      },
      'sip-servers' => {},
      'smb-servers' => {},
      'smtp-servers' => {},
      'snmp-servers' => {},
      'ssh-servers' => {},
      'telnet-servers' => {},
      'upnp-servers' => {},
      'unencrypted-logins' => {},
      'unencrypted-ftp-servers' => {},
      'web-servers' => {},
      'wildcard-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "details", proc: lambda{|x| 
            "Wildcard Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
        ],
        'vuln_def' => [ 
        ]
      },
      'vnc-servers' => {},
      'vx-works-servers' => {}
    }
  end

end
end
end
end