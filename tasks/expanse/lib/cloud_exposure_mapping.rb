
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
      '-certificate-advertisements' => {}, 
      'development-environments' => {},
      'dns-servers' => {}, 
      '-domain-control-validated-certificate-advertisements' => {
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