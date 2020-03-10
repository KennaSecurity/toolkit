module Kenna
module Toolkit
module Expanse
module CloudExposureMapping

  def default_cloud_exposure_field_mapping
    {
      'asset' => [  
        { action: "copy", source: "parentDomain", target: "domain" },
        { action: "copy", source: "domain", target: "hostname" },
        { action: "copy", source: "ip", target: "ip_address" },
        { action: "proc", target: "tags", proc: lambda{|x| 
          ["Cloud"].concat(x["businessUnits"].map{|x| x["name"] }) } }  
      ],
      'vuln' => [
        { action: "proc", target: "scanner_identifier", proc: lambda{|x| "open_port_#{x["port"]}" }},
        { action: "copy", source: "port", target: "port" },
        { action: "proc", target: "scanner_score", proc: lambda{|x| map_scanner_severity(x["severity"]) } },
        { action: "data", target: "scanner_type", data: "Expanse" }
      ],
      'vuln_def' => [
        { action: "proc", target: "scanner_identifier", proc: lambda{|x| "open_port_#{x["port"]}" }},
        { action: "proc", target: "description", proc: lambda{|x| "Port #{x["port"]}" } },
        { action: "data", target: "remediation", data: "Investigate this Exposure!" }
      ]
    }
  end


  # this method does the actual mapping, as specified
  # in the field_mapping_by_type method
  def map_cloud_exposure_fields(exposure_type, exposure)
    
    # grab the relevant mapping
    mapping_areas = default_cloud_exposure_field_mapping.deep_merge(
      field_mapping_for_cloud_exposures[exposure_type]) # asset, vuln, vuln_def

    # then execute the mapping 
    out = {}

    ## For each area (asset,vuln,vuln_def) in the mapping
    mapping_areas.each do |area,mapping|
      out[area] = {}

      ## For each item in the mapping
      mapping.each do |map_item|
        target = map_item[:target]
        map_action = map_item[:action]
        
        ## Perform the requested mapping action

        if map_action == "proc" # call a lambda, passing in the whole exposure
          out[area][target] = map_item[:proc].call(exposure)
        elsif map_action == "copy" # copy from source data
          out[area][target] = exposure[map_item[:source]]
        elsif map_action == "data" # static data 
          out[area][target] = map_item[:data]
        end

      end
    end

  out 
  end

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
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "application_server_software_#{x["firstObservation"]["configuration"]["applicationServerSoftware"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Exposed App Server Software: #{x["firstObservation"]["configuration"]["applicationServerSoftware"]}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "application_server_software_#{x["firstObservation"]["configuration"]["applicationServerSoftware"]}".to_string_identifier }
          }
        ]
      },
      'bacnet-servers' => {}, 
      'certificate-advertisements' => {}, 
      'development-environments' => {},
      'dns-servers' => {}, 
      '-domain-control-validated-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "comain_control_validated_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Domain Control Validated Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "comain_control_validated_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          }
        ]
      },
      'ethernet-ip-servers' => {}, 
      'expired-when-scanned-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "expired_when_scanned_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Expired Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "expired_when_scanned_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          }
        ]
      },
      'ftp-servers' => {}, 
      'ftps-servers' => {}, 
      '-healthy-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "healthy_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Healthy Certificate Advertisement: #{JSON.pretty_generate(x["certificate"])}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "healthy_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          }
        ]
      },
      'insecure-signature-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "insecure_signature_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Insecure Signature Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "insecure_signature_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          }
        ]
      },
      'internal-ip-address-advertisements'=> {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "internal_ip_address_advertisements_#{x["cloudAssetId"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Detected Internal IP advertisement with configuration: #{JSON.pretty_generate(x["firstObservation"]["configuration"])}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "internal_ip_address_advertisements_#{x["cloudAssetId"]}".to_string_identifier }
          }
        ]
      },
      'load-balancers' => {},
      'long-expiration-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "long_expiration_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Long Expiration Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "long_expiration_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          }
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
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "detected_server_pop3_#{x["cloudAssetId"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Detected Pop3 Server with configuration: #{JSON.pretty_generate(x["firstObservation"]["configuration"])}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "detected_server_pop3_#{x["cloudAssetId"]}".to_string_identifier }
          }
        ]
      }, 
      'rdp-servers' => {},
      'self-signed-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "self_signed_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Self Signed Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "self_signed_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          }
        ]
      },
      '-server-software' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "server_software_#{x["firstObservation"]["configuration"]["serverSoftware"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Exposed Server Software: #{x["firstObservation"]["configuration"]["serverSoftware"]}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "server_software_#{x["firstObservation"]["configuration"]["serverSoftware"]}".to_string_identifier }
          }
        ]
      },
      'short-key-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "shert_key_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Short Key Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "shert_key_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          }
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
      '-web-servers' => {},
      'wildcard-certificate-advertisements' => {
        'asset' => [],
        'vuln' => [
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "wildcard_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          },
          ],
        'vuln_def' => [ 
          { action: "proc", target: "description", proc: lambda{|x| 
            "Wildcard Certificate: #{JSON.pretty_generate(x["certificate"])}" } },
          { action: "proc", target: "scanner_identifier", proc: lambda{|x| 
            "wildcard_certificate_advertisement_#{x["certificate"]["id"]}".to_string_identifier }
          }
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