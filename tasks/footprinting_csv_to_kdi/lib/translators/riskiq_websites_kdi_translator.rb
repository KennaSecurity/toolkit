#encoding: utf-8

require_relative "../mapping"
require_relative "../helpers"


require 'json'
require 'csv'

include Kenna::Helpers
include Kenna::Mapping::External

$assets = []
$vuln_defs = []

SCAN_SOURCE="RiskIQ"

def _parse_ports(data)
  ports = []
  return [] unless data
  data.split(",").each do |p|
    port = {}
    port[:number] = p
    ports << port
  end
ports
end

def create_asset(hostname,ip_address,tags)

  # if we already have it, skip
  return unless $assets.select{|a|
    a[:hostname] == hostname &&
    a[:ip_address] == ip_address }.empty?

  asset = {
    ip_address: ip_address,
    hostname: hostname,
    tags: tags.split(",").map{|t| "RiskIQ-#{t}"},
    priority: 10,
    vulns: []
  }

  $assets << asset
end


def create_asset_vuln(hostname, ip_address, port, vuln_id, first_seen, last_seen)

  # grab the asset
  asset = $assets.select{|a|
    a[:hostname] == hostname &&
    a[:ip_address] == ip_address
  }.first

  asset[:vulns] << {
    scanner_identifier: "#{vuln_id}",
    scanner_type: SCAN_SOURCE,
    created_at: first_seen,
    port: port.to_i,
    last_seen_at: last_seen,
    status: "open"
  }

end


def create_asset_vuln_cve(hostname, ip_address, port, vuln_id, first_seen, last_seen)

  # grab the asset
  asset = $assets.select{|a|
    a[:hostname] == hostname &&
    a[:ip_address] == ip_address
  }.first

  asset[:vulns] << {
    scanner_identifier: "#{vuln_id}",
    scanner_type: SCAN_SOURCE,
    created_at: first_seen,
    port: port.to_i,
    last_seen_at: last_seen,
    status: "open"
  }

end


# iterate through the findings, looking for CVEs
headers = verify_file_headers(ARGV[0])
CSV.parse(read_input_file("#{ARGV[0]}"), encoding: "UTF-8", row_sep: :auto, col_sep: ",").each_with_index do |row,index|
  # skip first
  next if index == 0

  # create the asset
  ip_address = "#{row[15]}"
  hostname = "#{row[16]}"
  tags = "#{row[43]}"

  # hacky, look at the final url (or initial if it doesnt exist) and see if it's https enabled
  # note that there are no examples of :8080 or :8443 or anything.
  port = (row[60] || row[61]) =~ /^https:/ ? 443 : 80

  create_asset hostname, ip_address, tags

  first_seen = DateTime.parse "#{row[5]}"
  last_seen = DateTime.parse "#{row[44]}"

  # TODO... extract
  # handle ssl issues here (row[58])
  # SSL Error: hostname in certificate didn't match (invalid cert)
  # PKIX path building failed (unable to verify cert.. bad chain)
  # SSL Error: Certificate Expired

  # TODO... extract
  # handle pass/fail policy list here
  # - strict-transport-security,
  # - public-key-pinning-extensions-for-http
  # - xss-protection,
  # - content-security-policy-low,
  # - insecure-login-form,
  # - insecure-form,
  # - form,
  # - x-permitted-cross-domain-policies,
  # - login-form,
  # - x-frame-options,
  # - x-content-type-options,
  # - content-security-policy-high

  # handle CVE things here
  cves = "#{row[47]}".split(",")
  cves.each do |cve|
    create_asset_vuln_cve hostname,ip_address, port, "#{cve}", first_seen, last_seen
    create_vuln_def(nil, cve, nil, nil, nil, cve)
  end

end

kdi_output = generate_kdi_file
puts JSON.pretty_generate kdi_output