#encoding: utf-8

require_relative "lib/mapping"
require_relative "lib/helpers"

require 'json'
require 'csv'

include Kenna::Helpers
include Kenna::Mapping::External

$assets = []
$vuln_defs = []

SCAN_SOURCE="Expanse"

def create_asset(ip_address, hostname=nil)

  # if we already have it, skip
  return unless $assets.select{|a| a[:ip_address] == ip_address }.empty?

  asset = {
    ip_address: ip_address,
    tags: [],
    priority: 10,
    vulns: []
  }

  # if we have a hostname, add it
  asset[:hostname] = hostname if hostname

  $assets << asset
end

def create_asset_vuln(ip_address, port, vuln_id, first_seen, last_seen)

  # grab the asset
  asset = $assets.select{|a| a[:ip_address] == ip_address}.first

  asset[:vulns] << {
    scanner_identifier: "#{vuln_id}",
    scanner_type: SCAN_SOURCE,
    created_at: first_seen,
    port: port.to_i,
    last_seen_at: last_seen,
    status: "open"
  }

end

# verify we have a valid file
headers = verify_file_headers(ARGV[0])  

CSV.parse(read_input_file("#{ARGV[0]}"), encoding: "UTF-8").each_with_index do |row,index|
  # skip first
  next if index == 0

  # create the asset
  hostname = get_value_by_header(row, headers, "lastObservation.hostname") 
  next unless hostname # skip if we can't parse

  hostname = hostname.gsub("*.","")


  ip_address = get_value_by_header(row, headers, "ip")
  port = get_value_by_header(row, headers, "port")
  create_asset ip_address, hostname

  first = get_value_by_header(row, headers, "firstObservation.scanned")
  last = get_value_by_header(row, headers, "lastObservation.scanned")
  if 
    first_seen = Date.strptime("#{first}", "%Y-%m-%d")
  else
    first_seen = Date.today
  end

  if last
    last_seen = Date.strptime("#{last}", "%Y-%m-%d")
  else
    last_seen = Date.today
  end

  response_status = get_value_by_header(row, headers, "firstObservation.configuration.responseStatusAndReason")
  version = get_value_by_header(row, headers, "firstObservation.configuration.version")
  headers = get_value_by_header(row, headers, "firstObservation.configuration.headers")
  #body = get_value_by_header(row, headers, "firstObservation.configuration.body")

  finding_id = unique_finding_string("#{response_status} #{version} #{headers}")
  vuln_id = "detected_server_sip_#{finding_id}"
  description = "Sip Server detected:\n"
  description << "Response Status: #{response_status}\n"
  description << "Version: #{version}\n"
  description << "Headers: #{headers}\n"
  #description << "Body: #{body}"

  recommendation = "No action required if this server is intended to be exposed."

  mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)

  create_asset_vuln ip_address, port, vuln_id, first_seen, last_seen
  create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:recommendation], mapped_vuln[:cwe]

end

kdi_output = generate_kdi_file
puts JSON.pretty_generate kdi_output