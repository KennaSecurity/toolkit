#encoding: utf-8
require_relative "../mapping"
require_relative "../helpers"


require 'json'
require 'csv'

include Kenna::Helpers
include Kenna::Mapping::External

$basedir = "/opt/toolkit"
$assets = []
$vuln_defs = []

SCAN_SOURCE="Bitsight"

def create_asset(ip_address)

  # if we already have it, skip
  return unless $assets.select{|a| a[:ip_address] == ip_address }.empty?

  $assets << {
    ip_address: ip_address,
    tags: [],
    priority: 10,
    vulns: []
  }
end

def create_asset_vuln(ip_address, port, vuln_id, first_seen, last_seen)

  # check to make sure it doesnt exist
  asset = $assets.select{|a| a[:ip_address] == ip_address }.first
  #puts "Creating vuln #{vuln_id} on asset #{ip_address}"

  asset[:vulns] << {
    scanner_identifier: "#{vuln_id}",
    port: port,
    scanner_type: SCAN_SOURCE,
    created_at: first_seen,
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
  ip_address = "#{row[4]}"
  next unless ip_address

  create_asset ip_address

  # if so, create vuln and attach to asset
  port = "#{row[5]}".to_i
  vuln_id = "open_port_tcp_#{port}"

  if row[1]
    #puts "First Seen Date: #{row[1]}"
    first_seen = Date.strptime row[1], "%Y-%m-%d"
  else
    first_seen = Date.today
  end

  if row[2]
    #puts "Last Seen Date: #{row[2]}"
    last_seen = Date.strptime row[2], "%Y-%m-%d"
  else
    last_seen = Date.today
  end

  # also create the vuln def if we dont already have it (function handles dedupe)
  description = "#{row[7]} | #{row[8]} | #{row[5].to_i}/#{row[10]}".strip
  recommendation = "#{row[11]}".strip

  mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)

  create_asset_vuln ip_address, port, vuln_id, first_seen, last_seen
  create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:recommendation], mapped_vuln[:cwe]


end

puts JSON.pretty_generate generate_kdi_file