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
  #puts "Got port data: #{data}"
  ports = []
  data.split("\n").each do
    port = {}
    port[:number] = data.split("\t")[0].split(":").last.strip
    port[:first_seen] = DateTime.parse(data.split("\t")[1].split(":").last(3).join(":").strip).to_date
    port[:last_seen] = DateTime.parse(data.split("\t")[2].split(":").last(3).join(":").strip).to_date
    ports << port
  end
ports
end

def create_asset(ip_address)

  # if we already have it, skip
  return unless $assets.select{|a| a[:ip_address] == ip_address }.empty?

  asset = {
    ip_address: ip_address,
    tags: [],
    priority: 10,
    vulns: []
  }

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


# iterate through the findings, looking for CVEs
headers = verify_file_headers(ARGV[0])
CSV.parse(read_input_file("#{ARGV[0]}"), encoding: "UTF-8", row_sep: :auto, col_sep: ",").each_with_index do |row,index|
  # skip first
  next if index == 0

  # create the asset
  ip_address = row[0]

  ports = _parse_ports(row[4])

  create_asset ip_address
  #puts "#{ip_address} Ports: #{ports}"

  ports.each do |p|
    port = p[:number]
    first_seen = p[:first_seen]
    last_seen = p[:last_seen]

    vuln_id = "open_db_port_tcp_#{port}"
    description = "Open Database Port: #{port}"
    recommendation = "Verify the port should be open"

    mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)

    create_asset_vuln ip_address, port, vuln_id, first_seen, last_seen
    create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:recommendation], mapped_vuln[:cwe]
  end

end

kdi_output = generate_kdi_file
puts JSON.pretty_generate kdi_output