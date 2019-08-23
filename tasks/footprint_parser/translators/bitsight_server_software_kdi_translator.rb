#encoding: utf-8
require_relative "lib/mapping"
require_relative "lib/helpers"


require 'json'
require 'csv'

include Kenna::Helpers
include Kenna::Mapping::External

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
  asset = $assets.select{|a| a[:ip_address] == ip_address}.first
  #puts "Creating vuln #{vuln_id} on asset #{ip_address}"

  asset[:vulns] << {
    port: port,
    scanner_identifier: "#{vuln_id}",
    scanner_type: SCAN_SOURCE,
    created_at: first_seen,
    last_seen_at: last_seen,
    status: "open"
  }

end

# iterate through the findings, looking for CVEs
headers = verify_file_headers(ARGV[0])
CSV.parse(read_input_file("#{ARGV[0]}"), encoding: "UTF-8").each_with_index do |row,index|
  # skip first
  next if index == 0

  # create the asset
  ip_address = "#{row[4]}"
  create_asset ip_address

  if row[1]
  #  puts "First Seen Date: #{row[1]}"
    first_seen = Date.strptime row[1], "%Y-%m-%d"
  else
    first_seen = Date.today
  end

  if row[2]
  #  puts "Last Seen Date: #{row[2]}"
    last_seen = Date.strptime row[2], "%Y-%m-%d"
  else
    last_seen = Date.today
  end

  port_numbers = "#{row[5]}".split(",")

  port_numbers.each do |p|
   

    # also create the vuln def if we dont already have it (function handles dedupe)
    status = "#{row[8]}"
    description = "#{row[9]}"
    software = "#{row[6]} #{row[7]}".strip
    recommendation = "#{row[11]}".strip
    port_num = p.strip.to_i
    
    # if so, create vuln and attach to asset
    vuln_id = "#{row[0]}_#{software}".downcase.gsub(" ","_")

    mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)

    create_asset_vuln ip_address, port_num, vuln_id, first_seen, last_seen
    create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:recommendation], mapped_vuln[:cwe]
  end

end

puts JSON.pretty_generate generate_kdi_file