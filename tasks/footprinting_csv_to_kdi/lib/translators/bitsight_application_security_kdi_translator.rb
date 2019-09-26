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

def _parse_host(string)

  out = {}
  out[:hostname] = string.split(":").first
  out[:port] = string.split(":").last.to_i

out
end

def create_asset(hash, ip_address)

  # if we already have it, skip
  return unless $assets.select{ |a| a[:hostname] == hash[:hostname] &&
      a[:ip_address] == ip_address }.empty?

  asset = {
    hostname: hash[:hostname],
    ip_address: ip_address,
    tags: [],
    priority: 10,
    vulns: []
  }

  $assets << asset
end

def create_asset_vuln(hostname, ip_address, port, vuln_id, first_seen, last_seen)

  # check to make sure it doesnt exist
  asset = $assets.select{|a| a[:hostname] == hostname &&
    a[:ip_address] == ip_address}.first

  asset[:vulns] << {
    scanner_identifier: "#{vuln_id}",
    scanner_type: SCAN_SOURCE,
    created_at: first_seen,
    port: port,
    last_seen_at: last_seen,
    status: "open"
  }
end

###### FIRST CHECK THE FILE!! (See helpers)
headers = verify_file_headers(ARGV[0])

# iterate through the findings, looking for CVEs
CSV.parse(read_input_file("#{ARGV[0]}"), encoding: "UTF-8", row_sep: :auto, col_sep: ",").each_with_index do |row,index|
  # skip first
  next if index == 0

  ### SELECT FIELDS ----------------
  vuln_id_string = "#{row[0]}"
  
  first_seen_string = row[1]
  first_seen = parse_date first_seen_string
  
  last_seen_string = row[2]
  last_seen = parse_date last_seen_string

  parsable_host_data = row[3]
  finding_result = "#{row[6]}".strip
  description_string = "#{row[7]}".strip
  sample_ip_address = "#{row[12]}".strip
  recommendation_string = "#{row[14]}".strip
  ### ----------------------------------

  # create the asset
  host_hash = _parse_host(parsable_host_data)

  create_asset host_hash, sample_ip_address


  # only create items that match a specified result. Many rows are expected to
  # be "GOOD", and we don't need to import those.
  if finding_result == "BAD"
    create = true
  elsif finding_result == "FAIR"
    create = true
  elsif finding_result == "WARN"
    create = true
  else
    create = false
  end

  # create any items that have been marked with creation
  if create
    descriptions = description_string.split(",").each do |description|

      # get description & solution
      recommendation = recommendation_string

      # if so, create vuln and attach to asset
      vuln_id = vuln_id_string.strip << " #{description[0..40].gsub(":","").strip}"
      vuln_id = vuln_id.downcase.gsub(" ","_")

      mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)

      create_asset_vuln host_hash[:hostname], sample_ip_address, host_hash[:port], vuln_id, first_seen, last_seen
      create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:recommendation], mapped_vuln[:cwe]
    end
    
  end

end

puts JSON.pretty_generate generate_kdi_file