#encoding: utf-8

require_relative "../mapping"
require_relative "../helpers"


require 'json'
require 'csv'

include Kenna::Helpers
include Kenna::Mapping::External

$assets = []
$vuln_defs = []

SCAN_SOURCE="Bitsight"

def create_asset(fqdn)

  # if we already have it, skip
  return unless $assets.select{|a| a[:fqdn] == fqdn }.empty?

  $assets << {
    fqdn: fqdn,
    tags: [],
    priority: 10,
    vulns: []
  }
end

def create_asset_vuln(fqdn, vuln_id, first_seen, last_seen)

  # check to make sure it doesnt exist
  asset = $assets.select{|a| a[:fqdn] == fqdn }.first
  #puts "Creating vuln #{vuln_id} on asset #{fqdn}"

  asset[:vulns] << {
    scanner_identifier: "#{vuln_id}",
    scanner_type: SCAN_SOURCE,
    created_at: first_seen,
    last_seen_at: last_seen,
    status: "open"
  }

end

###### FIRST CHECK THE FILE!! (See helpers)
headers = verify_file_headers(ARGV[0])

# iterate through the findings, looking for CVEs
CSV.parse(read_input_file("#{ARGV[0]}"), encoding: "UTF-8").each_with_index do |row,index|
  # skip first
  next if index == 0

  ### SELECT FIELDS ----------------
  fqdn = "#{row[4]}"
  domain_name = fqdn.split(".").last(2).join(".")
  vuln_id = "#{row[0]}_#{row[6]}".downcase.gsub(" ","_")
  
  first_seen_string = row[1]
  first_seen = parse_date first_seen_string
  
  last_seen_string = row[2]
  last_seen = parse_date last_seen_string

  finding_result = "#{row[5]}".strip
  description = "#{row[6]}".strip
  recommendation = "#{row[8]}".strip
  ### -------------------------------
  
  create_asset domain_name

  # only create items that match a specified result. Many rows are expected to
  # be "GOOD", and we don't need to import those.
  if finding_result == "BAD"
    create = true
  elsif finding_result == "WARN"
    create = true
  elsif finding_result == "NEUTRAL"
    create = true
  else # finding_result == "GOOD"
    create = false
  end

  if create
    mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)
    create_asset_vuln domain_name, vuln_id, first_seen, last_seen
    create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:recommendation], mapped_vuln[:cwe]
  end

end

puts JSON.pretty_generate generate_kdi_file