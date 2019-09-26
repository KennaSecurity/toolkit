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
CSV.parse(read_input_file("#{ARGV[0]}"), encoding: "UTF-8", row_sep: :auto, col_sep: ",").each_with_index do |row,index|
  
  # skip first
  next if index == 0
  
  ### SELECT FIELDS ----------------

  first_seen_string = row[1]
  first_seen = parse_date first_seen_string
  
  last_seen_string = row[2]
  last_seen = parse_date last_seen_string
  
  fqdn = row[4]

  status = "#{row[5]}".strip
  description= "#{row[6]}".strip
  recommendation = "#{row[8]}".strip
  
  # skip good records 
  next if status =~ /GOOD/

  ### Generated vuln id field based on description

  short_desc = row[6][0..49] if row[6]
  if short_desc
    vuln_id = "#{short_desc}".downcase.gsub(" ","_")
  else 
    raise "Unable to generate a unique description on line: #{index}"
  end
  # ----------------------------------

  # create the asset
  create_asset fqdn
  create_asset_vuln fqdn, vuln_id, first_seen, last_seen

  # create the vuln 
  create_asset_vuln fqdn, vuln_id, first_seen, last_seen

  # also create the vuln def 
  mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)
  create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:recommendation], mapped_vuln[:cwe]

end

puts JSON.pretty_generate generate_kdi_file