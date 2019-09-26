
#encoding: utf-8
require_relative "../mapping"
require_relative "../helpers"


require 'json'
require 'csv'

include Kenna::Helpers
include Kenna::Mapping::External

SCAN_SOURCE="Bitsight"

$basedir = "/opt/toolkit"
$assets = []
$vuln_defs = []

def create_asset(hostname)

  # if we already have it, skip
  return unless $assets.select{|a| a[:hostname] == hostname }.empty?

  $assets << {
    hostname: hostname,
    tags: [],
    priority: 10,
    vulns: []
  }

end

def create_asset_vuln(hostname, vuln_id, first_seen, last_seen)

  # check to make sure it doesnt exist
  asset = $assets.select{|a| a[:hostname] == hostname }.first
  #puts "Creating vuln #{vuln_id} on asset #{hostname}"

  asset[:vulns] << {
    scanner_identifier: "#{vuln_id}",
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

  # Create the asset
  hostname = row[4]
  create_asset hostname

  # if so, create vuln and attach to asset
  vuln_id = row[0].downcase.gsub(" ","_")

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

  # only create items that match a specified result. Many rows are expected to
  # be "GOOD", and we don't need to import those.
  result = row[5]
  if result == "BAD"
    create = true
  elsif result == "NEUTRAL"
    create = true
  else # result == "GOOD"
    create = false
  end

  if create
    description = "#{row[6]}".strip
    recommendation = "#{row[8]}".strip

    vuln_id = description.gsub(" ","_").downcase[0..99]
    mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)

    create_asset_vuln hostname, vuln_id, first_seen, last_seen
    create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:recommendation], mapped_vuln[:cwe]
  end

end

kdi_output = generate_kdi_file
puts JSON.pretty_generate kdi_output