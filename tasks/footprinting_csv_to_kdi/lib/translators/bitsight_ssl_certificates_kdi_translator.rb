
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
  out[:port] = string.split(":").last

  if string.split(":").first =~ /\[/
    out[:ip_address] = string.match(/.*\[(.*)\]/).captures.first
    out[:hostname] = string.match(/(.*)\[.*\]/).captures.first
  else
    out[:ip_address] = string.split(":").first
  end

out
end

def create_asset(hostname)

  asset = {
    hostname: hostname,
    tags: [],
    priority: 10,
    vulns: []
  }

  $assets << asset
end

def create_asset_vuln(hostname, vuln_id, first_seen, last_seen)

  # check to make sure it doesnt exist
  asset = $assets.select{|a| a[:hostname] == hostname}.first

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

  # create the asset
  hostname = "#{row[4]}"
  create_asset hostname

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
  elsif result == "FAIR"
    create = true
  elsif result == "WARN"
    create = true
  elsif result == "GOOD" && "#{row[6]}".length > 0 # we have something in the desc
    create = true
  else
    create = false
  end

  if create

    descriptions = "#{row[6]}".strip
    descriptions.split(",").each do |description|

      # if so, create vuln and attach to asset
      vuln_id = "#{row[0]}".strip << " #{description[0..40].gsub(":","").strip}"
      vuln_id = vuln_id.downcase.gsub(" ","_")

      recommendation = "#{row[18]}".strip

      mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)

      create_asset_vuln hostname, vuln_id, first_seen, last_seen
      create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:recommendation], mapped_vuln[:cwe]
      
    end
  end

end

kdi_output = generate_kdi_file
puts JSON.pretty_generate kdi_output