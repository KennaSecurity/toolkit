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

def _parse_host(string)
  out = {}
  out[:port] = string.split(":").last.to_i

  if string.split(":").first =~ /\[/
    out[:ip_address] = string.match(/.*\[(.*)\]/).captures.first
    out[:hostname] = string.match(/(.*)\[.*\]/).captures.first
  else
    out[:ip_address] = string.split(":").first
  end

out
end

def create_asset(hash)

  # if we already have it, skip
  return unless $assets.select{ |a|
    a[:hostname] == hash[:hostname] &&
    a[:ip_address] == hash[:ip_address]  }.empty?

  asset = {
    ip_address: hash[:ip_address],
    tags: [],
    priority: 10,
    vulns: []
  }

  # if we have a hostname, add it
  asset[:hostname] = hash[:hostname] if hash[:hostname] && hash[:hostname].length > 0

  $assets << asset
end

def create_asset_vuln(ip_address, port, vuln_id, first_seen, last_seen)

  # check to make sure it doesnt exist
  asset = $assets.select{|a| a[:ip_address] == ip_address}.first
  #puts "Creating vuln #{vuln_id} on asset #{ip_address}:#{port}"

  asset[:vulns] << {
    scanner_identifier: "#{vuln_id}",
    scanner_type: SCAN_SOURCE,
    created_at: first_seen,
    port: port,
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
  host_hash = _parse_host(row[4])

  # TODO - SKIP IPV6?
  # TODO!!!!!
  next if host_hash[:ip_address] =~ /\:/

  #puts "Got host hash: #{host_hash}"
  create_asset host_hash

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
  else # result == "GOOD"
    create = false
  end

  if create
    # multiple issues in the same string, separated by a comma
    descriptions = "#{row[6]}".split(",").each do |description|

      description = description.strip

      # if so, create vuln and attach to asset
      vuln_id = "#{row[0]}".strip << " #{description[0..40].gsub(":","").strip}"
      vuln_id = vuln_id.downcase.gsub(" ","_")

      recommendation = "#{row[8]}".strip

      mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)

      create_asset_vuln host_hash[:ip_address], host_hash[:port], vuln_id, first_seen, last_seen
      create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:recommendation], mapped_vuln[:cwe]

    end
  end

end

kdi_output = generate_kdi_file
puts JSON.pretty_generate kdi_output