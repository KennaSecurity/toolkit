#encoding: utf-8

require_relative "../mapping"
require_relative "../helpers"

require 'json'
require 'csv'

include Kenna::Helpers
include Kenna::Mapping::External

$assets = []
$vuln_defs = []

SCAN_SOURCE="SecurityScorecard"

def create_url_asset(url)

  # if we already have it, skip
  return unless $assets.select{|a| a[:url] == url }.empty?

  asset = {
    url: url,
    #application: url,
    tags: [],
    priority: 10,
    vulns: []
  }

  # store the asset
  $assets << asset
end

def create_ip_asset(hostname, ip_address=nil)

  # if we already have it, skip
  return unless $assets.select{|a| a[:ip_address] == ip_address && a[:hostname] == hostname }.empty?

  asset = {
    tags: [],
    priority: 10,
    vulns: []
  }

  asset[:ip_address] = ip_address if ip_address
  asset[:hostname] = hostname if hostname

  # store the asset
  $assets << asset
end

def create_asset_vuln(url, ip_address, hostname, port, vuln_id, status, first_seen, last_seen)

  # check to make sure it doesnt exist
  if url
    asset = $assets.select{|a| a[:url] == url }.first
  else
    asset = $assets.select{|a| a[:ip_address] == ip_address && a[:hostname] == hostname }.first
  end

  unless asset 
    out = "Unable to proceed!\n"
    out << "url: #{url}!\n"
    out << "ip_address: #{ip_address}!\n"
    out << "hostname: #{hostname}!\n"
    out << "port: #{port}!\n"
    out << "vuln_id: #{vuln_id}!\n"
    out << "status: #{status}!\n"
    out << "first_seen: #{first_seen}!\n"
    out << "last_seen: #{last_seen}!\n"
    raise "Error finding asset!\n#{out}"
  end

  vuln = {
    scanner_identifier: "#{vuln_id}",
    scanner_type: SCAN_SOURCE,
    created_at: first_seen,
    last_seen_at: last_seen,
    status: "#{status}"
  }
  # save port if we have it
  vuln[:port] = port if port

  #puts "asset: #{asset}"
  #puts "vuln: #{vuln}"

  puts "Asset: #{asset}"
  puts "Vuln: #{vuln}"

  asset[:vulns] << vuln

end

###### FIRST CHECK THE FILE!! (See helpers)
#headers = verify_file_headers(ARGV[0])

# iterate through the findings, looking for CVEs
CSV.parse(read_input_file("#{ARGV[0]}"), encoding: "UTF-8", row_sep: :auto, col_sep: ",").each_with_index do |row,index|
  # skip first
  next if index == 0

  # create the asset
  hostname = row[19] || row[9]
  hostname = nil unless hostname && hostname.length > 0
  url = row[34]
  ip_addresses = "#{row[8]}"
  ip_address = ip_addresses.split(" ").first

  # skip anything without a url for now
  if url
    create_url_asset url
  elsif ip_address
    create_ip_asset hostname, ip_address
  elsif hostname
    create_ip_asset hostname
  else
    puts "ERROR! Dont know what to do with this row... #{row.to_s[0..79]}"
  end

  # if so, create vuln and attach to asset
  status = "#{row[12]}" == "active" ? "open" : "closed"

  # TODO - currently only brings in the first port. presumably we should do all,
  # so we'd need to iterate here
  port = row[11].split(" ").first.to_i if row[11]

  if row[6]
    first_seen = Date.strptime "#{row[6]}", "%m/%d/%Y"
  else
    first_seen = Date.today
  end

  if row[7]
    last_seen = Date.strptime "#{row[7]}", "%m/%d/%Y"
  else
    last_seen = Date.today
  end

  # also create the vuln def if we dont already have it (function handles dedupe)
  vuln_title = "#{row[3]}".strip
  if row[13]
    cve = "#{row[13]}".upcase
    description = "#{row[14]}".strip
  else
    description = "#{vuln_title}\n\n#{row[5]}".strip
  end

  vuln_id = "#{vuln_title}"
  if cve # handle cve a little differently
    create_asset_vuln url, ip_address, hostname, port, cve, status, first_seen, last_seen
    create_vuln_def nil, cve, nil, nil,nil, cve
  else

    # Skip positive findings
    outcome = row[4]
    next if outcome =~ /POSITIVE/

    recommendation = "#{row[5]}".strip
    mapped_vuln = get_canonical_vuln_details(SCAN_SOURCE, "#{vuln_id}", description, recommendation)
    create_asset_vuln url, ip_address, hostname, port, vuln_id, status, first_seen, last_seen
    create_vuln_def mapped_vuln[:name], vuln_id, mapped_vuln[:description], mapped_vuln[:solution], mapped_vuln[:cwe]
  end

end

kdi_output = kdi_output = generate_kdi_file
puts JSON.pretty_generate kdi_output