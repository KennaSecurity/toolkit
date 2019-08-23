require 'digest'

class String
  def sanitize_unicode
    self.encode("UTF-8", { 
      :undef => :replace,
     :invalid => :replace,
     :replace => "?" }).gsub("\u0000","")
  end
end


module Kenna
  module Helpers


  def read_input_file(filename)
    output = File.open(filename,"r").read 
  output.sanitize_unicode
  end

  def get_value_by_header(row, headers, field_name)

    # in case we get a string
    headers = headers.split(",") if headers.kind_of? String

    #puts "Getting value for field name: #{field_name} from: #{headers}"

    i = headers.find_index(field_name)
    return nil unless i 
    raise "Invalid index: #{i} for field_name: #{field_name}. All headers: #{headers}" unless i 

  "#{row[i]}"
  end

  def current_verified_file_dir 
    "#{base_directory}/data/archive/parse_20190503"
  end

  def verify_file_headers(filename)
    # A simple way to check if we're the same as what we expected!

    # first get the file we want to parse_20190503
    specific_file = filename.split("/").last(2).join("/")

    # then grab the headers
    first_row = CSV.parse(read_input_file(filename), encoding: "UTF-8").first
    raise "Missing source file: #{specific_file}" unless first_row

    # then get the file we know we can parse 
    ###
    ###
    ### !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    ### IF WE GET A NEW FILE FORMAT:
    ### Change the parser, then CHANGE THIS FILE
    ### !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    ###
    ###
    
    ### verified_filename = "#{current_verified_file_dir}/#{specific_file}"
    ###first_row_confirmed = CSV.parse(read_input_file(verified_filename), encoding: "UTF-8").first
    ###raise "Missing verification file: #{verified_filename}" unless first_row_confirmed

    # if they don't match, bail out
    ###unless first_row == first_row_confirmed
    ###  raise "Cowardly refusing to run! #{parse_file.path} appears to have changed!" 
    ###end

    ###raise "Invalid value for first_row: #{first_row}" unless first_row.kind_of?(Array)

  first_row
  end

  def base_directory
    File.expand_path("../..",File.dirname(__FILE__))
  end

  def parse_date(date_string, date_format="%Y-%m-%d")
    return Date.today unless date_string
  Date.strptime date_string, date_format
  end

  def generate_kdi_file
    { skip_autoclose: false, assets: $assets, vuln_defs: $vuln_defs }
  end

  def unique_finding_string(app_server_string)
    Digest::SHA1.hexdigest("#{app_server_string}")
  end

  def create_vuln_def(name, vuln_id, description, recommendation, cwe=nil, cve=nil)

    vuln_def = {
      scanner_identifier: "#{vuln_id}",
      scanner_type: SCAN_SOURCE,
    }

    vuln_def[:name] = "#{name}" if name
    vuln_def[:description] = "#{description}" if description
    vuln_def[:recommendation] = "#{recommendation}" if recommendation
    vuln_def[:cwe_identifiers] = cwe if cwe
    vuln_def[:cve_identifiers] = cve if cve

    # Dedupe
    return unless $vuln_defs.select{|v| vuln_def == v }.empty?
    $vuln_defs << vuln_def
  end

end
end