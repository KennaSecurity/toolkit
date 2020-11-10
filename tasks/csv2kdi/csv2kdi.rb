require_relative "lib/csv2kdi_helper"

module Kenna
module Toolkit
class Csv2kdi < Kenna::Toolkit::BaseTask

  include Kenna::Toolkit::Csv2kdihelper

  def self.metadata
    {
      id: "csv2kdi",
      name: "csv2kdi",
      description: "Converts CSV source to KDI JSON",
      options: [
        {:name => "csv_in",
          :type => "string",
          :required => false,
          :default => "input.csv",
          :description => "CSV to be converted to KDI JSON" },
        {:name => "has_header",
          :type => "boolean",
          :required => false,
          :default => true,
          :description => "Does the input file have a header?" },
        {:name => "meta_file",
          :type => "string",
          :required => false,
          :default => "meta.csv",
          :description => "File to map input to Kenna fields" },
        {:name => "skip_autoclose",
          :type => "string",
          :required => false,
          :default => "false",
          :description => "If vuln not in scan, do you want to close vulns?" },
        { :name => "assets_only",
            :type => "string",
            :required => false,
            :default => "false",
            :description => "Field to indicate assets only - no vulns" },
        { :name => "domain_suffix",
            :type => "string",
            :required => false,
            :default => nil,
            :description => "Optional domain suffix for hostnames" },
        { :name => "input_directory",
          :type => "string",
          :required => false,
          :default => "input",
          :description => "Where input files are found. Path is relative to #{$basedir}/"  },
        { :name => "output_directory",
          :type => "string",
          :required => false,
          :default => "output",
          :description => "If set, will write a file upon completion. Path is relative to #{$basedir}/"  },
        { :name => "kenna_api_host",
            :type => "string",
            :required => false,
            :default => "api.kennasecurity.com",
            :description => "Host used for the API endpoint" },
        { :name => "kenna_connector_id",
            :type => "integer",
            :required => false,
            :default => nil,
            :description => "ID required for connector to ingest file converted" },
        { :name => "kenna_api_key",
          :type => "string",
          :required => false,
          :default => nil,
          :description => "Kenna API code to be used to ingest"  }
      ]
    }
  end

  def run(opts)
    super # opts -> @options

    @csv_in = @options[:csv_in]
    @has_header = @options[:has_header]
    @meta_file = @options[:meta_file]
    $skip_autoclose = @options[:auto_close]
    @assets_only = @options[:assets_only]
    @domain_suffix = @options[:domain_suffix]
    @kenna_api_host = @options[:kenna_api_host]
    @kenna_connector_id = @options[:kenna_connector_id]
    @kenna_api_key = @options[:kenna_api_key]
    @output_directory = @options[:output_directory]
    @input_directory = @options[:input_directory]
    @domain_suffix = @options[:domain_suffix]


    @debug = true
    $map_locator = ''


    #Global variables required between methods
    $assets = []
    $vuln_defs = []
    $mapping_array = []
    $date_format_in = ''
    #meta = $basedir/@meta_file

    CSV.parse(File.open("#{$basedir}/#{@input_directory}/#{@meta_file}", 'r:iso-8859-1:utf-8'){|f| f.read}, :headers => @has_header.eql?('true') ? true : false) do |row|

      $mapping_array << Array[row[0],row[1]]
      $mapping_array.compact

    end
    #headers =
    $date_format_in = "#{$mapping_array.assoc('date_format').last}"
    $map_locator = "#{$mapping_array.assoc('locator').last}"
    map_file = "#{$mapping_array.assoc('file').last}"
    map_ip_address = "#{$mapping_array.assoc('ip_address').last}"
    map_mac_address = "#{$mapping_array.assoc('mac_address').last}"
    map_hostname = "#{$mapping_array.assoc('hostname').last}"
    map_ec2 = "#{$mapping_array.assoc('ec2').last}"
    map_netbios = "#{$mapping_array.assoc('netbios').last}"
    map_url = "#{$mapping_array.assoc('url').last}"
    map_fqdn = "#{$mapping_array.assoc('fqdn').last}"
    map_external_id = "#{$mapping_array.assoc('external_id').last}"
    map_database = "#{$mapping_array.assoc('database').last}"
    map_application = "#{$mapping_array.assoc('application').last}"
    map_tags = "#{$mapping_array.assoc('tags').last}"
    map_tag_prefix = "#{$mapping_array.assoc('tag_prefix').last}"
    map_owner = "#{$mapping_array.assoc('owner').last}"
    map_os = "#{$mapping_array.assoc('os').last}"
    map_os_version = "#{$mapping_array.assoc('os_version').last}"
    map_priority = "#{$mapping_array.assoc('priority').last}"


    if @assets_only == "false" then #Added for ASSET ONLY Run
      map_scanner_source = "#{$mapping_array.assoc('scanner_source').last}"
      map_scanner_type = "#{$mapping_array.assoc('scanner_type').last}"
      map_scanner_id = "#{$mapping_array.assoc('scanner_id').last}"
      map_scanner_id.encode!("utf-8")
      map_details = "#{$mapping_array.assoc('details').last}"
      map_created = "#{$mapping_array.assoc('created').last}"
      map_scanner_score = "#{$mapping_array.assoc('scanner_score').last}"
      map_last_fixed = "#{$mapping_array.assoc('last_fixed').last}"
      map_last_seen = "#{$mapping_array.assoc('last_seen').last}"
      map_status = "#{$mapping_array.assoc('status').last}"
      map_closed = "#{$mapping_array.assoc('closed').last}"
      map_port = "#{$mapping_array.assoc('port').last}"
      map_cve_id = "#{$mapping_array.assoc('cve_id').last}"
      map_wasc_id = "#{$mapping_array.assoc('wasc_id').last}"
      map_cwe_id = "#{$mapping_array.assoc('cwe_id').last}"
      map_name = "#{$mapping_array.assoc('name').last}"
      map_description = "#{$mapping_array.assoc('description').last}"
      map_solution = "#{$mapping_array.assoc('solution').last}"
      score_map_string = "#{$mapping_array.assoc('score_map').last}"
      status_map_string = "#{$mapping_array.assoc('status_map').last}"
      score_map = JSON.parse(score_map_string) unless score_map_string.nil? || score_map_string.empty?
      status_map = JSON.parse(status_map_string) unless status_map_string.nil? || status_map_string.empty?
    end      #Added for ASSET ONLY Run

    # Configure Date format
    ###########################
    # CUSTOMIZE Date format
    ###########################
    #date_format_in = "%m/%d/%Y %H:%M"
    date_format_KDI = "%Y-%m-%d-%H:%M:%S"


    CSV.parse(File.open("#{$basedir}/#{@input_directory}/#{@csv_in}", 'r:iso-8859-1:utf-8'){|f| f.read}, :headers => true ? true : false) do |row|

      ##################
      #  CSV MAPPINGS  #
      ##################
      # Asset settings #
      ##################

        locator = row["#{$map_locator}"]     # field used to compare for dupes
        file = row["#{map_file}"]                 #(string) path to affected file
        ip_address = row["#{map_ip_address}"]                  #(string) ip_address of internal facing asset
        mac_address = row["#{map_mac_address}"]                     #(mac format-regex) MAC address asset
        hostname = row["#{map_hostname}"]                  #(string) hostname name/domain name of affected asset
        ec2 = row["#{map_ec2}"]                    #(string) Amazon EC2 instance id or name
        netbios = row["#{map_netbios}"]                 #(string) netbios name
        url = row["#{map_url}"]
        url = url.strip unless url.nil?                  #(string) URL pointing to asset
        fqdn = row["#{map_fqdn}"]              #(string) fqdn of asset
        external_id = row["#{map_external_id}"]                #(string) ExtID of asset-Often used as an int org name for asset
        database = row["#{map_database}"]                    #(string) Name of database
        application = row["#{map_application}"]                   #(string) ID/app Name

        #Added for ASSET ONLY Run
        if @domain_suffix != nil && (@assets_only == "false" || @assets_only == false) then hostname += ".#{@domain_suffix}" end

      #########################
      # Asset Metadata fields #
      #########################
        tag_list = map_tags.split(',')   #(string) list of strings that correspond to tags on an asset
        prefix_list = map_tag_prefix.split(',')
        #puts tag_list
        tags = []
        count = 0
        tag_list.each do |col|
          col = col.gsub(/\A['"]+|['"]+\Z/, "")
          if !row[col].nil? && !row[col].empty? then
            if prefix_list.empty? then
              tags << "#{row[col]}"
            else
              tags << prefix_list[count] + "#{row[col]}"
            end
          end
          count+=1
        end
        owner = row["#{map_owner}"]                 #(string) Some string that identifies an owner of an asset
        os = row["#{map_os}"]                 #(string) Operating system of asset
        os_version = row["#{map_os_version}"]                  #(string) OS version
        priority = row["#{map_priority}"].to_i   unless  row["#{map_priority}"].nil? || row["#{map_priority}"].empty? #(Integer) Def:10 - Priority of asset (int 1 to 10).Adjusts asset score.

      if @assets_only == "false" then #Added for ASSET ONLY Run

        #########################
        # Vulnerability Section #
        #########################
          if map_scanner_source == "static" then
            scanner_type = "#{map_scanner_type}"    #(string) - default is freeform if nil from CSV
          else
            scanner_type = row["#{map_scanner_type}"]     #(string) - default is freeform if nil from CSV
          end
          raise "no scanner type found!" unless !scanner_type.nil? && !scanner_type.empty?
          scanner_id = row["#{map_scanner_id}"]
          raise "no scanner id found!" unless !scanner_id.nil? && !scanner_id.empty?
          details = row["#{map_details}"]            #(string) - Details about vuln
          created = row["#{map_created}"]
          if score_map.nil? || score_map.empty? then             #(string) - Date vuln created
            scanner_score = row["#{map_scanner_score}"].to_i  unless  row["#{map_scanner_score}"].nil? || row["#{map_scanner_score}"].empty?    #(Integer) - scanner score
          else
            scanner_score = score_map[row["#{map_scanner_score}"]].to_i  unless  row["#{map_scanner_score}"].nil? || row["#{map_scanner_score}"].empty?    #(Integer) - scanner score
          end
          last_fixed = row["#{map_last_fixed}"]            #(string) - Last fixed date
          last_seen = row["#{map_last_seen}"]
          if status_map.nil? || status_map.empty? then
            status = row["#{map_status}"]            #(string) #Rqd Def if nil; open status by default if not in import
          else
            status = status_map[row["#{map_status}"]]
          end
          closed = row["#{map_closed}"]                #(string) Date it was closed
          port = row["#{map_port}"].to_i  unless row["#{map_port}"].nil? ||row["#{map_port}"].empty? #(Integer) Port if associated with vuln

        ############################
        # Vulnerability Definition #
        ############################

        #in vuln section ##  scanner =
        #in vuln section ##  scanner_id =
          cve_id = row["#{map_cve_id}"]            #(string) Any CVE(s)?
          wasc_id = row["#{map_wasc_id}"]                #(string) Any WASC?
          cwe_id = row["#{map_cwe_id}"]                 #(string) Any CWE?
          name = row["#{map_name}"]               #(string) Name/title of Vuln
          description = row["#{map_description}"]             #(string) Description
          solution = row["#{map_solution}"]          #(string) Solution
      end #Added for ASSET ONLY Run

    ##call the methods that will build the json now##

      status = "open" if status.nil? || status.empty?
      # Convert the dates
      created = DateTime.strptime(created,$date_format_in).strftime(date_format_KDI) unless created.nil? || created.empty?
      last_fixed = DateTime.strptime(last_fixed,$date_format_in).strftime(date_format_KDI) unless last_fixed.nil? || last_fixed.empty?

    if last_seen.nil? || last_seen.empty? then
        #last_seen = "2019-03-01-14:00:00"
       last_seen = DateTime.now.strftime(date_format_KDI)
    else
      last_seen = DateTime.strptime(last_seen,$date_format_in).strftime(date_format_KDI)
    end

      closed = DateTime.strptime(closed,$date_format_in).strftime(date_format_KDI) unless closed.nil?

      ### CREATE THE ASSET
      done  = create_asset(file,ip_address,mac_address,hostname,ec2,netbios,url,fqdn,external_id,database,application,tags,owner,os,os_version,priority)
      #puts "create assset = #{done}"
      next if !done

      ### ASSOCIATE THE ASSET TO THE VULN



      if @assets_only == "false" then #Added for ASSET ONLY Run

        create_asset_vuln(hostname,ip_address,file, mac_address,netbios,url,ec2,fqdn,external_id,database,scanner_type,scanner_id,details,created,scanner_score,last_fixed,
                        last_seen,status,closed,port)

        # CREATE A VULN DEF THAT HAS THE SAME ID AS OUR VULN
        create_vuln_def(scanner_type,scanner_id,cve_id,wasc_id,cwe_id,name,description,solution)
      end

    end

    #puts JSON.pretty_generate kdi_output

    #f = File.new('#{$basedir}/#{kdi_out}', 'w')
    #f.write(JSON.pretty_generate kdi_output)
    #f.close
    #print_good "Output is available at: #{$basedir}/#{kdi_out}"
    ### Write KDI format
    #kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
    kdi_output = generate_kdi_file
    output_dir = "#{$basedir}/#{@options[:output_directory]}"
    filename = "kdiout#{@kenna_connector_id}_#{Time.now.strftime("%Y%m%d%H%M%S")}.json"
    write_file output_dir, filename, JSON.pretty_generate(kdi_output)
    print_good "Output is available at: #{output_dir}/#{filename}"

    ### Finish by uploading if we're all configured
    if @kenna_connector_id && @kenna_api_host && @kenna_api_key
      print_good "Attempting to upload to Kenna API at #{@kenna_api_host}"
      upload_file_to_kenna_connector @kenna_connector_id, @kenna_api_host, @kenna_api_key, "#{output_dir}/#{filename}"
    end
  end



end
end
end
