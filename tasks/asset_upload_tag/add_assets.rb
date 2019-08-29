module Kenna 
module Toolkit
class AssetUploadTag < Kenna::Toolkit::BaseTask

  def metadata 
    {
      id: "add_assets",
      name: "Add Assets",
      description: "This task does blah blah blah (TODO)",
      options: [
        {:name => "kenna_api_token", 
          :type => "api_key", 
          :required => true, 
          :default => nil, 
          :description => "Kenna API Key" },
        {:name => "kenna_api_host", 
          :type => "hostname", 
          :required => false  , 
          :default => "api.kennasecurity.com", 
          :description => "Kenna API Hostname" },
        {:name => "primary_locator", 
          :type => "string", 
          :required => false, 
          :default => "ip_address", 
          :description => "Field to use as the primary locator"  },
        {:name => "csv_file", 
          :type => "filename", 
          :required => true, 
          :default => "input/assets.csv", 
          :description => "Path to CSV file"  },
        {:name => "field_mapping_file", 
          :type => "filename", 
          :required => false, 
          :default => "tasks/asset_upload_tag/field_mapping.csv", 
          :description => "Path to field mapping file, relative to #{$basedir}"  },
        {:name => "tag_mapping_file", 
          :type => "filename", 
          :required => false, 
          :default => "tasks/asset_upload_tag/tag_mapping.csv", 
          :description => "Path to tag mapping file, relative to #{$basedir}"  }
      ]
    }
  end


  # api_token, primary_locator, field_mapping_file,csv_file,tag_column_file
  def run(options)
    super

    #These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
    #@token = ARGV[0]
    @token = @options[:kenna_api_token]

    #@primary_locator = ARGV[1]
    @primary_locator = @options[:primary_locator]

    #@field_mapping_file = ARGV[2]
    @field_mapping_file = @options[:field_mapping_file]

    #@csv_file = ARGV[3]
    @csv_file = @options[:csv_file]

    #ARGV.length == 5 ? @tag_column_file = ARGV[4] : @tag_column_file = nil
    # @tag_column_file = tag_column_file
    @tag_column_file = @options[:tag_mapping_file]

    #Variables we'll need later
    @debug = true
    @post_url = "https://#{@options[:kenna_api_host]}/assets"
    @headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }

    @tag_columns = []

    # Encoding characters
    enc_colon = "%3A"
    enc_dblquote = "%22"
    enc_space = "%20"

    puts "Path:#{$basedir}/#{@csv_file}"


    ## Set columns to use for tagging, if a @tag_column_file is provided

    # tag_columns = File.readlines(@tag_column_file).map{|line| line.strip}.uniq.reject(&:empty?) if !@tag_column_file.nil?
    num_lines = CSV.read(@csv_file).length
    puts "Found #{num_lines} lines."

    # binding.pry

    puts "Setting Field Mappings"
    set_field_mappings(@field_mapping_file)
    puts "Setting Tag Mappings"
    set_tag_mapping(@tag_column_file)

    # binding.pry

    # STOP HERE

    ## Iterate through CSV
    CSV.foreach(@csv_file, :headers => true){ |row|
      # "Reading line #{$.}... "
      current_line = $.
      ip_address = nil
      hostname = nil
      url = nil
      mac_address = nil
      database = nil
      netbios = nil
      fqdn = nil
      file_name = nil
      application_name = nil

      #your csv column names should match these if you don't want to change the script
      next if row["#{@ip_address_col}"].nil?
      ip_address = row["#{@ip_address_col}"]
      hostname = row["#{@hostname_col}"]
      url = row["#{@url_col}"]
      mac_address = row["#{@mac_address_col}"]
      database = row["#{@database_col}"]
      netbios = row["#{@netbios_col}"]
      fqdn = row["#{@fqdn_col}"]
      file_name = row["#{@file_name_col}"]
      application_name = row["#{@application_name_col}"]

      # binding.pry
      
      puts "#{ip_address}"
      json_data = {
        'asset' => {
          'primary_locator' => "#{@primary_locator}",
          'ip_address' => "#{ip_address}",
          'hostname' => "#{hostname}",
          'database' => "#{database}",
          'url' => "#{url}",
          'mac_address' => "#{mac_address}",
          'netbios' => "#{netbios}",
          'fqdn' => "#{fqdn}",
          'file' => "#{file_name}",
          'application' => "#{application_name}"
        }
      }
      
      # DBro - Added Tagging Section
      tag_list = [] 
      if @tag_columns.count > 0 then
        @tag_columns.each{|item|
          pull_column = []
          pull_string = ""  # <==== Should this be an array? The loop next doesn't work.
          pull_column = CSV.parse_line("#{item[0]}")
          pull_column.each{|col|
            pull_string << "#{row[col]} "
          } 
          pull_string = pull_string.strip
          if !pull_string.nil? && !pull_string.empty? then
            # If is has a delimiter defined
            if !item[2].nil? then  
              if !item[1].nil? then
                pull_string.split(item[2]).each { |e| tag_list << "#{item[1]}#{e}"}
              else
                pull_string.split(item[2]).each { |e| tag_list << "#{e}"}
              end
            # If is has NO delimiter defined
            else
              if !item[1].nil? then
                tag_list << "#{item[1]}#{pull_string}"
              else
                tag_list << "#{pull_string}"
              end
            end
          end
        }
      end

      tag_string = ""
      tag_list.each{|t| 
        t = t.gsub(/[\s,]/ ," ")
        tag_string << "#{t}," }
      tag_string = tag_string[0...-1]


      # binding.pry

      puts "========================"
      puts json_data
      puts "------------------------"
      puts tag_list
      puts "========================"

    # ========================
    # Add Asset
    # ========================

      puts json_data
      puts @post_url
      begin
        query_post_return = RestClient::Request.execute(
          method: :post,
          url: @post_url,
          payload: json_data,
          headers: @headers
        )
      rescue RestClient::UnprocessableEntity 

        puts "#{query_post_return}"

      rescue RestClient::BadRequest
        
        puts "Unable to add....Primary Locator data missing for this item."  

      end

      # binding.pry

      # Need to find the new asset ID 
      # asset_id = query_post_return........
      asset_id = JSON.parse(query_post_return)["asset"]["id"]

      # ========================
      # Add Tags
      # ========================

      if !tag_string.empty? then 
        tag_update_json = {
          'asset' => {
          'tags' => "#{tag_string}"
          }


        }## Push tags to assets

        tag_api_url = "#{@post_url}/#{asset_id}/tags"
        puts tag_api_url if @debug
        puts tag_update_json if @debug

        tag_update_response = RestClient::Request.execute(
          method: :put,
          url: tag_api_url,
          headers: @headers,
          payload: tag_update_json,
          timeout: 10
        )

        sleep(0.02)

      end

    }

  end


  def set_field_mappings(csv_file)

    CSV.parse(File.open(csv_file, 'r:iso-8859-1:utf-8'){|f| f.read}, headers: true) do |row|

      case row['Kenna Field']
      when 'ip_address'
        @ip_address_col = row['Customer Field']
      when 'hostname'
        @hostname_col = row['Customer Field']
      when 'url'
        @url_col = row['Customer Field']
      when 'mac_address'
        @mac_address_col = row['Customer Field']
      when 'database'
        @database_col = row['Customer Field']
      when 'netbios'
        @netbios_col = row['Customer Field']
      when 'fqdn'
        @fqdn_col = row['Customer Field']
      when 'file_name'
        @file_name_col = row['Customer Field']
      when 'application'
        @application_col = row['Customer Field']
      end
    end

    puts 'Finished with field mapping'
  end


  def set_tag_mapping(csv_file)
    if !csv_file.empty? && !csv_file.nil? then
      CSV.foreach(csv_file, :headers => true, :encoding => "UTF-8"){|row|
        @tag_columns << Array[row[0],row[1],row[2]]
      }
      puts "tag_columns = #{@tag_columns.to_s}" if @debug
    else
      puts "No Tag File Specified."
    end
  end

end
end
end