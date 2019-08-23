require 'fileutils'

require_relative "lib/mapping"
require_relative "lib/helpers"

include Kenna::Helpers
include Kenna::Mapping::External

module Kenna 
module Toolkit
class FootprintingCsvToKdi < Kenna::Toolkit::BaseTask

  def metadata 
    {
      id: "footprinting_csv_to_kdi",
      name: "Footprinting Data CSV -> KDI Converter",
      description: "This task parses digital footprinting data from CSV files into KDI and optionally uploads them.",
      options: [
        {:name => "kenna_api_token", 
          :type => "api_key", 
          :required => false, 
          :default => nil, 
          :description => "Kenna API Key" },
        {:name => "kenna_api_host", 
          :type => "hostname", 
          :required => false , 
          :default => "api.kennasecurity.com", 
          :description => "Kenna API Hostname" },
        {:name => "parse_files", 
          :type => "boolean", 
          :required => false, 
          :default => false, 
          :description => "Parse CSV files?" },
        {:name => "upload_to_api", 
          :type => "boolean", 
          :required => false, 
          :default => true, 
          :description => "Push the results directly to API using a connector config file?" },
        {:name => "connector_config_file", 
          :type => "filename", 
          :required => false , 
          :default => "input/footprinting/connectors.json", 
          :description => "Connector configuration file" },
        {:name => "input_directory", 
          :type => "filename", 
          :required => false, 
          :default => "
          /footprinting", 
          :description => "Path to footprinting data, relative to #{$basedir}"  },
        {:name => "output_directory", 
          :type => "filename", 
          :required => false, 
          :default => "output/footprinting", 
          :description => "Path to parsing output, relative to #{$basedir}"  }
      ]
    }
  end

  def run(options)
    super


    @config = parse_configuration_file

    unless @config
      print_error "Nothing to do, empty config file!"
    end

    if @config.empty?
      print_error "Nothing to do, empty config file!"
    end

    # parse them up
    parse_csv_files_to_kdi

    # and upload 
    if @options[:upload_to_api]
      upload_results
    end

    print_good "Done!"

  end

  def parse_configuration_file
    filename = "#{$basedir}/#{@options[:connector_config_file]}"
    print_good "Attempting to parse config file: #{filename}"
    config = File.open(filename,"r").read
    begin 
      JSON.parse(config, { symbolize_names: true })
    rescue JSON::ParserError 
      print_error "FATAL! Unable to parse json file: #{filename}"
    end
  end

  # 
  # This function uses the hardcoded mapping to generate a config file
  #
  # NOT used in normal operation, but can be handy to generate a new / scratch config
  #
  #def generate_config_file
  #  config = []
  #
  #  configuration_file.each do |m|
  #    headers = []
  #    File.open("#{$basedir}/#{@options[:input_directory]}/#{m[:name]}.csv","r:UTF-8") { |x| headers = x.first.split(",")}
  #    config << m.merge(headers: headers.map{|x|x.downcase})
  #  end
  #
  #  File.open("#{$basedir}/#{@options[:output_directory]}/footprinting_csv_to_kdi.json","w"){|f| f.puts JSON.pretty_generate(config)}
  #end

  def parse_csv_files_to_kdi

    # for each entry in the config, read the file, parse it into output
    @config.each do |f|
      print_good "Running #{f[:name]}"

      # if we have an explicit translator, use that, otherwise just use the name 
      translator_name = f[:translator] ? "#{f[:translator]}_kdi_translator.rb" : "#{f[:name]}_kdi_translator.rb"
      
      # HAX - run this until we convert into classes
      command_line = "bundle exec ruby #{$basedir}/tasks/footprinting_csv_to_kdi/lib/translators/#{translator_name} #{$basedir}/#{@options[:input_directory]}/#{f[:name]}.csv"
      output = `#{command_line}`
      
      # Make the directory if it eodesnt exist
      FileUtils.mkdir_p "#{$basedir}/#{@options[:output_directory]}"

      output_file = "#{$basedir}/#{@options[:output_directory]}/#{f[:name]}.json"
      print_good "Writing output to #{output_file}"
      File.open(output_file,"w"){|f| f.puts output_file}
    end

  end


  def upload_results
    basedir = "#{File.expand_path(File.dirname(__FILE__))}"

    @MAX_RETRIES = 3
    @LOCATOR_DELIMITER = ":"

    kenna_api_host = @options[:kenna_api_host]
    kenna_api_token = @options[:kenna_api_token]

    unless kenna_api_host && kenna_api_token
      print_error "Unable to upload, missing host or token!"
      print_error "kenna_api_host: #{kenna_api_host}"
      print_error "kenna_api_token: #{kenna_api_token}"
    end

    kenna_api_endpoint = "https://#{kenna_api_host}/connectors"
    @headers = {
      'content-type' => 'application/json', 
      'X-Risk-Token' => kenna_api_token,
      'accept' => 'application/json'
    }

    ## Sanity check 
    ## 
    unless kenna_api_token
      print_good "Unable to find API Token, cowardly refusing to continue!"
      print_good "Please add an API Token in a file named .token and retry"
      print_good 
      print_good "Note that if you're running in a container, you'll need to rebuild"
      print_good 
      exit -1 
    end 


    @config.each do |f|

      @filename = "#{$basedir}/#{@options[:output_directory]}/footprinting/#{f[:name]}.json" 

      shortname = @filename.split("/").last

      connector_endpoint = "#{@enna_api_endpoint}/#{f[:connector_id]}/data_file?run=true"

      unless f[:connector_id]
        print_error "WARNING! Skipping connector #{f[:name]}, no connector id specified!"
        next 
      end

      begin
        print_good "Sending request"
        query_response = RestClient::Request.execute(
          method: :post,
          url: connector_endpoint,
          headers: @headers,
          payload: {
            multipart: true,
            file: File.new(@filename)
          }
        )

        query_response_json = JSON.parse(query_response.body)
        _log "Success!" if query_response_json.fetch("success")

        running = true

        connector_check_endpoint = "#{kenna_api_endpoint}/#{f[:connector_id]}"
        while running do
          _log "Waiting for 30 seconds... "
          sleep(30)

          #_log "Checking on connector status..."
          connector_check_response = RestClient::Request.execute(
            method: :get,
            url: connector_check_endpoint,
            headers: @headers
          )

          connector_check_json = JSON.parse(connector_check_response)['connector']
          _log "#{connector_check_json["name"]} running" if connector_check_json["running"]

          # check our value to see if we need to keep going
          running = connector_check_json["running"]
        end  

      rescue RestClient::UnprocessableEntity => e
        _log "Unprocessable Entity: #{e.message}..."
      rescue RestClient::BadRequest => e
        print_error "Bad Request: #{e.message}... #{e}"
      rescue RestClient::Exception => e
        print_error "Unknown Exception... #{e}"

        @retries ||= 0
        if @retries < @MAX_RETRIES
          print_error "Retrying in 60s..."
          @retries += 1
          sleep(60)
          retry
        else
         print_error "Max retries hit, failing with... #{e}"

        end
      end

      print_good "Done!"
    end

    def directory_exists?(directory)
      Dir.exists?(directory)
    end

    def _log(line)

      print_line = "#{Time.now.strftime("%Y%m%dT%H%m%s")} (#{@filename.split("/").last}): #{line}"
      #output_filename = "upload.log"
      #File.open(output_filename,'a+').write print_line
      print_good print_line 

    end


  end

end
end
end