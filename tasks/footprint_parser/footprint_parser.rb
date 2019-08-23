require 'fileutils'

require_relative "translators/lib/mapping"
require_relative "translators/lib/helpers"

include Kenna::Helpers
include Kenna::Mapping::External

module Kenna 
module Toolkit
class FootprintParser < Kenna::Toolkit::BaseTask

  def metadata 
    {
      id: "footprint_parser",
      name: "Footprint Parser",
      description: "This task parses digital footprinting data from CSV files",
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
        {:name => "upload_to_api", 
          :type => "boolean", 
          :required => false, 
          :default => false, 
          :description => "Push the results directly to API using a connector config file?" },
        {:name => "connector_config_file", 
          :type => "filename", 
          :required => false , 
          :default => "input/footprint/connectors.json", 
          :description => "Connector configuration file" },
        {:name => "input_directory", 
          :type => "filename", 
          :required => false, 
          :default => "input/footprinting", 
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

    parse_csvs

    if @options[:upload_to_api]
      upload_results
    end

  end

  def file_mapping
    files = [
      { name: "bitsight_application_security", connector_id: 148278 },
      { name: "bitsight_dkim", connector_id: 148277 },
      { name: "bitsight_dnssec", connector_id: 145511 },
      { name: "bitsight_insecure_systems", connector_id: 149332 },
      { name: "bitsight_open_ports", connector_id: 148249 },
      { name: "bitsight_patching_cadence", connector_id: 148248 },
      { name: "bitsight_server_software", connector_id: 148247 },
      { name: "bitsight_spf", connector_id: 148246 },
      { name: "bitsight_ssl_certificates", connector_id: 148245 },
      { name: "bitsight_ssl_configurations", connector_id: 148276 },
      { name: "expanse_application_server_software", connector_id: 148262 },
      #{ name: "expanse_certificate_advertisements", connector_id:  },
      { name: "expanse_development_environments", connector_id: 148258 },
      { name: "expanse_dns_servers", connector_id: 147874 },
      #{ name: "expanse_domain_control_validated_certificate", connector_id: 148260 },
      { name: "expanse_expired_when_scanned_certificate_advertisements", connector_id: 148261 },
      { name: "expanse_ftps_servers", connector_id: 148263 }, # 147878
      { name: "expanse_healthy_certificate_advertisements", connector_id: 149331 },
      { name: "expanse_insecure_signature_advertisements", connector_id: 148266 },
      { name: "expanse_internal_ip_address_advertisements", connector_id: 148281 },
      { name: "expanse_load_balancers", connector_id: 149330 },
      { name: "expanse_long_expiration_certificate_advertisements", connector_id: 148270 },
      { name: "expanse_mysql_servers", connector_id: 148275 },
      { name: "expanse_open_ports", connector_id: 148250 },
      { name: "expanse_pop3_servers", connector_id: 147888 },
      { name: "expanse_self_signed_certificate_advertisements", connector_id: 148267 },
      { name: "expanse_server_software", connector_id: 149333 },
      { name: "expanse_short_key_certificate_advertisements", connector_id: 148273 },
      { name: "expanse_sip_servers", connector_id: 148271 },
      { name: "expanse_smtp_servers", connector_id: 147894 },
      { name: "expanse_snmp_servers", connector_id: 147893 },
      { name: "expanse_ssh_servers", connector_id: 148272 },
      { name: "expanse_telnet_servers", connector_id: 147891 },
      { name: "expanse_unencrypted_ftp_servers", connector_id: 147896 }, # 147878?
      { name: "expanse_unencrypted_logins", connector_id: 147898 },
      { name: "expanse_web_servers", connector_id: 147895 },
      { name: "expanse_wildcard_certificate_advertisements", connector_id: 148274 },
      { name: "riskiq_ips", connector_id: 149334 },
      { name: "riskiq_open_port_database_servers", translator: "riskiq_open_ports", connector_id: 148253 },
      { name: "riskiq_open_port_iot", translator: "riskiq_open_ports", connector_id: 148254 },
      { name: "riskiq_open_port_networking_equipment", translator: "riskiq_open_ports", connector_id: 148256 },
      { name: "riskiq_open_port_registered", translator: "riskiq_open_ports", connector_id: 148257 },
      { name: "riskiq_open_port_remote_access", translator: "riskiq_open_ports",connector_id: 148254 },
      { name: "riskiq_open_port_system", translator: "riskiq_open_ports", connector_id: 148255 },
      { name: "riskiq_open_port_web_servers", translator: "riskiq_open_ports", connector_id: 148251 },
      { name: "riskiq_websites", connector_id: 148280 },
      { name: "security_scorecard_issues", connector_id: 148279 },
    ]
  end

  def parse_csvs

    # for each file, read the file, parse it into output and upload it
    files = file_mapping

    files.each do |f|
      print_good "Running #{f[:name]}"

      # if we have an explicit translator, use that, otherwise just use the name 
      translator_name = f[:translator] ? "#{f[:translator]}_kdi_translator.rb" : "#{f[:name]}_kdi_translator.rb"
      
      # HAX - run this until we convert into classes
      command_line = "bundle exec ruby #{$basedir}/tasks/footprint_parser/translators/#{translator_name} #{$basedir}/#{@options[:input_directory]}/#{f[:name]}.csv"
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
    
    files = file_mapping

    @MAX_RETRIES = 3
    @TOKEN = @options[:kenna_api_key]
    @LOCATOR_DELIMITER = ":"

    kenna_api_host = @options[:kenna_api_host]
    puts "Sending Results to API at: #{kenna_api_host}"

    @API_ENDPOINT = "https://#{kenna_api_host}/connectors"
    @headers = {
      'content-type' => 'application/json', 
      'X-Risk-Token' => @TOKEN,
      'accept' => 'application/json'
    }

    ## Sanity check 
    ## 
    unless @TOKEN
      puts "Unable to find API Token, cowardly refusing to continue!"
      puts "Please add an API Token in a file named .token and retry"
      puts 
      puts "Note that if you're running in a container, you'll need to rebuild"
      puts 
      exit -1 
    end 


    def directory_exists?(directory)
      Dir.exists?(directory)
    end

    def _log(line)

      print_line = "#{Time.now.strftime("%Y%m%dT%H%m%s")} (#{@filename.split("/").last}): #{line}"
      #output_filename = "upload.log"
      #File.open(output_filename,'a+').write print_line
      puts print_line 

    end


    files.each do |f|

      @filename = "#{$basedir}/#{@options[:output_directory]}/#{f[:name]}.json" 

      shortname = @filename.split("/").last

      connector_endpoint = "#{@API_ENDPOINT}/#{f[:connector_id]}/data_file?run=true"

      unless f[:connector_id]
        _log "WARNING! Skipping connector #{f[:name]}, no connector id!"
        next 
      end

      begin
        _log "Sending request"
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

        connector_check_endpoint = "#{@API_ENDPOINT}/#{f[:connector_id]}"
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
        _log "Bad Request: #{e.message}... #{e}"
      rescue RestClient::Exception => e
        _log "Unknown Exception... #{e}"

        @retries ||= 0
        if @retries < @MAX_RETRIES
          _log "Retrying in 60s..."
          @retries += 1
          sleep(60)
          retry
        else
         _log "Max retries hit, failing with... #{e}"

        end
      end

      _log "Done!"
    end


  end

end
end
end