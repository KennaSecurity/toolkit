module Kenna
  module Toolkit
    module Helpers

      def print_usage
        puts "[ ]                                                                    "
        puts "[+] ========================================================           "
        puts "[+]  Welcome to the Kenna Security API & Scripting Toolkit!            "
        puts "[+] ========================================================           "
        puts "[ ]                                                                    "
        puts "[ ] Usage:                                                             "
        puts "[ ]                                                                    "
        puts "[ ] In order to use the toolkit, you must pass a 'task' argument       "
        puts "[ ] which specifies the function to perform. Each task has a set       "
        puts "[ ] of required and optional parameters which can be passed to         "
        puts "[ ] it via the command line.                                           "
        puts "[ ]                                                                    "
        puts "[ ] To see the usage for a given tasks, simply pass the task name      "
        puts "[ ] via the task=[name] argument and the options, separated by colons. "
        puts "[ ]                                                                    " 
        puts "[ ] For DEBUG output and functionality, set the debug=true option.     " 
        puts "[ ]                                                                    " 
        puts "[ ] Example:                                                           "
        puts "[ ] ruby toolkit.rb task=example:option1=true:option2=abc              "
        puts "[ ]                                                                    "
        puts "[ ] At this time, toolkit usage is strictly UNSUPPORTED.               "
        puts "[ ]                                                                    "
        puts "[ ]                                                                    "
        puts "[ ] Tasks:"
        TaskManager.tasks.sort_by{|x| x.metadata[:id] }.each do |t|
          task = t.new
          puts "[+]  - \033[1m#{task.class.metadata[:id]}\033[0m: #{task.class.metadata[:description]}"
        end
        puts "[ ]                                                                    "
      end

      def timestamp
        DateTime.now.strftime("%Y%m%d%H")
      end

      def timestamp_long
        DateTime.now.strftime("%Y%m%d%H%M%S")
      end

      def print(message=nil)
        puts "[ ] (#{timestamp_long}) #{message}"
      end

      def print_good(message=nil)
        puts "[+] (#{timestamp_long}) #{message}"
      end

      def print_error(message=nil)
        puts "[!] (#{timestamp_long}) #{message}"
      end

      def print_debug(message=nil)
        puts "[D] (#{timestamp_long}) #{message}" if @options[:debug]
      end

      def print_task_help(task_name)
        task = TaskManager.tasks.select{|x| x.metadata[:id] == task_name }.first.new
        task.class.metadata[:options].each do |o|
          puts "- Task Option: #{o[:name]} (#{o[:type]}): #{o[:description]}"
        end
      end

      ###
      ### Helper to read a file consistently
      ### 
      def read_input_file(filename)
        output = File.open(filename,"r").read.gsub!("\r", '') 
      output.sanitize_unicode
      end

      ###
      ### Helper to write a file consistently
      ### 
      def write_file(directory,filename,output)

        FileUtils.mkdir_p directory
        
        # create full output path
        output_path = "#{directory}/#{filename}"

        # write it
        File.open(output_path,"w") {|f| f.puts output } 
      end

      ###
      ### Helper to upload to kenna api
      ###
      def upload_kdi(connector_id, api_host, api_token, kdi_file)
        # optionally upload the file if a connector ID has been specified 
        if connector_id && api_host && api_token
      
          print_good "Attempting to upload to Kenna API"
          print_good "Kenna API host: #{api_host}"

          # upload it 
          if connector_id && connector_id != -1 
            kenna = Kenna::Api::Client.new(kenna_api_token, kenna_api_host)
            kenna.upload_to_connector(connector_id, output_path)
          else 
            print_error "Invalid Connector ID (#{connector_id}), unable to upload."
          end
        end
      end

      
    end
  end
end
