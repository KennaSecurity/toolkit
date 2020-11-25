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
        puts "[ ] via the task=[name] argument and the options, separated by spaces. "
        puts "[ ]                                                                    "
        puts "[ ] For DEBUG output and functionality, set the debug=true option.     "
        puts "[ ]                                                                    "
        puts "[ ] Example:                                                           "
        puts "[ ] task=example option1=true option2=abc                              "
        puts "[ ]                                                                    "
        puts "[ ] At this time, toolkit usage is strictly UNSUPPORTED.               "
        puts "[ ]                                                                    "
        puts "[ ]                                                                    "
        puts "[ ] Tasks:"
        TaskManager.tasks.sort_by { |x| x.metadata[:id] }.each do |t|
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

      def print(message = nil)
        puts "[ ] (#{timestamp_long}) #{message}"
      end

      def print_good(message = nil)
        puts "[+] (#{timestamp_long}) #{message}"
      end

      def print_error(message = nil)
        puts "[!] (#{timestamp_long}) #{message}"
      end

      def print_debug(message = nil)
        if @options && @options[:debug]
          puts "[D] (#{timestamp_long}) #{message}"
        end
      end

      def print_task_help(task_name)
        task = TaskManager.tasks.select { |x| x.metadata[:id] == task_name }.first.new
        task.class.metadata[:options].each do |o|
          puts "- Task Option: #{o[:name]} (#{o[:type]}): #{o[:description]}"
          puts "               Required:(#{o[:required]}): Default: #{o[:default]}"
        end
      end

      ###
      ### Helper to read a file consistently
      ###
      def read_input_file(filename)
        output = File.open(filename, "r").read.gsub!("\r", '')
        output.sanitize_unicode
      end

      def print_readme(task_name)
        if File.exist?("#{$basedir}/tasks/#{task_name}/readme.md")
          readme = File.open("#{$basedir}/tasks/#{task_name}/readme.md").read
          readme_header = "\n \n \n \n# ***********************************************\n"
          readme_header << "#     Displaying readme.md for #{task_name} \n"
          readme_header << "# ***********************************************\n"
          readme_header << "\n "
          readme_header << "\n "
          readme = readme_header + readme
          pager = TTY::Pager.new
          pager.page(readme.to_s)
        else
          print_error("No readme.md found for #{task_name}")
        end
      end

      ###
      ### Helper to write a file consistently
      ###
      def write_file(directory, filename, output)
        FileUtils.mkdir_p directory

        # create full output path
        output_path = "#{directory}/#{filename}"

        # write it, char by char to avoid large mem issues
        File.open(output_path, "wb") do |file|
          output.each_char { |char| file.write char }
        end
      end

      def run_files_on_kenna_connector(connector_id, api_host, api_token, upload_ids, max_retries = 3)
        # optionally upload the file if a connector ID has been specified
        return unless connector_id && api_host && api_token

        print_good "Attempting to upload to Kenna API"
        print_good "Kenna API host: #{api_host}"

        # upload it
        if connector_id && connector_id != -1
          kenna = Kenna::Api::Client.new(api_token, api_host)
          kenna.run_files_on_connector(connector_id, upload_ids, max_retries)
        else
          print_error "Invalid Connector ID (#{connector_id}), unable to upload."
        end
      end

      ###
      ### Helper to upload to kenna api
      ###

      def upload_file_to_kenna_connector(connector_id, api_host, api_token, filename, run_now = true, max_retries = 3)
        # optionally upload the file if a connector ID has been specified
        return unless connector_id && api_host && api_token

        print_good "Attempting to upload to Kenna API"
        print_good "Kenna API host: #{api_host}"

        # upload it
        if connector_id && connector_id != -1
          kenna = Kenna::Api::Client.new(api_token, api_host)
          query_response_json = kenna.upload_to_connector(connector_id, filename, run_now, max_retries)
        else
          print_error "Invalid Connector ID (#{connector_id}), unable to upload."
        end

        return query_response_json
      end
    end
  end
end
