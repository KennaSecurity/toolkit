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
        puts "[X] (#{timestamp_long}) #{message}"
      end

      def read_input_file(filename)
        output = File.open(filename,"r").read.gsub!("\r", '') 
      output.sanitize_unicode
      end

    end
  end
end
