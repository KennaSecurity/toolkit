module Kenna
  module Toolkit
    module Helpers

      def print_usage
        puts "[ ]                                                               "
        puts "[+] ========================================================      "
        puts "[+]  Welcome to the Kenna Security API & Scripting Toolkit!       "
        puts "[+] ========================================================      "
        puts "[ ]                                                               "
        puts "[ ] Usage:                                                        "
        puts "[ ]                                                               "
        puts "[ ] In order to use the toolkit, you must pass a 'task' argument  "
        puts "[ ] which specifies the function to perform. Each task has a set  "
        puts "[ ] of required and optional parameters which can be passed to    "
        puts "[ ] it.                                                           "
        puts "[ ]                                                               "
        puts "[ ] To see the usage for a given tasks, simply pass the task name "
        puts "[ ] and the and its options, separated by a semicolon!            "
        puts "[ ]                                                               "
        puts "[ ] Example:                                                      "
        puts "[ ] ruby toolkit.rb task=example:example_option=true              "
        puts "[ ]                                                               "
        puts "[ ] If you have questions or require assistance, please contact   "
        puts "[ ] support@kennasecurity.com                                     "
        puts "[ ]                                                               "
        puts "[ ]                                                               "
      end

      def print(message=nil)
        puts "[ ] #{message}"
      end

      def print_good(message=nil)
        puts "[+] #{message}"
      end

      def print_error(message=nil)
        puts "[!] #{message}"
      end
    end
  end
end
