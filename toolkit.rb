#!/usr/bin/ruby

# standard dependencies
require 'rest-client'
require 'json'
require 'csv'

# initialize monkeypatches & other hacks
require_relative 'initialize/string'

# local deps
require_relative 'lib/helpers'
include Kenna::Toolkit::Helpers

# libraries
require_relative 'lib/data/digital_footprinting'

# Task manager
require_relative 'lib/task_manager'

# tasks / scripts
require_relative 'tasks/base'

### GLOBAL VARIABLES - ONLY SET THESE ONCE
$basedir = "#{File.expand_path(File.dirname(__FILE__))}"
puts "Base Directory: #{$basedir}"
### END GLOBALS

# Load specific tasks 
Dir["#{$basedir}/tasks/*.rb"].each { |file| require_relative(file) }
Dir["#{$basedir}/tasks/*/*.rb"].each { |file| require_relative(file) }

# First split up whatever we got
args_array = "#{ARGV[0]}".split(":")

# Then split up this into a hash
args = {}
args_array.each do |arg| 

  arg_name  = arg.split("=").first.to_sym
  arg_value = arg.split("=").last

  # handle a request for just "help" as a special case
  #if arg_name = "help"
  #  print_usage && exit
  #end

  # make sure all arguments were well formed
  unless arg_name && arg_value
    print_error "FATAL! Invalid Argument: #{arg}"
    print_error "All arguments should take the form [name]=[value]"
    print_error "Multiple arguments should be separated by a semicolon (;)"
    exit
  end

  # set the arg value into the hash
  args[arg_name] = arg_value
end

# Fail if we didnt get a task 
unless args[:task]
  print_error "FATAL! Missing required argument: 'task'"
  print_usage
  exit
end

# handle task request
case args[:task]
  when "help"
    print_usage && exit
  else
    task_class = Kenna::Toolkit::TaskManager.find_task_by_id(args[:tas])
    if task_class
      task.class.new.run(args)
    else
      puts "[!] Error. Unknown task requested!"
    end
end
