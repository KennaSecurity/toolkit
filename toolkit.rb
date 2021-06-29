#!/usr/bin/ruby
# frozen_string_literal: true

# all dependencies
require_relative "lib/toolkit"

# First split up whatever we got
args_array = ARGV.map { |arg| arg.split(":") }.flatten

# Then split up this into a hash
args = {}
args_array.each do |arg|
  name_value = arg.split("=", 2)
  arg_name = name_value[0].to_sym
  arg_value = name_value[1]

  # handle a request for just "help" as a special case
  # if arg_name = "help"
  #  print_usage && exit
  # end

  # make sure all arguments were well formed
  unless arg_name && arg_value
    print_error "FATAL! Invalid Argument: #{arg}"
    print_error "All arguments should take the form [name]=[value]"
    print_error "Multiple arguments should be separated by colons (:) or spaces"
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
  task_class = Kenna::Toolkit::TaskManager.find_by_id((args[:task]).to_s.strip)
  if task_class
    puts "Running: #{task_class}"
    task_class.new.run(args)
  else
    puts "[!] Error. Unknown task requested!"
  end
end
