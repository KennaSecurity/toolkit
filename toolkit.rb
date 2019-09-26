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

# Task manager
require_relative 'lib/task_manager'

# tasks / scripts
require_relative 'tasks/base'

### GLOBAL VARIABLES - ONLY SET THESE ONCE
$basedir = "#{File.expand_path(File.dirname(__FILE__))}"
puts "Base Directory: #{$basedir}"
### END GLOBALS

# LoadS pecific tasks 
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
when "asset_upload_tag"
  Kenna::Toolkit::AssetUploadTag.new.run(args)
when "example"
  Kenna::Toolkit::Example.new.run(args)
when "help"
  print_usage && exit
when "footprinting_csv_to_kdi"
  Kenna::Toolkit::FootprintingCsvToKdi.new.run(args)
when "inspect_api_token"
  Kenna::Toolkit::InspectApiToken.new.run(args)
when "aws_guardduty_to_kdi"
  Kenna::Toolkit::AwsGuarddutyToKdi.new.run(args)
when "aws_inspector_to_kdi"
  Kenna::Toolkit::AwsInspectorToKdi.new.run(args)
when "upload_file"
  Kenna::Toolkit::UploadFile.new.run(args)
when "user_role_sync"
  Kenna::Toolkit::UserRoleSync.new.run(args)
else
  puts "[!] Error! Unknown task requested!"
end
