#!/usr/bin/ruby

# standard dependencies
require 'rest-client'
require 'json'
require 'csv'

# local deps
require_relative 'lib/helpers'
include Kenna::Toolkit::Helpers

# tasks / scripts
require_relative 'tasks/base'

# Specific tasks 
require_relative 'tasks/asset_upload_tag/add_assets'
require_relative 'tasks/example'
require_relative 'tasks/footprinting_csv_to_kdi/footprinting_csv_to_kdi'
require_relative 'tasks/inspect_api_token'
require_relative 'tasks/inspector_to_kdi'
require_relative 'tasks/user_role_sync/user_role_sync'

### GLOBAL VARIABLES - ONLY SET THESE ONCE
$basedir = "/opt/toolkit"
### END GLOBALS

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
    puts "[!] FATAL! Invalid Argument: #{arg}"
    puts "[!] All arguments should take the form [name]=[value]"
    puts "[!] Multiple arguments should be separated by a semicolon (;)"
    exit
  end

  # set the arg value into the hash
  args[arg_name] = arg_value
end

# Fail if we didnt get a task 
unless args[:task]
  puts "[!] FATAL! Missing required argument: 'task'"
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
when "inspector_to_kdi"
  Kenna::Toolkit::InspectorToKdi.new.run(args)
when "user_role_sync"
  Kenna::Toolkit::UserRoleSync.new.run(args)
else
  puts "[!] Error! Unknown task requested!"
end
