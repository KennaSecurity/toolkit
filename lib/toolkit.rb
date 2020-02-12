# standard dependencies
require 'rest-client'
require 'json'
require 'csv'

# initialize monkeypatches & other hacks
require_relative '../initialize/string'

# local deps
require_relative 'helpers'
include Kenna::Toolkit::Helpers

# libraries
require_relative 'data/digital_footprinting'

# Task manager
require_relative 'task_manager'

# API Helpers
require_relative 'api' # kenna api client 
require_relative 'kdi_helpers'

# tasks / scripts
require_relative '../tasks/base'

### GLOBAL VARIABLES - ONLY SET THESE ONCE
$basedir = "#{File.expand_path("..", File.dirname(__FILE__))}"
### END GLOBALS

puts "BASE: #{$basedir}"

# Tasks
Dir["#{$basedir}/tasks/*.rb"].each { |file| require_relative(file) }
Dir["#{$basedir}/tasks/*/*.rb"].each { |file| require_relative(file) }