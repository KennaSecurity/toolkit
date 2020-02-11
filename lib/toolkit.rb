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

# tasks / scripts
require_relative '../tasks/base'

### GLOBAL VARIABLES - ONLY SET THESE ONCE
$basedir = "#{File.expand_path(File.dirname(__FILE__), "..")}"
### END GLOBALS

# Load specific tasks 
Dir["#{$basedir}/tasks/*.rb"].each { |file| require_relative(file) }
Dir["#{$basedir}/tasks/*/*.rb"].each { |file| require_relative(file) }