# standard dependencies
require 'rest-client'
require 'json'
require 'csv'

# initialize monkeypatches & other hacks
require_relative '../initialize/hash'
require_relative '../initialize/string'

# local deps
require_relative 'helpers'
require_relative 'http'
# rubocop:todo Style/MixinUsage
include Kenna::Toolkit::Helpers
include Kenna::Toolkit::Helpers::Http
# rubocop:enable Style/MixinUsage

# Shared libraries / mapping / data etc
require_relative 'data/mapping/digi_footprint_finding_mapper'
require_relative 'data/mapping/digi_footprint_port_mapper'

# Task manager
require_relative 'task_manager'

# kenna api client
require_relative 'api/client'

# KDI Helpers
require_relative 'kdi/kdi_helpers'

# tasks / scripts
require_relative '../tasks/base'

### GLOBAL VARIABLES - ONLY SET THESE ONCE
$basedir = File.expand_path("..", File.dirname(__FILE__)).to_s
### END GLOBALS

# Tasks
Dir.glob("#{$basedir}/tasks/*.rb").each { |file| require_relative(file) }
Dir.glob("#{$basedir}/tasks/*/*.rb").each { |file| require_relative(file) }
