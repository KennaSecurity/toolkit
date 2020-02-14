#!/usr/bin/env ruby

require_relative '../lib/toolkit'
require 'pry'

alias print puts
alias print_bad puts
alias print_good puts
alias print_error puts

###
### Define the prompt & drop into pry repl
###
Pry.start(self, :prompt => [proc{"toolkit>"}])