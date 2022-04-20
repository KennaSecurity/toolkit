# frozen_string_literal: true

require "mkmf"

$defs << "-DJSON_GENERATOR"
create_makefile "json/ext/generator"
