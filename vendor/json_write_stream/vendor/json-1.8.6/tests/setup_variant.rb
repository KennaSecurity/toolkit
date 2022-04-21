# frozen_string_literal: true

case ENV["JSON"]
when "pure"
  $LOAD_PATH.unshift "lib"
  require "json/pure"
when "ext"
  $LOAD_PATH.unshift "ext", "lib"
  require "json/ext"
else
  $LOAD_PATH.unshift "ext", "lib"
  require "json"
end
