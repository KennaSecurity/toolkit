# frozen_string_literal: true

$toolkit_debug = false
$toolkit_running_local = true

def debug?
  $toolkit_debug
end

def running_local?
  $toolkit_running_local
end
