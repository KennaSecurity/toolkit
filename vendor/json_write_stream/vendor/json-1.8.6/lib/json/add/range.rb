# frozen_string_literal: true

require "json" unless defined?(::JSON::JSON_LOADED) && ::JSON::JSON_LOADED

# Range serialization/deserialization
class Range
  # Deserializes JSON string by constructing new Range object with arguments
  # <tt>a</tt> serialized by <tt>to_json</tt>.
  def self.json_create(object)
    new(*object["a"])
  end

  # Returns a hash, that will be turned into a JSON object and represent this
  # object.
  def as_json(*)
    {
      JSON.create_id => self.class.name,
      "a" => [first, last, exclude_end?]
    }
  end

  # Stores class name (Range) with JSON array of arguments <tt>a</tt> which
  # include <tt>first</tt> (integer), <tt>last</tt> (integer), and
  # <tt>exclude_end?</tt> (boolean) as JSON string.
  def to_json(*args)
    as_json.to_json(*args)
  end
end