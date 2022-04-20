# frozen_string_literal: true

require "json"
require "json-write-stream/yielding"
require "json-write-stream/stateful"

class JsonWriteStream
  DEFAULT_ENCODING = Encoding::UTF_8

  class << self
    def from_stream(stream, options = {})
      encoding = options.fetch(:encoding, DEFAULT_ENCODING)
      stream.set_encoding(encoding)

      if block_given?
        yield writer = YieldingWriter.new(stream)
        writer.close
      else
        StatefulWriter.new(stream, options)
      end
    end

    def open(file, options = {})
      encoding = options.fetch(:encoding, DEFAULT_ENCODING)
      handle = File.open(file, "w")
      handle.set_encoding(encoding)

      if block_given?
        yield writer = YieldingWriter.new(handle)
        writer.close
      else
        StatefulWriter.new(handle, options)
      end
    end
  end
end
