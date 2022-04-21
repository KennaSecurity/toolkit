# frozen_string_literal: true

class JsonWriteStream
  class YieldingWriter
    attr_reader :stream, :index, :options

    def initialize(stream, options = {})
      @stream = stream
      @index = 0
      @options = options
      after_initialize
    end

    def after_initialize; end

    def write_object(comma_written: false)
      unless comma_written
        write_comma
        increment
      end

      yield writer = YieldingObjectWriter.new(stream)
      writer.close
    end

    def write_array(comma_written: false)
      unless comma_written
        write_comma
        increment
      end

      yield writer = YieldingArrayWriter.new(stream)
      writer.close
    end

    def flush; end

    def close
      stream.close
    end

    protected

    def escape(str)
      JSON.generate([str])[1..-2]
    end

    def write_comma
      stream.write(",") if index.positive?
    end

    def increment
      @index += 1
    end
  end

  class YieldingObjectWriter < YieldingWriter
    def after_initialize
      stream.write("{")
    end

    def write_array(key)
      write_comma
      increment
      write_key(key)
      stream.write(":")
      super(true)
    end

    def write_object(key)
      write_comma
      increment
      write_key(key)
      stream.write(":")
      super(true)
    end

    def write_key_value(key, value)
      write_comma
      increment
      write_key(key)
      stream.write(":")
      stream.write(escape(value))
    end

    def close
      stream.write("}")
    end

    private

    def write_key(key)
      stream.write(escape(key.to_s))
    end
  end

  class YieldingArrayWriter < YieldingWriter
    def after_initialize
      stream.write("[")
    end

    def write_element(element)
      write_comma
      increment
      stream.write(escape(element))
    end

    def close
      stream.write("]")
    end
  end
end
