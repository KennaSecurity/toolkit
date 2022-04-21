# frozen_string_literal: true

require "json"

class JsonWriteStream
  class NotInObjectError < StandardError; end
  class NotInArrayError < StandardError; end
  class EndOfStreamError < StandardError; end

  class StatefulWriter
    attr_reader :stream, :stack, :index, :closed, :options
    alias closed? closed

    def initialize(stream, options = {})
      @stream = stream
      @stack = []
      @closed = false
      @options = options
      @index = 0
    end

    def write_object(*args)
      check_eos
      new_indent_level = 1

      if current
        current.write_object(*args)
        new_indent_level = current.indent_level + 1
      end

      stack.push(StatefulObjectWriter.new(self, new_indent_level))
    end

    def write_array(*args)
      check_eos

      new_indent_level = 1

      if current
        current.write_array(*args)
        new_indent_level = current.indent_level + 1
      end

      stack.push(StatefulArrayWriter.new(self, new_indent_level))
    end

    def write_key_value(*args)
      check_eos
      current.write_key_value(*args)
    end

    def write_element(*args)
      check_eos
      current.write_element(*args)
    end

    def close_object
      raise NotInObjectError, "not currently writing an object." unless in_object?

      stack.pop.close
      current&.increment
      increment

      # if in_object?
      #   stack.pop.close
      #   current&.increment
      #   increment
      # else
      #   raise NotInObjectError, "not currently writing an object."
      # end
    end

    def close_array
      raise NotInArrayError, "not currently writing an array." unless in_array?

      stack.pop.close
      current&.increment
      increment

      # if in_array?
      #   stack.pop.close
      #   current&.increment
      #   increment
      # else
      #   raise NotInArrayError, "not currently writing an array."
      # end
    end

    def flush
      until stack.empty?
        if in_object?
          close_object
        else
          close_array
        end
      end

      @closed = true
      nil
    end

    def close
      flush
      stream.close
      nil
    end

    def in_object?
      current ? current.object? : false
    end

    def in_array?
      current ? current.array? : false
    end

    def eos?
      (stack.size.zero? && index.positive?) || closed?
    end

    def pretty?
      options.fetch(:pretty, false)
    end

    def indent_size
      options.fetch(:indent_size, 2)
    end

    protected

    def increment
      @index += 1
    end

    def check_eos
      raise EndOfStreamError, "end of stream." if eos?
    end

    def current
      stack.last
    end
  end

  class BaseWriter
    attr_reader :writer, :indent_level, :index

    def initialize(writer, indent_level)
      @writer = writer
      @indent_level = indent_level
      @index = 0
      after_initialize
    end

    def after_initialize; end

    def stream
      writer.stream
    end

    def increment
      @index += 1
    end

    def indent(level = indent_level)
      stream.write(" " * indent_size * level) if pretty?
    end

    def indent_size
      writer.indent_size
    end

    def escape(str)
      JSON.generate([str])[1..-2]
    end

    def write_comma
      return unless index.positive?

      stream.write(",")
      write_newline

      # if index.positive?
      #   stream.write(",")
      #   write_newline
      # end
    end

    def write_colon
      stream.write(":")
      stream.write(" ") if pretty?
    end

    def write_newline
      stream.write("\n") if pretty?
    end

    def pretty?
      writer.pretty?
    end
  end

  class StatefulObjectWriter < BaseWriter
    def after_initialize
      stream.write("{")
      write_newline
    end

    # prep work (array is written afterwards)
    def write_array(key)
      write_comma
      increment
      indent
      write_key(key)
      write_colon
    end

    # prep work (object is written afterwards)
    def write_object(key)
      write_comma
      increment
      indent
      write_key(key)
      write_colon
    end

    def write_key_value(key, value)
      write_comma
      increment
      indent
      write_key(key)
      write_colon
      stream.write(escape(value))
    end

    def close
      write_newline
      indent(indent_level - 1)
      stream.write("}")
    end

    def object?
      true
    end

    def array?
      false
    end

    private

    def write_key(key)
      case key
      when String
        stream.write(escape(key))
      else
        raise ArgumentError, "'#{key}' must be a string"
      end
    end
  end

  class StatefulArrayWriter < BaseWriter
    def after_initialize
      stream.write("[")
      write_newline
    end

    def write_element(element)
      write_comma
      increment
      indent
      stream.write(escape(element))
    end

    # prep work
    def write_array
      write_comma
      increment
      indent
    end

    # prep work
    def write_object
      write_comma
      increment
      indent
    end

    def close
      write_newline
      indent(indent_level - 1)
      stream.write("]")
    end

    def object?
      false
    end

    def array?
      true
    end
  end
end
