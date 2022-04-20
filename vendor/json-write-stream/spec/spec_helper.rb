# frozen_string_literal: true

require "rspec"
require "json-write-stream"
require "shared_examples"
require "pry-byebug"

RSpec.configure do |config|
end

class RoundtripChecker
  class << self
    include RSpec::Matchers

    def check_roundtrip(obj, options = {})
      stream = StringIO.new
      writer = create_writer(stream, options)
      serialize(obj, writer)
      writer.close
      new_obj = JSON.parse(stream.string)
      compare(obj, new_obj)
    end

    private

    def compare(old_obj, new_obj)
      expect(old_obj.class).to equal(new_obj.class)

      case old_obj
      when Hash
        expect(old_obj.keys).to eq(new_obj.keys)

        old_obj.each_pair do |key, old_val|
          compare(old_val, new_obj[key])
        end
      when Array
        old_obj.each_with_index do |old_element, idx|
          compare(old_element, new_obj[idx])
        end
      else
        expect(old_obj).to eq(new_obj)
      end
    end
  end
end

class YieldingRoundtripChecker < RoundtripChecker
  class << self
    protected

    def create_writer(stream, options = {})
      JsonWriteStream::YieldingWriter.new(stream, options)
    end

    def serialize(obj, writer)
      case obj
      when Hash
        writer.write_object do |object_writer|
          serialize_object(obj, object_writer)
        end
      when Array
        writer.write_array do |array_writer|
          serialize_array(obj, array_writer)
        end
      end
    end

    def serialize_object(obj, writer)
      obj.each_pair do |key, val|
        case val
        when Hash
          writer.write_object(key) do |object_writer|
            serialize_object(val, object_writer)
          end
        when Array
          writer.write_array(key) do |array_writer|
            serialize_array(val, array_writer)
          end
        else
          writer.write_key_value(key, val)
        end
      end
    end

    def serialize_array(obj, writer)
      obj.each do |element|
        case element
        when Hash
          writer.write_object do |object_writer|
            serialize_object(element, object_writer)
          end
        when Array
          writer.write_array do |array_writer|
            serialize_array(element, array_writer)
          end
        else
          writer.write_element(element)
        end
      end
    end
  end
end

class StatefulRoundtripChecker < RoundtripChecker
  class << self
    protected

    def create_writer(stream, options = {})
      JsonWriteStream::StatefulWriter.new(stream, options)
    end

    def serialize(obj, writer)
      case obj
      when Hash
        writer.write_object
        serialize_object(obj, writer)
        writer.close_object
      when Array
        writer.write_array
        serialize_array(obj, writer)
        writer.close_array
      end
    end

    def serialize_object(obj, writer)
      obj.each_pair do |key, val|
        case val
        when Hash
          writer.write_object(key)
          serialize_object(val, writer)
          writer.close_object
        when Array
          writer.write_array(key)
          serialize_array(val, writer)
          writer.close_array
        else
          writer.write_key_value(key, val)
        end
      end
    end

    def serialize_array(obj, writer)
      obj.each do |element|
        case element
        when Hash
          writer.write_object
          serialize_object(element, writer)
          writer.close_object
        when Array
          writer.write_array
          serialize_array(element, writer)
          writer.close_array
        else
          writer.write_element(element)
        end
      end
    end
  end
end
