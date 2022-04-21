# frozen_string_literal: true

require "spec_helper"

describe JsonWriteStream::YieldingWriter do
  let(:stream) do
    StringIO.new.tap do |io|
      io.set_encoding(Encoding::UTF_8)
    end
  end

  let(:stream_writer) { JsonWriteStream::YieldingWriter.new(stream) }

  def check_roundtrip(obj, options = {})
    YieldingRoundtripChecker.check_roundtrip(obj, options)
  end

  def utf8(str)
    str.encode(Encoding::UTF_8)
  end

  it_behaves_like "a json stream"
  it_behaves_like "a json stream", pretty: true

  describe "#write_key_value" do
    it "converts all keys to strings" do
      stream_writer.write_object do |object_writer|
        object_writer.write_key_value(123, "abc")
      end

      expect(stream.string).to eq(utf8('{"123":"abc"}'))
    end

    it "supports non-string values" do
      stream_writer.write_object do |object_writer|
        object_writer.write_key_value("abc", 123)
        object_writer.write_key_value("def", true)
      end

      expect(stream.string).to eq(utf8('{"abc":123,"def":true}'))
    end
  end

  describe "#close" do
    it "closes the underlying stream" do
      stream_writer.close
      expect(stream).to be_closed
    end
  end
end
