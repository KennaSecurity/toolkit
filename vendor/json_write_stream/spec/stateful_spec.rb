# frozen_string_literal: true

require "spec_helper"

describe JsonWriteStream::YieldingWriter do
  let(:stream) do
    StringIO.new.tap do |io|
      io.set_encoding(Encoding::UTF_8)
    end
  end

  let(:options) { {} }
  let(:stream_writer) { JsonWriteStream::StatefulWriter.new(stream, options) }

  def check_roundtrip(obj, options = {})
    StatefulRoundtripChecker.check_roundtrip(obj, options)
  end

  def utf8(str)
    str.encode(Encoding::UTF_8)
  end

  it_behaves_like "a json stream"

  context "with the pretty option" do
    let(:options) { { pretty: true } }

    it_behaves_like "a json stream", pretty: true

    it "prettifies a basic array" do
      stream_writer.write_array
      stream_writer.write_element("foo")
      stream_writer.close
      expect(stream.string).to eq(<<~JSON.strip)
        [
          "foo"
        ]
      JSON
    end

    it "prettifies a basic object" do
      stream_writer.write_object
      stream_writer.write_key_value("foo", "bar")
      stream_writer.close
      expect(stream.string).to eq(<<~JSON.strip)
        {
          "foo": "bar"
        }
      JSON
    end

    it "prettifies a complex structure" do
      stream_writer.write_object
      stream_writer.write_array("foo")
      stream_writer.write_element("bar")
      stream_writer.write_object
      stream_writer.write_key_value("baz", "moo")
      stream_writer.write_array("gaz")
      stream_writer.write_element("doo")
      stream_writer.close_array
      stream_writer.close_object
      stream_writer.write_element("kal")
      stream_writer.close_array
      stream_writer.write_array("jim")
      stream_writer.write_element("jill")
      stream_writer.write_array
      stream_writer.write_element("john")
      stream_writer.close
      expect(stream.string).to eq(<<~JSON.strip)
        {
          "foo": [
            "bar",
            {
              "baz": "moo",
              "gaz": [
                "doo"
              ]
            },
            "kal"
          ],
          "jim": [
            "jill",
            [
              "john"
            ]
          ]
        }
      JSON
    end

    context "and the indent_size option" do
      let(:options) { super().merge(indent_size: 4) }

      it "indents a basic object correctly" do
        stream_writer.write_object
        stream_writer.write_key_value("foo", "bar")
        stream_writer.close
        expect(stream.string).to eq(<<~JSON.strip)
          {
              "foo": "bar"
          }
        JSON
      end

      it "indents a more complicated object correctly" do
        stream_writer.write_object
        stream_writer.write_array("foo")
        stream_writer.write_element("bar")
        stream_writer.write_object
        stream_writer.write_key_value("baz", "moo")
        stream_writer.close
        expect(stream.string).to eq(<<~JSON.strip)
          {
              "foo": [
                  "bar",
                  {
                      "baz": "moo"
                  }
              ]
          }
        JSON
      end
    end
  end

  describe "#close" do
    it "unwinds the stack, adds appropriate closing punctuation for each unclosed item, and closes the stream" do
      stream_writer.write_array
      stream_writer.write_element("abc")
      stream_writer.write_object
      stream_writer.write_key_value("def", "ghi")
      stream_writer.close

      expect(stream.string).to eq(utf8('["abc",{"def":"ghi"}]'))
      expect(stream_writer).to be_closed
      expect(stream).to be_closed
    end
  end

  describe "#closed?" do
    it "returns false if the stream is still open" do
      expect(stream_writer).to_not be_closed
    end

    it "returns true if the stream is closed" do
      stream_writer.close
      expect(stream_writer).to be_closed
    end
  end

  describe "#in_object?" do
    it "returns true if the writer is currently writing an object" do
      stream_writer.write_object
      expect(stream_writer).to be_in_object
    end

    it "returns false if the writer is not currently writing an object" do
      expect(stream_writer).to_not be_in_object
      stream_writer.write_array
      expect(stream_writer).to_not be_in_object
    end
  end

  describe "#in_array?" do
    it "returns true if the writer is currently writing an array" do
      stream_writer.write_array
      expect(stream_writer).to be_in_array
    end

    it "returns false if the writer is not currently writing an array" do
      expect(stream_writer).to_not be_in_array
      stream_writer.write_object
      expect(stream_writer).to_not be_in_array
    end
  end

  describe "#eos?" do
    it "returns false if nothing has been written yet" do
      expect(stream_writer).to_not be_eos
    end

    it "returns false if the writer is in the middle of writing" do
      stream_writer.write_object
      expect(stream_writer).to_not be_eos
    end

    it "returns true if the writer has finished it's top-level" do
      stream_writer.write_object
      stream_writer.close_object
      expect(stream_writer).to be_eos
    end

    it "returns true if the writer is closed" do
      stream_writer.close
      expect(stream_writer).to be_eos
    end
  end

  describe "#close_object" do
    it "raises an error if an object is not currently being written" do
      stream_writer.write_array
      expect(-> { stream_writer.close_object }).to raise_error(JsonWriteStream::NotInObjectError)
    end
  end

  describe "#close_array" do
    it "raises an error if an array is not currently being written" do
      stream_writer.write_object
      expect(-> { stream_writer.close_array }).to raise_error(JsonWriteStream::NotInArrayError)
    end
  end

  context "with a closed stream writer" do
    before(:each) do
      stream_writer.close
    end

    describe "#write_object" do
      it "raises an error if eos" do
        expect(-> { stream_writer.write_object }).to raise_error(JsonWriteStream::EndOfStreamError)
      end
    end

    describe "#write_array" do
      it "raises an error if eos" do
        expect(-> { stream_writer.write_object }).to raise_error(JsonWriteStream::EndOfStreamError)
      end
    end

    describe "#write_key_value" do
      it "raises an error if eos" do
        expect(-> { stream_writer.write_key_value("abc", "def") }).to raise_error(JsonWriteStream::EndOfStreamError)
      end
    end

    describe "#write_element" do
      it "raises an error if eos" do
        expect(-> { stream_writer.write_element("foo") }).to raise_error(JsonWriteStream::EndOfStreamError)
      end
    end
  end
end
