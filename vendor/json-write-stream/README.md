json-write-stream
=================

[![Build Status](https://travis-ci.org/camertron/json-write-stream.svg?branch=master)](http://travis-ci.org/camertron/json-write-stream)

An easy, streaming way to generate JSON.

## Installation

`gem install json-write-stream`

## Usage

```ruby
require 'json-write-stream'
```

### Examples for the Impatient

There are two types of JSON write stream: one that uses blocks and `yield` to delimit arrays and objects, and one that's purely stateful. Here are two examples that produce the same output:

Yielding:

```ruby
stream = StringIO.new
JsonWriteStream.from_stream(stream) do |writer|
  writer.write_object do |obj_writer|
    obj_writer.write_key_value('foo', 'bar')
    obj_writer.write_array('baz') do |arr_writer|
      arr_writer.write_element('goo')
    end
  end
end
```

Stateful:

```ruby
stream = StringIO.new
writer = JsonWriteStream.from_stream(stream)
writer.write_object
writer.write_key_value('foo', 'bar')
writer.write_array('baz')
writer.write_element('goo')
writer.close  # automatically adds closing punctuation for all nested types
```

Output:

```ruby
stream.string # => {"foo":"bar","baz":["goo"]}
```

### Yielding Writers

As far as yielding writers go, the example above contains everything you need. The stream will be automatically closed when the outermost block terminates.

### Stateful Writers

Stateful writers have a number of additional methods:

```ruby
stream = StringIO.new
writer = JsonWriteStream.from_stream(stream)
writer.write_object

writer.in_object?    # => true, currently writing an object
writer.in_array?     # => false, not currently writing an array
writer.eos?          # => false, the stream is open and the outermost object hasn't been closed yet

writer.close_object  # explicitly close the current object
writer.eos?          # => true, the outermost object has been closed

writer.write_array   # => raises JsonWriteStream::EndOfStreamError
writer.close_array   # => raises JsonWriteStream::NotInArrayError

writer.closed?       # => false, the stream is still open
writer.close         # close the stream
writer.closed?       # => true, the stream has been closed
```

### Writing to a File

JsonWriteStream also supports streaming to a file via the `open` method:

Yielding:

```ruby
JsonWriteStream.open('path/to/file.json') do |writer|
  writer.write_object do |obj_writer|
    ...
  end
end
```

Stateful:

```ruby
writer = JsonWriteStream.open('path/to/file.json')
writer.write_object
...
writer.close
```

### Options

JsonWriteStream supports generating "pretty" JSON, i.e. JSON formatted in a more human-readable way. Currently only the stateful writer supports pretty generation. Example:

```ruby
stream = StringIO.new
writer = JsonWriteStream.from_stream(stream, pretty: true)
writer.write_object
writer.write_key_value('foo', 'bar')
writer.write_array('baz')
writer.write_element('goo')
writer.close
```

Now `stream.string` will contain

```json
{
  "foo": "bar",
  "baz": [
    "goo"
  ]
}
```

## Requirements

No external requirements.

## Running Tests

`bundle exec rake` should do the trick. Alternatively you can run `bundle exec rspec`, which does the same thing.

## Authors

* Cameron C. Dutro: http://github.com/camertron
