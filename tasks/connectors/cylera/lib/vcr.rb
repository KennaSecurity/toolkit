# frozen_string_literal: true

require 'vcr'

VCR.configure do |config|
  config.cassette_library_dir = 'spec/fixtures/vcr_cassettes'
  config.allow_http_connections_when_no_cassette = true
  config.hook_into :webmock
  config.ignore_request do |request|
    URI(request.uri).host != 'cylera.host'
  end
end

def http_get(uri, headers)
  use_cassette(URI(uri).query) do
    super
  end
end

def http_post(uri, headers, body)
  use_cassette do
    super
  end
end

def use_cassette(query = '', &)
  VCR.use_cassette('cylera', erb: { query: }, &)
end
