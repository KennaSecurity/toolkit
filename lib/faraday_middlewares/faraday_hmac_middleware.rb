# frozen_string_literal: true

require 'faraday'

class FaradayHmac < Faraday::Middleware
  def initialize(app, client)
    super(app)
    @client = client
  end

  def call(env)
    uri = URI.parse(env.url.to_s)
    auth_path = "#{uri.path}?#{uri.query}"
    env.request_headers['Authorization'] = @client.hmac_auth_options(auth_path)[:Authorization]
    @app.call(env)
  end
end
