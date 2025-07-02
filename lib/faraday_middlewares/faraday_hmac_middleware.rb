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
    auth_header = @client.hmac_auth_options(auth_path)[:Authorization]
    env.request_headers['Authorization'] = auth_header
    
    # Log when HMAC is being generated
    if auth_header&.include?('VERACODE-HMAC-SHA-256')
      timestamp = auth_header[/ts=(\d+)/, 1]
      nonce = auth_header[/nonce=([^,]+)/, 1]
      puts "HMAC MIDDLEWARE: Generated auth for #{env.method.upcase} #{env.url} - ts=#{timestamp}, nonce=#{nonce}"
    end
    
    @app.call(env)
  end
end
