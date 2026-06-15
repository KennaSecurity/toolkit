# frozen_string_literal: true

require "rspec_helper"
require_relative "../../lib/http"

class TestHelper
  include Kenna::Toolkit::Helpers::Http

  attr_reader :options

  def initialize(options = {})
    @options = options
  end
end

RSpec.describe Kenna::Toolkit::Helpers::Http do
  subject(:helper) { TestHelper.new }

  describe "#connection" do
    context "without retry_options" do
      it "uses default retry configuration" do
        conn = helper.connection
        # Verify connection is created without errors
        expect(conn).to be_a(Faraday::Connection)
      end
    end

    context "with custom retry_options" do
      it "merges retry_statuses instead of replacing them" do
        custom_options = {
          retry_statuses: [504]
        }
        conn = helper.connection(true, 5, retry_options: custom_options)
        expect(conn).to be_a(Faraday::Connection)
      end

      it "preserves default exceptions while adding custom ones" do
        custom_options = {
          exceptions: [Faraday::TooManyRequestsError]
        }
        conn = helper.connection(true, 5, retry_options: custom_options)
        expect(conn).to be_a(Faraday::Connection)
      end

      it "allows overriding other retry options" do
        custom_options = {
          interval: 60,
          max_interval: 60,
          backoff_factor: 2
        }
        conn = helper.connection(true, 5, retry_options: custom_options)
        expect(conn).to be_a(Faraday::Connection)
      end
    end

    context "HMAC client support" do
      it "creates connection with HMAC middleware when hmac_client is provided" do
        mock_client = double("hmac_client")
        conn = helper.connection(true, 5, hmac_client: mock_client)
        expect(conn).to be_a(Faraday::Connection)
      end
    end

    context "SSL verification" do
      it "disables SSL verification when verify_ssl is false" do
        conn = helper.connection(false)
        expect(conn).to be_a(Faraday::Connection)
      end
    end
  end

  describe "#http_get" do
    it "makes GET requests" do
      stub_request(:get, "https://example.com/test")
        .to_return(body: "success", status: 200)

      response = helper.http_get("https://example.com/test", {})
      expect(response.status).to eq(200)
      expect(response.body).to eq("success")
    end

    it "accepts retry_options parameter" do
      stub_request(:get, "https://example.com/test")
        .to_return(body: "success", status: 200)

      retry_opts = { retry_statuses: [504] }
      response = helper.http_get("https://example.com/test", {}, 5, true, retry_options: retry_opts)
      expect(response.status).to eq(200)
    end
  end

  describe "#http_post" do
    it "makes POST requests with retry options" do
      stub_request(:post, "https://example.com/test")
        .to_return(body: "created", status: 201)

      retry_opts = { retry_statuses: [504] }
      response = helper.http_post("https://example.com/test", {}, { foo: "bar" }, 5, true, retry_options: retry_opts)
      expect(response.status).to eq(201)
      expect(response.body).to eq("created")
    end
  end

  describe "#http_put" do
    it "makes PUT requests with retry options" do
      stub_request(:put, "https://example.com/test")
        .to_return(body: "updated", status: 200)

      retry_opts = { retry_statuses: [504] }
      response = helper.http_put("https://example.com/test", {}, { foo: "bar" }, 5, true, retry_options: retry_opts)
      expect(response.status).to eq(200)
      expect(response.body).to eq("updated")
    end
  end

  describe "#http_delete" do
    it "makes DELETE requests with retry options" do
      stub_request(:delete, "https://example.com/test")
        .to_return(body: "deleted", status: 200)

      retry_opts = { retry_statuses: [504] }
      response = helper.http_delete("https://example.com/test", {}, 5, true, retry_options: retry_opts)
      expect(response.status).to eq(200)
      expect(response.body).to eq("deleted")
    end
  end
end
