require_relative '../../../lib/toolkit'
require_relative '../../../spec/rspec_helper'
require 'rspec'

describe "Kenna" do
  describe "Toolkit" do
    describe "SecurityScorecard" do
      describe "Client" do
        before do
          @api_key = (ENV['SSC_API_KEY']).to_s
          @client = Kenna::Toolkit::Ssc::Client.new @api_key
        end

        it "can authenticate" do
          expect(@client.successfully_authenticated?).to be true
        end

        it "can get a portfolio" do
          puts @client.get_portfolio
        end

        it "can get all issues for all companies in portfolio" do
          pid = @client.get_portfolio["entries"].first["id"]
          issues = @client.get_issues_for_portfolio(pid, ["patching_cadence_low"])
          expect(issues.first).to be_a Hash

          issues = @client.get_issues_for_portfolio(pid, ["open_resolver"])
          expect(issues.first).to be_a Hash
        end
      end
    end
  end
end
