require 'rspec_helper'

RSpec.describe Kenna::Toolkit::SecurityScorecard do 
    let(:security_scorecard) { described_class.new }

    describe "#ip?" do 
        context "when given a valid ip input" do 
            it "returns truthy for valid ipv4" do 
                expect(security_scorecard.ip?('192.168.1.1')).to be_truthy
            end

            it "returns truthy for valid ipv6" do 
                expect(security_scorecard.ip?('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).to be_truthy
            end
        end

        context "when given invalid ip input" do 
            it "return false for incomplete ipv4" do
                expect(security_scorecard.ip?('00.32.123')).to be false
            end

            it "return false for string ips" do
                expect(security_scorecard.ip?('1234')).to be false
            end

            it "return false for nil input" do 
                expect(security_scorecard.ip?(nil)).to be false
            end

            it "return false for empty input" do 
                expect(security_scorecard.ip?('')).to be false
            end
        end
    end

    describe "#url" do 
        context "when given valid url" do
            it "return true for valid url" do 
                expect(security_scorecard.url?('https://example.com')).to be_truthy
            end 
        end

        context "when given invalid url" do 
            it "retrun false for empty string" do 
                expect(security_scorecard.url?('')).to be false
            end

            it "return false when http or https is missing" do
                expect(security_scorecard.url?('example.com')).to be false
            end
        end
    end

    describe "#scc_issue_to_kdi_asset_hash" do 
        let(:issue) do
            {
                "connection_attributes" => {
                    "dst_ip" => "192.168.1.1",
                    "dst_host" => "example.com",
                    "dst_port" => 80
                },
                "hostname" => "example.com",
                "subdomain" => "sub.example.com", 
                "common_name" => "example.com",
                "target" => "example.com",
                "ip_address" => "192.168.1.1",
                "src_ip" => "200.205.32.55",
                "initial_url" => "https://example.com",
                "url" => "https://example.com"
            }
        end

        context "when issue has valid attributes" do
            it "returns asset attributes hash" do
                result = security_scorecard.ssc_issue_to_kdi_asset_hash(issue)
                
                expect(result).to be_a(Hash)
                expect(result["tags"]).to include("SecurityScorecard")
                expect(result["hostname"]).to eq("example.com")
                expect(result["ip_address"]).to eq("192.168.1.1")
            end
        end

        context "when issue has missing attributes" do
            it "still returns asset hash when other attributes are present" do
                issue_with_missing_attributes = issue.dup
                issue_with_missing_attributes.delete("connection_attributes")
                result = security_scorecard.ssc_issue_to_kdi_asset_hash(issue_with_missing_attributes)
                
                expect(result).to be_a(Hash)
                expect(result["tags"]).to include("SecurityScorecard")
                expect(result["hostname"]).to eq("example.com") # from issue["hostname"]
                expect(result["ip_address"]).to eq("192.168.1.1") # from issue["ip_address"]
            end

            it "returns nil when no valid identifiers are found" do
                empty_issue = {}
                result = security_scorecard.ssc_issue_to_kdi_asset_hash(empty_issue)
                
                expect(result).to be_nil
            end

            it "returns nil when connection_attributes is not a hash" do
                invalid_issue = { "connection_attributes" => "not a hash" }
                result = security_scorecard.ssc_issue_to_kdi_asset_hash(invalid_issue)
                
                expect(result).to be_nil
            end
        end
    end
end