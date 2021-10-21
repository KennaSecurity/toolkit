# frozen_string_literal: true

require "rspec_helper"

RSpec.describe Kenna::Toolkit::WhitehatSentinel::Mapper do
  let(:scoring_system) { :legacy }

  subject(:mapper) { described_class.new(scoring_system) }

  describe "#finding_hash" do
    let(:node) { { id: node_id, found: found.iso8601, closed: closed&.iso8601, class: node_class, status: status, severity: severity.to_s, risk: risk, attack_vectors: attack_vectors } }
    let(:node_id) { 10_085 }
    let(:found) { Time.new(2021, 10, 22, 12, 13, 14).utc }
    let(:closed) { nil }
    let(:node_class) { "Insufficient Transport Layer Protection" }
    let(:status) { "new" }
    let(:severity) { 4 }
    let(:risk) { 3 }
    let(:attack_vectors) { [] }

    subject(:finding_hash) { mapper.finding_hash(node) }

    it { is_expected.to include(scanner_identifier: node_id) }
    it { is_expected.to include(scanner_type: "Whitehat Sentinel") }
    it { is_expected.to include(created_at: found) }
    it { is_expected.to_not include(:last_fixed_on) }
    it { is_expected.to_not include(:closed_at) }
    it { is_expected.to include(vuln_def_name: node_class) }

    it "sets last_seen_at to now" do
      now = Time.new(2021, 10, 30, 8, 9, 10).utc

      Timecop.freeze(now) do
        expect(mapper.finding_hash(node)).to include(last_seen_at: now)
      end
    end

    context "when the node has a closed attribute" do
      let(:closed) { Time.new(2021, 10, 23, 11, 12, 13).utc }

      it { is_expected.to include(last_seen_at: closed) }
      it { is_expected.to include(last_fixed_on: closed) }
      it { is_expected.to include(closed_at: closed) }
    end

    context "when the node's status is open" do
      let(:status) { "open" }

      it { is_expected.to include(triage_state: "in_progress") }
    end

    context "when the node's status is closed" do
      let(:status) { "closed" }

      it { is_expected.to include(triage_state: "resolved") }
    end

    context "when the node's status is accepted" do
      let(:status) { "accepted" }

      it { is_expected.to include(triage_state: "risk_accepted") }
    end

    context "when the node's status is invalid" do
      let(:status) { "invalid" }

      it { is_expected.to include(triage_state: "not_a_security_issue") }
    end

    context "when the node's status is an unrecognized value" do
      let(:status) { "bogus" }

      it { is_expected.to include(triage_state: "new") }
    end

    it { is_expected.to include(severity: severity * 2) }

    context "when using advanced scoring" do
      let(:scoring_system) { :advanced }

      it { is_expected.to include(severity: risk * 2) }
    end

    context "when using an unknown scoring system" do
      it "raises an ArgumentError" do
        expect { described_class.new(:bogus) }.to raise_error(ArgumentError)
      end
    end

    context "when there is an attack vector" do
      let(:attack_vectors) { [vector] }
      let(:vector) { { request: { method: method, url: vector_url, headers: request_headers }, response: { status: response_status, headers: response_headers } } }
      let(:method) { "GET" }
      let(:vector_url) { "http://vector.example.com" }
      let(:response_status) { 200 }
      let(:request_headers) { [{ name: "User-Agent", value: "chrome" }, { name: "Cookie", value: "oreo" }] }
      let(:response_headers) { [{ name: "ETag", value: "0xdeadbeef" }, { name: "X-Token", value: "this is a token" }] }

      it { is_expected.to include(additional_details: hash_including(request_method: method)) }
      it { is_expected.to include(additional_details: hash_including(request_url: vector_url)) }
      it { is_expected.to include(additional_details: hash_including(response_status: response_status.to_s)) }

      it "combines the request headers into a single string" do
        headers_string = "User-Agent=chrome Cookie=oreo"
        expect(finding_hash[:additional_details]).to include(request_headers: headers_string)
      end

      it "combines the response headers into a single string" do
        headers_string = "ETag=0xdeadbeef X-Token=this is a token"
        expect(finding_hash[:additional_details]).to include(response_headers: headers_string)
      end
    end

    context "when there are multiple attack vectors" do
      let(:attack_vectors) { [vector0, vector1] }
      let(:vector0) { { method: "GET", url: "http://vec.example.com" } }
      let(:vector1) { { method: "POST", url: "http://vec.example.com/another/vector" } }

      it "includes all vectors", :pending do
        expect(finding_hash).to include(:request_0_url, :request_1_url)
      end
    end
  end

  describe "#asset_hash" do
    let(:node) { { site: site_id.to_s, site_name: site_name } }
    let(:site_id) { 12 }
    let(:site_name) { "Example dot com" }
    let(:url) { "http://foo.example.com/path" }

    subject(:asset_hash) { mapper.asset_hash(node, url) }

    it { is_expected.to include(url: url) }
    it { is_expected.to include(application: site_name) }
    it { is_expected.to include(tags: []) }

    context "when an asset has been registered" do
      let(:asset) do
        {
          asset: {
            id: site_id,
            custom_asset_id: whitehat_custom_id,
            label: whitehat_label,
            asset_owner_name: whitehat_owner,
            tags: whitehat_tags
          }
        }
      end
      let(:whitehat_custom_id) { "custom id" }
      let(:whitehat_tags) { %w[tag_one tag_two] }
      let(:whitehat_label) { "label" }
      let(:whitehat_owner) { "owner" }

      before do
        mapper.register_asset(asset)
      end

      it "includes the asset's tags from Whitehat" do
        expect(asset_hash[:tags]).to include(*whitehat_tags)
      end

      it "includes the asset's label from Whitehat" do
        expect(asset_hash[:tags]).to include(whitehat_label)
      end

      it "includes the asset's owner name from Whitehat" do
        expect(asset_hash[:tags]).to include(whitehat_owner)
      end

      it "includes the asset's custom id from Whitehat" do
        expect(asset_hash[:tags]).to include(whitehat_custom_id)
      end

      context "when there are no tags" do
        let(:whitehat_tags) { [] }

        it "includes the other fields" do
          expect(asset_hash[:tags]).to contain_exactly(whitehat_label, whitehat_owner, whitehat_custom_id)
        end
      end

      context "when a field is blank" do
        let(:whitehat_owner) { "" }

        it "excludes the empty string" do
          expect(asset_hash[:tags]).to_not include("")
        end
      end

      context "when a field is nil" do
        let(:whitehat_label) { nil }

        it "excludes the nil" do
          expect(asset_hash[:tags]).to_not include(nil)
        end
      end

      context "when a field is missing" do
        let(:asset) do
          {
            asset: {
              id: site_id,
              label: whitehat_label,
              asset_owner_name: whitehat_owner,
              tags: whitehat_tags
            }
          }
        end

        it "includes the other fields" do
          expect(asset_hash[:tags]).to contain_exactly(*[whitehat_tags, whitehat_label, whitehat_owner].flatten)
        end
      end
    end
  end
end
