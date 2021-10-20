# frozen_string_literal: true

require "rspec_helper"

RSpec.describe Kenna::Toolkit::WhitehatSentinel::Mapper do
  subject(:mapper) { described_class.new }

  describe "#finding_hash" do
    let(:node) { { id: node_id, found: found.iso8601, closed: closed&.iso8601, class: node_class } }
    let(:node_id) { 10_085 }
    let(:found) { Time.new(2021, 10, 22, 12, 13, 14).utc }
    let(:closed) { nil }
    let(:node_class) { "Insufficient Transport Layer Protection" }

    it "uses the node's id attribute as scanner_identifier" do
      expect(mapper.finding_hash(node)).to include(scanner_identifier: node_id)
    end

    it "sets the scanner_type to Whitehat Sentinel" do
      expect(mapper.finding_hash(node)).to include(scanner_type: "Whitehat Sentinel")
    end

    it "sets created_at to the parsed value of the found attribute" do
      expect(mapper.finding_hash(node)).to include(created_at: found)
    end

    it "sets last_fixed_on to nil" do
      expect(mapper.finding_hash(node)).to include(last_fixed_on: nil)
    end

    it "sets closed_at to nil" do
      expect(mapper.finding_hash(node)).to include(closed_at: nil)
    end

    it "sets last_seen_at to now" do
      now = Time.new(2021, 10, 30, 8, 9, 10).utc

      Timecop.freeze(now) do
        expect(mapper.finding_hash(node)).to include(last_seen_at: now)
      end
    end

    it "uses the vuln's class as the vuln_def_name field" do
      expect(mapper.finding_hash(node)).to include(vuln_def_name: node_class)
    end

    context "when the node has a closed attribute" do
      let(:closed) { Time.new(2021, 10, 23, 11, 12, 13).utc }

      it "sets last_seen_at to the parsed value of the closed attribute" do
        expect(mapper.finding_hash(node)).to include(last_seen_at: closed)
      end

      it "sets last_fixed_on to the parsed value of the closed attribute" do
        expect(mapper.finding_hash(node)).to include(last_fixed_on: closed)
      end

      it "sets closed_at to the parsed value of the closed attribute" do
        expect(mapper.finding_hash(node)).to include(closed_at: closed)
      end
    end
  end
end
