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

    subject(:finding_hash) { mapper.finding_hash(node) }

    it { is_expected.to include(scanner_identifier: node_id) }
    it { is_expected.to include(scanner_type: "Whitehat Sentinel") }
    it { is_expected.to include(created_at: found) }
    it { is_expected.to include(last_fixed_on: nil) }
    it { is_expected.to include(closed_at: nil) }
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
  end
end
