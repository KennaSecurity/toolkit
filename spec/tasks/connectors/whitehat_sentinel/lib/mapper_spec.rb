# frozen_string_literal: true

require "rspec_helper"

RSpec.describe Kenna::Toolkit::WhitehatSentinel::Mapper do
  subject(:mapper) { described_class.new }

  describe "#finding_hash" do
    let(:node) { { id: node_id } }
    let(:node_id) { 10_085 }

    it "uses the node's id attribute as scanner_identifier" do
      expect(mapper.finding_hash(node)).to include(scanner_identifier: node_id)
    end

    it "sets the scanner_type to Whitehat Sentinel" do
      expect(mapper.finding_hash(node)).to include(scanner_type: "Whitehat Sentinel")
    end
  end
end
