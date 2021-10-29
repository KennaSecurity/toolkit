# frozen_string_literal: true

require "rspec_helper"
require_relative "../initialize/enumerable"

RSpec.describe "Enumerable" do
  let(:numbers) { 1..10 }
  describe :index_by do
    it "returns a hash when block is given" do
      expect([].index_by(&:nil?)).to be_a_kind_of(Hash)
    end

    it "returns a hash with the expected results" do
      hash = numbers.index_by(&:object_id)
      expect(hash.size).to eq 10
      expect(hash[1.object_id]).to eq 1
      expect(hash[2.object_id]).to eq 2
    end

    it "returns an enumerator when no block given" do
      expect([].index_by).to be_a_kind_of(Enumerator)
    end
  end
end