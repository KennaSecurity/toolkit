# frozen_string_literal: true

require "rspec_helper"

RSpec.describe "compare output" do
  describe "bitsight output" do
    let(:old_assets) { build_assets("output/bitsight_0/*.json") }
    let(:new_assets) { build_assets("output/bitsight/*.json") }

    it "is the same output" do
      expect(new_assets.count).to eq(old_assets.count)
      expect(new_assets.keys).to match_array(old_assets.keys)
      old_assets.each do |key, value|
        expect(new_assets[key].to_json.length).to eq(value.to_json.length)
      end
    end
  end

  describe "expanse output" do
    let(:old_assets) { build_assets("output/expanse_0/*.json") }
    let(:new_assets) { build_assets("output/expanse/*.json") }

    it "is the same output" do
      expect(new_assets.count).to eq(old_assets.count)
      expect(new_assets.keys).to match_array(old_assets.keys)
      old_assets.each do |key, value|
        expect(new_assets[key].to_json.length).to eq(value.to_json.length)
      end
    end
  end

  describe "riskiq output" do
    let(:old_assets) { build_assets("output/riskiq_0/*.json") }
    let(:new_assets) { build_assets("output/riskiq/*.json") }

    it "is the same output" do
      expect(new_assets.count).to eq(old_assets.count)
      expect(new_assets.keys).to match_array(old_assets.keys)
      old_assets.each do |key, value|
        expect(new_assets[key].count).to eq(value.count)
      end
    end
  end

  describe "security scorecard output" do
    let(:old_assets) { build_assets("output/security_scorecard_0/*.json") }
    let(:new_assets) { build_assets("output/security_scorecard/*.json") }

    it "is the same output" do
      expect(new_assets.count).to eq(old_assets.count)
      expect(new_assets.keys).to match_array(old_assets.keys)
      old_assets.each do |key, value|
        expect(new_assets[key].to_json.length).to eq(value.to_json.length)
      end
    end
  end

  def build_assets(path)
    files = Dir[path]
    assets = []
    files.each do |file|
      data = JSON.parse(File.read(file))
      assets.concat(data["assets"])
    end
    assets.group_by { |a| a["ip_address"] }
  end
end
