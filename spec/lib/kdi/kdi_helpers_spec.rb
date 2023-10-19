# frozen_string_literal: true

require_relative "../../rspec_helper"

RSpec.describe Kenna::Toolkit::KdiHelpers do
  let(:example_class) { Class.new { extend Kenna::Toolkit::KdiHelpers } }

  describe "#create_kdi_asset_vuln" do
    let(:asset_hash) do
      {
        "external_id" => "7339373",
        "hostname" => 'hostname',
        "owner" => "owner",
        "tags" => ["tag1", "tag2"]
      }
    end

    let(:vuln_hash) do
      {
        "scanner_identifier" => "CVE-2018-9999",
        "scanner_type" => "Nexpose",
        "vuln_def_name" => "CVE-2018-9999",
        "scanner_score" => 10,
        "status" => "open",
        "created_at" => "2019-01-01T00:00:00Z",
        "last_seen_at" => "2019-01-01T00:00:00Z"
      }
    end

    it 'left priority as 10' do
      example_class.create_kdi_asset_vuln(asset_hash, vuln_hash)
      asset = example_class.instance_variable_get(:@assets).find { |a| a["external_id"] == "7339373" }
      expect(asset["priority"]).to eq(10)
    end

    it 'removes the priority field' do
      example_class.create_kdi_asset_vuln(asset_hash, vuln_hash, nil, { skip_priority: true })
      asset = example_class.instance_variable_get(:@assets).find { |a| a["external_id"] == "7339373" }
      expect(asset.key?("priority")).to eq(false)
    end
  end
end
