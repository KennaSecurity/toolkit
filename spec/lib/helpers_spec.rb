# frozen_string_literal: true

require_relative "../rspec_helper"

RSpec.describe Kenna::Toolkit::Helpers do
  let(:example_class) { Class.new { extend Kenna::Toolkit::Helpers } }

  describe "#write_file_stream" do
    let(:tempfile) { Tempfile.new }
    let(:autoclose) { false }
    let(:assets) { (1..10).map {|n| {'id' => n }} } 
    let(:vuln_defs) { (1..10).map {|n| {'id' => n }} }
    let(:version) { 2 }

    it 'writes JSON to the file' do
      example_class.write_file_stream(
        File.dirname(tempfile),
        File.basename(tempfile),
        autoclose,
        assets,
        vuln_defs,
        version
      )
      expect(tempfile.read).to eq(
        {
          "skip_autoclose": false,
          "version": 2,
          "assets": assets,
          "vuln_defs": vuln_defs,
        }.to_json
      )
    end
  end
end