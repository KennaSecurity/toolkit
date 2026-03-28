# frozen_string_literal: true

require_relative "../rspec_helper"

RSpec.describe Kenna::Toolkit::Helpers do
  let(:example_class) { Class.new { extend Kenna::Toolkit::Helpers } }

  describe "#write_file_stream" do
    let(:tempfile) { Tempfile.new }
    let(:autoclose) { false }
    let(:assets) { (1..10).map { |n| { 'id' => n } } }
    let(:vuln_defs) { (1..10).map { |n| { 'id' => n } } }
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
          "vuln_defs": vuln_defs
        }.to_json
      )
    end

    it 'sanitizes path traversal in filename' do
      dir = Dir.mktmpdir
      example_class.write_file_stream(
        dir,
        "../../etc/passwd",
        autoclose,
        assets,
        vuln_defs,
        version
      )
      expect(File.exist?(File.join(dir, "passwd"))).to be true
      expect(File.exist?("/etc/passwd.json")).to be false
      FileUtils.rm_rf(dir)
    end
  end

  describe "#safe_output_path" do
    it 'returns resolved path for safe inputs' do
      path = example_class.safe_output_path("/tmp/output", "report.json")
      expect(path).to eq("/tmp/output/report.json")
    end

    it 'strips directory components from filename' do
      path = example_class.safe_output_path("/tmp/output", "subdir/report.json")
      expect(path).to eq("/tmp/output/report.json")
    end

    it 'strips traversal sequences from filename' do
      path = example_class.safe_output_path("/tmp/output", "../../etc/passwd")
      expect(path).to eq("/tmp/output/passwd")
    end
  end
end
