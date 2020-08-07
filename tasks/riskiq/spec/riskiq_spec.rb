require 'rspec'

require_relative "../../../lib/toolkit.rb"

describe "Kenna" do 
describe "Toolkit" do 
  describe "RiskiqTask" do
  
    include Kenna::Toolkit::Helpers
    include Kenna::Toolkit::KdiHelpers  
    include Kenna::Toolkit::RiskIq::Helpers

    before do 
      @riq_user = ENV["RIQ_API_KEY"]
      @riq_secret = ENV["RIQ_API_SECRET"]
    end

    it "should have a key in memory" do
      expect(@riq_user).to be_a String
      expect(@riq_secret).to be_a String
    end

    it 'should get the global footprint' do 

      max_pages = 1

      client = Kenna::Toolkit::RiskIq::Client.new(@riq_user, @riq_secret)

      print_good "Getting footprint"
      result = client.get_global_footprint(max_pages)
      #print_good result 

      print_good "Conveting to KDI"
      convert_riq_output_to_kdi result
      print_good "KDI Conversion complete!"
  

      ####
      # Write KDI format
      ####
      kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
      
      expect(kdi_output[:assets].first["vulns"].first["scanner_type"]).to match("RiskIQ")
      expect(kdi_output[:vuln_defs].first["scanner_type"]).to match("RiskIQ")
      expect(kdi_output[:vuln_defs].first["scanner_identifier"]).to match(/^CVE-/)
      expect(kdi_output[:vuln_defs].first["cve_identifiers"]).to match(/^CVE-/)

    end

  end

end
end