# frozen_string_literal: true

require_relative "../rspec_helper"

RSpec.describe Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper do
  before(:context) do
    initialize_mapper
  end

  after(:context) do
    File.delete(@mappings_filename) if @mappings_filename
  end

  describe :get_canonical_vuln_details do
    it "get canonical vuln for definition with only one match" do
      vuln = @mapper.get_canonical_vuln_details("SecurityScorecard", { "scanner_identifier" => "upnp_accessible" })
      expect(vuln["name"]).to eq("Accessible UPNP server")
      expect(vuln["scanner_type"]).to eq("SecurityScorecard")
      expect(vuln["source"]).to eq("SecurityScorecard (Kenna Normalized)")
      expect(vuln["scanner_score"]).to eq(9)
      expect(vuln["override_score"]).to eq(90)
      expect(vuln["description"]).to eq("A upn Device is accessible from the internet at this location")
      expect(vuln["recommendation"]).to eq("This service should not be visible on the public Internet. Please refer to the details provided and remediate these vulnerabilities as soon as possible by closing the affected ports, removing the instance if it is no longer needed, or implementing appropriate security controls to limit visibility.")
    end

    it "get canonical vuln for definition with more than one match" do
      vuln = @mapper.get_canonical_vuln_details("SecurityScorecard", { "scanner_identifier" => "x_frame_options_incorrect" })
      expect(vuln["name"]).to eq("Application Security Headers")
      expect(vuln["scanner_type"]).to eq("SecurityScorecard")
      expect(vuln["source"]).to eq("SecurityScorecard (Kenna Normalized)")
      expect(vuln["scanner_score"]).to eq(3)
      expect(vuln["override_score"]).to eq(30)
      expect(vuln["description"]).to eq("One or more application security headers was detected missing or misconfigured.")
      expect(vuln["recommendation"]).to eq("Correct the header configuration on the server.")
    end
  end

  private

  def initialize_mapper
    @mappings_filename = generate_mappings_file
    @mapper = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper.new(__dir__, __dir__, File.basename(@mappings_filename))
  end

  def generate_mappings_file
    csv = <<~CSV
      type,name,cwe or source,score or vuln_regx,description,remediation
      definition,Accessible UPNP server,,90,A upn Device is accessible from the internet at this location,"This service should not be visible on the public Internet. Please refer to the details provided and remediate these vulnerabilities as soon as possible by closing the affected ports, removing the instance if it is no longer needed, or implementing appropriate security controls to limit visibility. "
      match,Accessible UPNP server,SecurityScorecard,/^upnp_accessible$/i,,
      definition,Application Content Security Policy Issue,CWE-358,40,A problem with this application's content security policy was identified.,"Update the certificate to include the hostname, or ensure that clients access the host from the matched hostname."
      match,Application Content Security Policy Issue,SecurityScorecard,/^csp_no_policy$/i,,
      match,Application Content Security Policy Issue,SecurityScorecard,/^csp_unsafe_policy$/i,,
      match,Application Content Security Policy Issue,SecurityScorecard,/^csp_too_broad$/i,,
      definition,Application Security Headers,CWE-693,30,One or more application security headers was detected missing or misconfigured.,Correct the header configuration on the server.
      match,Application Security Headers,SecurityScorecard,/^x_xss_protection_incorrect$/i,,
      match,Application Security Headers,SecurityScorecard,/^x_content_type_options_incorrect$/i,,
      match,Application Security Headers,SecurityScorecard,/^x_frame_options_incorrect$/i,,
      match,Application Security Headers,Bitsight,/^web_application_headers$/i,,
      match,Application Security Headers,Bitsight,/^application_security$/i,,
      definition,Application Software Version Detected,CWE-693,20,Software details were detected.,Verify this is not leaking sensitive data:.
      match,Application Software Version Detected,Bitsight,/^server_software$/i,,
    CSV
    filename = File.expand_path("mappings.csv", __dir__)
    File.write(filename, csv)
    filename
  end
end
