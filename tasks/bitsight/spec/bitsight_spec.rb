# frozen_string_literal: true

require "rspec"

require_relative "../../../lib/toolkit"

describe "Kenna" do
  describe "Toolkit" do
    describe "BitsightTask" do
      include Kenna::Toolkit::BitsightHelpers
      include Kenna::Toolkit::Helpers
      include Kenna::Toolkit::KdiHelpers

      before do
        @key = ENV["BITSIGHT_API_KEY"]
      end

      it "should have a key in memory" do
        expect(@key).to be_a String
      end

      it "should have a key of the correct length" do
        expect(@key.length).to be 40
      end

      it "should be a valid key" do
        expect(valid_bitsight_api_key?(@key)).to be true
      end

      it "should return the expected organization for our org" do
        expect(get_my_company(@key)).to eq("a940bb61-33c4-42c9-9231-c8194c305db3")
      end

      it "should return assets when requested" do
        guid = get_my_company(@key)
        assets = get_bitsight_assets_for_company(@key, guid)
        expect(assets).to be_a Array
        expect(assets.include?("23.4.132.93")).to be true
      end

      it "should create kdi from a finding" do
        # guid = get_my_company(@key)

        # results = create_kdi_from_bitsight_findings_for_company(@key, guid)

        example_finding = { "temporary_id" => "A9Jq47BBje22e285780fa57ee47542e7d4d91877e3",
                            "affects_rating" => true,
                            "assets" => [{ "asset" => "206.255.90.67",
                                           "category" => "high",
                                           "importance" => 0.024056261,
                                           "is_ip" => true }],
                            "details" => { "geo_ip_location" => "US",
                                           "infection" => { "family" => "Necurs",
                                                            "description" => "This malware steals information, disables security programs, and is often installed in conjunction with other malware.",
                                                            "references" => ["https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/Necurs", "http://www.symantec.com/security_response/writeup.jsp?docid=2012-121212-2802-99"],
                                                            "data_exfiltration" => true,
                                                            "unauthorized_access" => false,
                                                            "implies_other_infections" => true,
                                                            "resource_abuse" => false,
                                                            "target_platforms" => ["Win32"] },
                                           "remediations" => [],
                                           "sample_timestamp" => "2020-04-18T23:45:06Z",
                                           "server_name" => "XXX.251.106.29",
                                           "vulnerabilities" => [],
                                           "count" => 21,
                                           "dest_port" => 80,
                                           "detection_method" => "Sinkhole",
                                           "request_method" => "POST",
                                           "rollup_end_date" => "2020-04-18",
                                           "rollup_start_date" => "2020-04-16",
                                           "sinkhole_ip_masked" => "XXX.251.106.29",
                                           "src_port" => 4828 },
                            "evidence_key" => "206.255.90.67",
                            "first_seen" => "2020-04-16",
                            "last_seen" => "2020-04-18",
                            "related_findings" => [{ "temporary_id" => "A9Jq47BBje0b3c5c19a9707610e211d5a3baac0ff2",
                                                     "affects_rating" => true,
                                                     "assets" => [{ "asset" => "206.255.90.67",
                                                                    "category" => "high",
                                                                    "importance" => 0.024056261,
                                                                    "is_ip" => true }],
                                                     "details" => { "geo_ip_location" => "US",
                                                                    "infection" => { "family" => "Necurs", "description" => "This malware steals information, disables security programs, and is often installed in conjunction with other malware.", "references" => ["https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/Necurs", "http://www.symantec.com/security_response/writeup.jsp?docid=2012-121212-2802-99"], "data_exfiltration" => true, "unauthorized_access" => false, "implies_other_infections" => true, "resource_abuse" => false, "target_platforms" => ["Win32"] },
                                                                    "remediations" => [],
                                                                    "sample_timestamp" => "2020-04-17T22:37:20Z",
                                                                    "server_name" => "XXX.251.106.29",
                                                                    "vulnerabilities" => [],
                                                                    "count" => 21,
                                                                    "dest_port" => 80,
                                                                    "detection_method" => "Sinkhole",
                                                                    "request_method" => "POST",
                                                                    "rollup_end_date" => "2020-04-18",
                                                                    "rollup_start_date" => "2020-04-16",
                                                                    "sinkhole_ip_masked" => "XXX.251.106.29",
                                                                    "src_port" => 2619 },
                                                     "evidence_key" => "206.255.90.67",
                                                     "first_seen" => "2020-04-16",
                                                     "last_seen" => "2020-04-18",
                                                     "risk_category" => "Compromised Systems",
                                                     "risk_vector" => "botnet_infections",
                                                     "risk_vector_label" => "Botnet Infections",
                                                     "rolledup_observation_id" => "iNV2ehFg9kZzMdQBURl-4g==",
                                                     "severity" => 10.0,
                                                     "severity_category" => "severe",
                                                     "tags" => [],
                                                     "last_requested_refresh_date" => nil },
                                                   { "temporary_id" => "A9Jq47BBje366a1e9404403ffd94193553ddcb7e2f",
                                                     "affects_rating" => true,
                                                     "assets" => [{ "asset" => "206.255.90.67",
                                                                    "category" => "high",
                                                                    "importance" => 0.024056261,
                                                                    "is_ip" => true }],
                                                     "details" => { "geo_ip_location" => "US", "infection" => { "family" => "Necurs", "description" => "This malware steals information, disables security programs, and is often installed in conjunction with other malware.", "references" => ["https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/Necurs", "http://www.symantec.com/security_response/writeup.jsp?docid=2012-121212-2802-99"], "data_exfiltration" => true, "unauthorized_access" => false, "implies_other_infections" => true, "resource_abuse" => false, "target_platforms" => ["Win32"] }, "remediations" => [], "sample_timestamp" => "2020-04-16T22:43:43Z", "server_name" => "XXX.251.106.29", "vulnerabilities" => [], "count" => 15, "dest_port" => 80, "detection_method" => "Sinkhole", "request_method" => "POST", "rollup_end_date" => "2020-04-18", "rollup_start_date" => "2020-04-16", "sinkhole_ip_masked" => "XXX.251.106.29", "src_port" => 1681 },
                                                     "evidence_key" => "206.255.90.67",
                                                     "first_seen" => "2020-04-16",
                                                     "last_seen" => "2020-04-18",
                                                     "risk_category" => "Compromised Systems",
                                                     "risk_vector" => "botnet_infections",
                                                     "risk_vector_label" => "Botnet Infections",
                                                     "rolledup_observation_id" => "iNV2ehFg9kZzMdQBURl-4g==",
                                                     "severity" => 10.0,
                                                     "severity_category" => "severe",
                                                     "tags" => [],
                                                     "last_requested_refresh_date" => nil }],
                            "risk_category" => "Compromised Systems",
                            "risk_vector" => "botnet_infections",
                            "risk_vector_label" => "Botnet Infections",
                            "rolledup_observation_id" => "iNV2ehFg9kZzMdQBURl-4g==",
                            "severity" => 10.0,
                            "severity_category" => "severe",
                            "tags" => [],
                            "last_requested_refresh_date" => nil }

        # parses a finding an sticks it in our array
        _add_finding_to_working_kdi example_finding

        expect(@assets).to be_a Array
        expect(@assets.first).to be_a Hash
        expect(@assets.first[:tags]).to be_a Array
        expect(@assets.first[:tags].include?("Bitsight")).to be true
      end

      it "should translate api results into vali kdi" do
        # guid = get_my_company(@key)

        # results = get_bitsight_findings_and_create_kdi(@key, guid, 100)

        # kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
        # These were not used so I commented them out. - JG 11/27/2020

        expect(@assets).to be_a Array
        expect(@assets.first).to be_a Hash
        expect(@assets.first[:tags]).to be_a Array
        expect(@assets.first[:tags].include?("Bitsight")).to be true
        # TODO... more verification here
      end
    end
  end
end
