# frozen_string_literal: true

require 'rspec_helper'

RSpec.describe Kenna::Toolkit::CyleraTask do
  subject(:task) { described_class.new }

  def spy_on_accumulators
    subject.extend Kenna::Toolkit::KdiAccumulatorSpy
  end

  describe '#run' do
    let(:options) do
      {
        cylera_api_host: 'cylera.host',
        cylera_api_user: 'api_user',
        cylera_api_password: 'api_pass',
        kenna_api_key: 'api_key',
        kenna_api_host: 'kenna.example.com',
        kenna_connector_id: '12'
      }
    end
    let(:connector_run_success) { true }
    let(:kenna_client) do
      instance_double(
        Kenna::Api::Client,
        upload_to_connector: { 'data_file' => 12 },
        run_files_on_connector: { 'success' => connector_run_success },
        get_connector_runs: { results: [{ success: true, start_time: Time.now.to_s }] }
      )
    end

    before { allow(Kenna::Api::Client).to receive(:new) { kenna_client } }

    it 'succeeds' do
      VCR.use_cassette('cylera') do
        expect { task.run(options) }.to_not raise_error
      end
    end

    context 'when the required param is missed' do
      let(:options) { {} }

      it 'exits the script' do
        expect { task.run(options) }.to raise_error(SystemExit) { |e| expect(e.status).to_not be_zero }
      end
    end

    context 'when the connector run fails' do
      let(:connector_run_success) { false }

      it 'exits the script' do
        VCR.use_cassette('cylera') do
          expect { task.run(options) }.to raise_error(SystemExit) { |e| expect(e.status).to_not be_zero }
        end
      end
    end

    context 'when the API errors' do
      before { allow_any_instance_of(Kenna::Toolkit::Cylera::Client).to receive(:http_get) }

      it 'exits the script' do
        VCR.use_cassette('cylera') do
          expect { task.run(options) }.to raise_error(SystemExit) { |e| expect(e.status).to_not be_zero }
        end
      end
    end

    context 'when time value is an unexpected format' do
      it 'exits the script' do
        expect { task.run(options.merge(cylera_last_seen_after: '60m')) }.to raise_error(RuntimeError)
      end
    end

    context 'when the incremental param present' do
      it 'calls the connector runs endpoint' do
        expect(kenna_client).to receive(:get_connector_runs)
        VCR.use_cassette('cylera') do
          expect { task.run(options.merge(incremental: true)) }.to_not raise_error
        end
      end
    end

    context 'when asset source data has all fields' do
      before do
        spy_on_accumulators
        VCR.use_cassette('cylera') do
          task.run(options)
        end
      end

      it 'creates asset with vulnerability' do
        expect(task.assets)
          .to include({ "external_id" => "ae2e8de0-c764-11eb-8e8d-4627b9127261",
                        "ip_address" => "192.168.1.40",
                        "mac_address" => "00:15:bd:01:0f:10",
                        "os" => "VxWorks",
                        "hostname" => "dhcp-12-25-19-132",
                        "tags" => ["Cy Vendor:Group 4 Technology Ltd",
                                   "Cy Type:Network Access Control System",
                                   "Cy Model:Group 4 Tec Access Control / Security Management System",
                                   "Cy Class:Infrastructure",
                                   "Cy Location:Jersey City Medical Center, Jersey City, NJ",
                                   "Cy FDA Class:2",
                                   "Cy Serial Number:0000001",
                                   "Cy Version:4.0.1.0",
                                   "Cy VLAN:-1",
                                   "Cy AETitle:NBXXCU"],
                        "vulns" => [{ "created_at" => "2022-09-10 02:48:11.000000000 +0000",
                                      "last_seen_at" => "2022-09-10 02:48:11.000000000 +0000",
                                      "scanner_identifier" => "CVE-2000-0761",
                                      "scanner_score" => 6,
                                      "scanner_type" => "Cylera",
                                      "status" => "Open",
                                      "vuln_def_name" => "CVE-2000-0761" }] })
      end

      it 'creates vulnerability definition' do
        expect(task.vuln_defs)
          .to include({ "cve_identifiers" => "CVE-2000-0761",
                        "description" =>
                       "OS2/Warp 4.5 FTP server allows remote attackers to cause a denial of service via a long username.",
                        "name" => "CVE-2000-0761",
                        "scanner_type" => "Cylera",
                        "solution" =>
                         "Incident Response Plan - Identify contact within appropriate team, i.e. biomedical"\
                         " engineering, responsible for this device.; Document procedure for alerting appropriate staff"\
                         " from IT, IS, biomedical engineering, and clinical staff in case of device compromise.;"\
                         " Document possibility and procedure for isolating or disconnecting device from network in"\
                         " various scenarios of clinical use.; Document workflow changes that must occur if devices are"\
                         " disconnected from the network, i.e. manual drug library updates.; Prioritize training and"\
                         " simulation events for device downtime.\nAdditional Info\nhttp://archives.neohapsis.com/"\
                         "archives/bugtraq/2000-08/0166.html\nhttp://www.securityfocus.com/bid/1582\n"\
                         "ftp://ftp.software.ibm.com/ps/products/tcpip/fixes/v4.3os2/ic27721/README" })
      end
    end
    context 'when ip_ignore_list is provided' do
      before do
        spy_on_accumulators
        VCR.use_cassette('cylera') do
          task.run(options.merge(ip_ignore_list: '0.0.0.0,192.168.1.0/24'))
        end
      end

      it 'ignores matched ip address' do
        expect(task.assets)
          .to include({ "external_id" => "ae2e8de0-c764-11eb-8e8d-4627b9127261",
                        "mac_address" => "00:15:bd:01:0f:10",
                        "os" => "VxWorks",
                        "hostname" => "dhcp-12-25-19-132",
                        "tags" => ["Cy Vendor:Group 4 Technology Ltd",
                                   "Cy Type:Network Access Control System",
                                   "Cy Model:Group 4 Tec Access Control / Security Management System",
                                   "Cy Class:Infrastructure",
                                   "Cy Location:Jersey City Medical Center, Jersey City, NJ",
                                   "Cy FDA Class:2",
                                   "Cy Serial Number:0000001",
                                   "Cy Version:4.0.1.0",
                                   "Cy VLAN:-1",
                                   "Cy AETitle:NBXXCU"],
                        "vulns" => [{ "created_at" => "2022-09-10 02:48:11.000000000 +0000",
                                      "last_seen_at" => "2022-09-10 02:48:11.000000000 +0000",
                                      "scanner_identifier" => "CVE-2000-0761",
                                      "scanner_score" => 6,
                                      "scanner_type" => "Cylera",
                                      "status" => "Open",
                                      "vuln_def_name" => "CVE-2000-0761" }] })
      end
    end

    context 'when ip_ignore_list contains unexpected values' do
      it 'raises exception' do
        VCR.use_cassette('cylera') do
          expect { task.run(options.merge(ip_ignore_list: '0.0.0.0,192.168.1.0/43')) }.to raise_error(RuntimeError)
        end
      end
    end
  end
end
