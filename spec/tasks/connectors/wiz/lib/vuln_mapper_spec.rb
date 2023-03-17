# frozen_string_literal: true

require 'rspec_helper'

RSpec.describe Kenna::Toolkit::Wiz::VulnsMapper do
  subject(:vuln_mapper) { described_class.new }
  let(:vuln) do
    {
      'id': 'e60ac06a-38d2-56ad-aldc-cb40c27d568f',
      'locationPath': '',
      'description': "Microsoft product's file '\\Program Files\\Common Files\\microsoft shared\ \EQUATION\\EQNEDT3:",
      'version': '2000.11.9.0',
      'score': '7,8',
      'exploitabilityScore': '1,8',
      'link': '"https://msrc.microsoft.com/update-guide/en-us/vulnerability/CVE-2017-11882,',
      'projects': '',
      'detailedName': detailed_name,
      'detectionMethod': detection_method,
      'vulnerableAsset': { 'cloudProviderURL': 'foo' }
    }.with_indifferent_access
  end

  let(:detailed_name) { "data here" }
  let(:detection_method) { "data here" }

  describe "extract_details" do
    subject(:details_json) { JSON.parse(vuln_mapper.extract_details(vuln)) }

    context 'When detailed name and detection method data' do
      it 'should should retrieve the corresponding data' do
        expect(details_json['Detailed Name']).to eq(vuln['detailedName'])
        expect(details_json['Detection Method']).to eq(vuln['detectionMethod'])
      end
    end

    context 'Whem detailed name and detection method are missing' do
      let(:detailed_name) { nil }
      let(:detection_method) { nil }

      it 'should be nil' do
        expect(details_json['Detailed Name']).to be_nil
        expect(details_json['Detailed Name']).to be_nil
      end
    end
  end
end
