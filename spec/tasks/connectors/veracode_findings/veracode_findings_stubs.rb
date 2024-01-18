# frozen_string_literal: true

module VeracodeFindingsStubs
  def read_fixture_file(filename)
    File.read(File.join(%w[spec tasks connectors veracode_findings fixtures], filename))
  end

  def stub_findings_request
    stub_request(:get, "https://api.veracode.com/appsec/v2/applications/TESTGUID/findings?size=100").to_return_json(body: read_fixture_file("findings.json"))
  end

  def stub_sca_findings_request
    stub_request(:get, "https://api.veracode.com/appsec/v2/applications/TESTGUID/findings?scan_type=SCA&size=100").to_return_json(body: read_fixture_file("sca_findings.json"))
  end

  def stub_categories_request
    stub_request(:get, "https://api.veracode.com/appsec/v1/categories?size=100").to_return_json(body: read_fixture_file("category_recommendations.json"))
  end

  def stub_applications_request
    stub_request(:get, Addressable::Template.new("https://api.veracode.com/appsec/v1/applications?size=100"))
      .to_return_json(body: read_fixture_file("applications.json"))
  end
end
