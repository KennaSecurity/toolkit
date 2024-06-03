# frozen_string_literal: true

module SnykV2Stubs
  def read_fixture_file(filename)
    File.read(File.join(%w[spec tasks connectors snyk_v2 fixtures], filename))
  end

  def stub_orgs_request
    stub_request(:get, "https://api.snyk.io/rest/orgs?version=2024-04-29")
      .to_return_json(body: read_fixture_file("orgs.json"))
  end

  def stub_projects_request
    stub_request(:get, Addressable::Template.new("https://api.snyk.io/rest/orgs/{orgId}/projects?version=2024-04-29&limit=100"))
      .to_return_json(body: read_fixture_file("projects.json"))
  end

  def stub_issues_request
    stub_request(:get, Addressable::Template.new("https://api.snyk.io/rest/orgs/{orgId}/issues?version=2024-04-29&limit=100&created_after={fromDate}&created_before={toDate}"))
      .with(query: hash_including({ "page" => "1" }))
      .to_return_json(body: read_fixture_file("issues.json"))
    stub_request(:get, Addressable::Template.new("https://api.snyk.io/rest/orgs/{orgId}/issues?version=2024-04-29&limit=100&created_after={fromDate}&created_before={toDate}"))
      .with(query: hash_including({ "page" => "2" }))
      .to_return_json(body: read_fixture_file("issues_empty.json"))
  end
end
