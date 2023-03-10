def read_fixture_file(filename)
  File.read(File.join(%w[spec tasks connectors snyk_v2 fixtures], filename))
end

def stub_orgs_request
  stub_request(:get, "https://snyk.io/api/v1/orgs").to_return_json(body: read_fixture_file("orgs.json"))
end

def stub_projects_request
  stub_request(:get, Addressable::Template.new("https://snyk.io/api/v1/org/{orgId}/projects"))
    .to_return_json(body: read_fixture_file("projects.json"))
end

def stub_issues_request
  stub_request(:post, "https://snyk.io/api/v1/reporting/issues")
    .with(query: hash_including({"page" => "1"}))
    .to_return_json(body: read_fixture_file("issues.json"))
  stub_request(:post, "https://snyk.io/api/v1/reporting/issues")
    .with(query: hash_including({"page" => "2"}))
    .to_return_json(body: read_fixture_file("issues_empty.json"))
end
