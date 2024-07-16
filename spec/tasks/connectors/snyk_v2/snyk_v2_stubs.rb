# frozen_string_literal: true

module SnykV2Stubs
  def read_fixture_file(filename)
    File.read(File.join('spec', 'tasks', 'connectors', 'snyk_v2', 'fixtures', filename))
  end

  def stub_orgs_request
    stub_request(:get, "https://api.snyk.io/rest/orgs?version=2024-04-29")
      .to_return(status: 200, body: read_fixture_file("orgs.json"), headers: {})
  end

  def stub_projects_request(org_id)
    stub_request(:get, "https://api.snyk.io/rest/orgs/#{org_id}/projects?version=2024-04-29&limit=100")
      .to_return(status: 200, body: read_fixture_file("projects.json"), headers: {})
  end

  def stub_issues_request(org_id, from_date, to_date)
    stub_request(:get, "https://api.snyk.io/rest/orgs/#{org_id}/issues?version=2024-04-29&limit=100&created_after=#{from_date}&created_before=#{to_date}")
      .to_return(status: 200, body: read_fixture_file("issues.json"), headers: {})
  end
end
