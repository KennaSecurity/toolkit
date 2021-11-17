# frozen_string_literal: true

require "graphql/client"
require "graphql/client/http"
module Kenna
  module Toolkit
    class GithubDependabot < Kenna::Toolkit::BaseTask
      def self.metadata
        {
          id: "github_dependabot",
          name: "github_dependabot Vulnerabilities",
          description: "Pulls assets and vulnerabilitiies from github_dependabot",
          options: [
            { name: "github_access_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Github Access Token" },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.kennasecurity.com",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/github_dependabot",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def self.github_graphql_client
        http = GraphQL::Client::HTTP.new("https://api.github.com/graphql") do
          def headers(context)
            { "Authorization": "Bearer #{GITHUB_DEPENDABOT_TOKEN}" }
          end
        end

        schema = GraphQL::Client.load_schema(http)

        GraphQL::Client.new(schema: schema, execute: http)
      end

      SECURITY_ADVISORY_QUERY = github_graphql_client.parse <<-'GRAPHQL'
        query {
          organization(login: "KennaSecurity") {
            repositories(orderBy: {field: UPDATED_AT, direction: DESC}, first: 50) {
              nodes {
              name
                vulnerabilityAlerts(last: 50) {
                  nodes {
                    id
                    securityAdvisory {
                      description
                      cvss {
                        score
                      }
                      severity
                      identifiers {
                        type
                        value
                      }
                      summary
                      vulnerabilities(last: 50) {
                        nodes {
                          package {
                            name
                          }
                          severity
                          firstPatchedVersion {
                            identifier
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      GRAPHQL

      def self.security_advisories
        github_graphql_client.query(SECURITY_ADVISORY_QUERY)
      end

      def run(opts)
        super

        @github_access_token = @options[:github_access_token]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]

        repos = GithubDependabot.security_advisories.original_hash["data"]["organization"]["repositories"]["nodes"]

        repo_map = repos.each_with_object({}) do |repo, h|
          advisories = repo["vulnerabilityAlerts"]["nodes"].map { |alert| alert["securityAdvisory"] }
          h[repo["name"]] = advisories.reject { |ad| ad["identifiers"].last.value?("GHSA") }
        end

        kdi_hash = {
          "skip_autoclose": false,
          "version": 2,
          "assets":
            repo_map.map do |repo|
              {
                "application": repo.first,
                "tags": [
                  "github_dependabot_kdi"
                ],
                "vulns": vulnerability_alerts_for(repo)
              }
            end,
          "vuln_defs": vulnerability_definitions(repo_map)
        }

        # create output dir
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        FileUtils.mkdir_p output_dir

        # create full output path
        filename = "github_dependabot_kdi.json"

        File.open("#{output_dir}/#{filename}", "w") do |f|
          f.write(kdi_hash.to_json)
        end
        
        print_good "Output is available at: #{output_dir}/#{filename}"

        ####
        ### Finish by uploading if we're all configured
        ####
        return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

        print_good "Attempting to upload to Kenna API at #{@kenna_api_host}"
        upload_file_to_kenna_connector @kenna_connector_id, @kenna_api_host, @kenna_api_key, "#{output_dir}/#{filename}"
        
      end

      def vulnerability_alerts_for(repo)
        repo.last.map do |alert|
          {
            "scanner_identifier": alert["identifiers"].last["value"],
            "scanner_type": "Github Dependabot",
            "scanner_score": alert["cvss"]["score"].to_i,
            "last_seen_at": Time.now.utc,
            "status": "open",
            "vuln_def_name": alert["identifiers"].last["value"]
          }
        end
      end

      def vulnerability_definitions(repo_map)
        all_vulns = repo_map.flat_map do |repo|
          repo.last
        end

        all_vulns.map do |advisory|
          {
            "scanner_type": "Github Dependabot",
            "name": advisory["identifiers"].last["value"],
            "cve_identifiers": advisory["identifiers"].last["value"],
            "description": advisory["description"]
          }
        end
      end
    end
  end
end
