# frozen_string_literal: true

require_relative "lib/checkmarx_sast_helper"
require "json"

module Kenna
  module Toolkit
    class CheckmarxSast < Kenna::Toolkit::BaseTask
      include Kenna::Toolkit::CheckmarxSastHelper

      def self.metadata
        {
          id: "checkmarx_sast",
          name: "checkmarx_sast Vulnerabilities",
          description: "Pulls assets and vulnerabilitiies from checkmarx_sast",
          options: [
            { name: "checkmarx_sast_console",
              type: "hostname",
              required: true,
              default: nil,
              description: "Your checkmarx_sast Console hostname (without protocol and port), e.g. app.checkmarx_sastsecurity.com" },
            { name: "checkmarx_sast_console_port",
              type: "integer",
              required: false,
              default: nil,
              description: "Your checkmarx_sast Console port, e.g. 8080" },
            { name: "checkmarx_sast_user",
              type: "user",
              required: true,
              default: nil,
              description: "checkmarx_sast Username" },
            { name: "checkmarx_sast_password",
              type: "password",
              required: true,
              default: nil,
              description: "checkmarx_sast Password" },
            { name: "container_data",
              type: "boolean",
              required: false,
              default: "false",
              description: "Optional filter to limit vulnerabilities using a comma separated list of severities (e.g. CRITICAL,HIGH)" },
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
              default: "output/checkmarx_sast",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        username = @options[:checkmarx_sast_user]
        password = @options[:checkmarx_sast_password]
        checkmarx_sast_port = @options[:checkmarx_sast_console_port]
        checkmarx_sast_console = @options[:checkmarx_sast_console]
        checkmarx_sast_url = if checkmarx_sast_port
          "#{checkmarx_sast_console}:#{checkmarx_sast_port}"
        else
          checkmarx_sast_console
        end
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]

        # Request checkmarx sast auth api to get access token
        token = request_checkmarx_sast_token(checkmarx_sast_url, username, password)
        fail_task "Unable to authenticate with checkmarx_sast, please check credentials" unless token

        # Request checkmarx sast api to fetch projects using token
        projects = fetch_checkmarx_sast_projects(checkmarx_sast_url, token)

        projects.each do |project|
          print_good "Project Name: #{project["name"]}"
          project_id = project["id"]
          # Request checkmarx sast api to fetch all scans of each project
          all_scans = fetch_all_scans_of_project(checkmarx_sast_url, token, project_id)
        end
        print_good "\n"
      end
    end
  end
end
