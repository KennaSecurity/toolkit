# frozen_string_literal: true

# expanse client
require_relative "lib/client"

# cloud exposure field mappings
require_relative "lib/mapper"

module Kenna
  module Toolkit
    class ExpanseIssuesTask < Kenna::Toolkit::BaseTask
      include Kenna::Toolkit::ExpanseIssues::Mapper

      def self.metadata
        {
          id: "expanse_issues",
          name: "ExpanseIssues",
          description: "This task connects to the Expanse API and pulls results into the Kenna Platform.",
          options: [
            { name: "expanse_api_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the Expanse key used to query the API." },
            { name: "issue_types",
              type: "string",
              required: false,
              default: "",
              description: "Comma-separated list of issue types. If not set, all issue types will be included" },
            { name: "priorities",
              type: "string",
              required: false,
              default: "",
              description: "Comma-separated list of priorities. If not set, all priorities will be included" },
            { name: "tagNames",
              type: "string",
              required: false,
              default: "",
              description: "Comma-separated list of tag names. If not set, all tags will be included" },
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
              default: "output/expanse",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(options)
        super

        # Get options
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @uploaded_files = []
        @output_dir = "#{$basedir}/#{@options[:output_directory]}"
        @issue_types = @options[:issue_types].split(",") if @options[:issue_types]
        @priorities =  @options[:priorities] if @options[:priorities]
        @tags = @options[:tagNames] if @options[:tagNames]
        expanse_api_key = @options[:expanse_api_key]

        print @issue_types
        print @priorities

        # create an api client
        @client = Kenna::Toolkit::ExpanseIssues::Client.new(expanse_api_key)

        @assets = []
        @vuln_defs = []

        # verify we have a good key before proceeding
        unless @client.successfully_authenticated?
          print_error "Unable to proceed, invalid key for Expanse?"
          return
        end
        print_good "Valid key, proceeding!"

        if @options[:debug]
          max_pages = 1
          max_per_page = 100
          print_debug "Debug mode, override max to: #{max_pages * max_per_page}"
        else
          max_pages = 100
          max_per_page = 10_000
        end

        create_kdi_from_issues(max_pages, max_per_page, @issue_types, @priorities, @tags)

        ####
        ### Finish by uploading if we're all configured
        ####
        return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

        kdi_kickoff
      end
    end
  end
end
