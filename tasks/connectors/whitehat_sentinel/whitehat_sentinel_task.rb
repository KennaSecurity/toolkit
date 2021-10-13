# frozen_string_literal: true

require_relative "lib/api_client"

module Kenna
  module Toolkit
    class WhitehatSentinelTask < Kenna::Toolkit::BaseTask
      def self.metadata
        {
          id: "whitehat_sentinel",
          name: "Whitehat Sentinel",
          description: "This task connects to the Whitehat Sentinel API and pulls results into the Kenna Platform.",
          options: [
            { name: "whitehat_api_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the Whitehat key used to query the API." }
          ]
        }
      end

      def run(options)
        super

        # Process:
        # 1. Retrieve sites from API
        # 2. Retrieve vulns from API
        # 3. Retrieve tags from API
        # 4. Group vulns by URL
        # 5. Generate KDI doc from vulns

        key = @options[:whitehat_api_key]
        client = Kenna::Toolkit::WhitehatSentinel::ApiClient.new(api_key: key)

        client.sites
      end
    end
  end
end
