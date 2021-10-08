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
          options: []
        }
      end

      def run(options) # rubocop:disable Lint/UselessMethodDefinition
        super
      end
    end
  end
end
