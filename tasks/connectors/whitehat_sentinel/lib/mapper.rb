# frozen_string_literal: true

module Kenna
  module Toolkit
    module WhitehatSentinel
      class Mapper
        def finding_hash(node)
          {
            scanner_identifier: node[:id],
            scanner_type: "Whitehat Sentinel"
          }
        end
      end
    end
  end
end
