# frozen_string_literal: true

module Kenna
  module Toolkit
    module WhitehatSentinel
      class Mapper
        def finding_hash(node)
          closed_at = Time.parse(node[:closed]) if node[:closed]

          {
            scanner_identifier: node[:id],
            scanner_type: "Whitehat Sentinel",
            created_at: Time.parse(node[:found]),
            last_seen_at: closed_at || Time.now,
            last_fixed_on: closed_at,
            closed_at: closed_at
          }
        end
      end
    end
  end
end
